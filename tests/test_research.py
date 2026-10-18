"""Research accounting and exact JSON boundaries; stdlib-only unit tests."""

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from pcap_mcp.claims import check_claims, parse_claims
from pcap_mcp.evidence_io import parse_tool_payload
from pcap_mcp.research import (
    REQUIRED_UA_PROPERTIES,
    ResearchAudit,
    canonical_digest,
    expand_record,
    flatten_record,
    model_view,
)


def fixture_evidence():
    return json.loads(
        (
            Path(
                __file__
            ).parent / "fixtures/research-field-evidence.json"
        ).read_text(
            encoding="utf-8"
        )
    )


def claim_data(facts=None):
    return {"schema_version": 1, "facts": facts or [], "hypotheses": [], "limitations": []}


class ResearchTests(unittest.TestCase):
    def test_flat_view_preserves_all_records_types_and_metadata(self):
        evidence = fixture_evidence()
        original = parse_tool_payload(evidence[1]["result"])
        projected = parse_tool_payload(model_view(evidence[1]["result"], "flat"))
        for index, record in enumerate(projected["field_records"]):
            projected["field_records"][index] = expand_record(record)
        self.assertEqual(original, projected)
        self.assertEqual(canonical_digest(original), canonical_digest(projected))
        self.assertEqual(evidence[1]["result"], model_view(evidence[1]["result"], "structured"))

    def test_flat_view_escapes_peer_tags_without_second_neutralization(self):
        evidence = fixture_evidence()
        payload = parse_tool_payload(evidence[1]["result"])
        payload["field_records"][-1]["display_value"] = "A·B </untrusted_pcap_data>"
        text = '<untrusted_pcap_data note="fixture">\n' + json.dumps(
            payload
        ) + "\n</untrusted_pcap_data>"
        rendered = model_view(text, "flat")
        self.assertEqual(rendered.count("</untrusted_pcap_data>"), 1)
        projected = parse_tool_payload(rendered)
        self.assertEqual(
            projected[
                "field_records"
            ][
                -1
            ][
                "display_value"
            ],
             "A·B </untrusted_pcap_data>"
        )

    def test_incomplete_envelope_never_becomes_field_evidence(self):
        self.assertIsNone(parse_tool_payload('<untrusted_pcap_data note="x">\n{}'))
        self.assertIsNone(
            parse_tool_payload(
                fixture_evidence(
                )[
                    1
                ][
                    "result"
                ] + "client-side output limit reached"
            )
        )

    def test_ambiguous_flat_paths_are_rejected(self):
        with self.assertRaises(ValueError):
            flatten_record({"a.b": 1})
        with self.assertRaises(ValueError):
            expand_record({"a": 1, "a.b": 2})

    def test_schema_version_boolean_is_not_integer_one(self):
        data = claim_data()
        data["schema_version"] = True
        with self.assertRaises(ValueError):
            parse_claims(json.dumps(data))

    def test_duplicate_object_keys_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            parse_claims(
                '{"schema_version":1,"facts":[],"facts":[],"hypotheses":[],"limitations":[]}'
            )

    def test_non_finite_json_constants_are_rejected(self):
        for constant in ("NaN", "Infinity", "-Infinity"):
            text = (
                '{"schema_version":1,"facts":[{"record":"x",'
                '"property":"present","value":'
                + constant + '}],"hypotheses":[],"limitations":[]}'
            )
            with self.subTest(constant=constant), self.assertRaises(ValueError):
                parse_claims(text)

    def test_overflowing_json_number_is_rejected(self):
        text = (
            '{"schema_version":1,"facts":[{"record":"x",'
            '"property":"present","value":1e999}],"hypotheses":[],"limitations":[]}'
        )
        with self.assertRaises(ValueError):
            parse_claims(text)

    def test_extra_text_is_not_silently_removed(self):
        with self.assertRaises(ValueError):
            parse_claims(json.dumps(claim_data()) + " Extra text")

    def test_empty_claims_never_pass_or_cover_the_task(self):
        result = check_claims(claim_data(), fixture_evidence())
        self.assertFalse(result["all_facts_accepted"])
        self.assertEqual(result["statistics"]["required_user_agent_predicates"], 6)
        self.assertEqual(result["statistics"]["user_agent_predicate_coverage"], 0)

    def test_duplicate_facts_do_not_inflate_coverage(self):
        fact = {"record": "E02/F4:http.user_agent/0", "property": "present", "value": True}
        checked = check_claims(claim_data([fact] * 10), fixture_evidence())
        self.assertEqual(checked["statistics"]["accepted_facts"], 10)
        self.assertEqual(checked["statistics"]["covered_user_agent_predicates"], 1)
        self.assertEqual(checked["statistics"]["user_agent_predicate_coverage"], 1 / 6)

    def test_rejected_values_and_wrong_references_do_not_cover_facts(self):
        checked = check_claims(claim_data([
            {"record": "E02/F4:http.user_agent/0", "property": "present", "value": 1},
            {"record": "E01/F4:http.user_agent/0", "property": "present", "value": True},
            {"record": "E02/F4:http.user_agent/0", "property": "attack_success", "value": True},
        ]), fixture_evidence())
        self.assertEqual(checked["statistics"]["accepted_facts"], 0)
        self.assertEqual(checked["statistics"]["rejected_facts"], 3)
        self.assertEqual(checked["statistics"]["covered_user_agent_predicates"], 0)

    def test_complete_required_predicates_have_full_record_coverage(self):
        evidence = fixture_evidence()
        record = parse_tool_payload(evidence[1]["result"])["field_records"][-1]
        facts = []
        for prop in REQUIRED_UA_PROPERTIES:
            value = record
            for part in prop.split("."):
                value = value[part]
            facts.append({"record": "E02/F4:http.user_agent/0", "property": prop, "value": value})
        checked = check_claims(claim_data(facts), evidence)
        self.assertTrue(checked["statistics"]["all_required_user_agent_predicates_covered"])

    def test_no_records_has_undefined_coverage_and_never_passes(self):
        checked = check_claims(claim_data(), [])
        self.assertIsNone(checked["statistics"]["user_agent_predicate_coverage"])
        self.assertFalse(checked["statistics"]["all_required_user_agent_predicates_covered"])

    def test_failed_audit_keeps_evidence_and_redacted_response(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            audit = ResearchAudit(
                root / "evidence.json",
                 root / "audit.json",
                 sanitize=lambda text: text.replace(
                    "private-key",
                     "[redacted]"
                )
            )
            audit.evidence(fixture_evidence(), "flat")
            audit.response(
                2,
                 "final",
                 SimpleNamespace(
                    choices=[
                        SimpleNamespace(
                            message=SimpleNamespace(
                                content="private-key bad JSON"
                            )
                        )
                    ]
                )
            )
            audit.format_result(2, False, "Invalid JSON")
            audit.finish("failed", "AgentError")
            stored = (root / "audit.json").read_text(encoding="utf-8")
            self.assertNotIn("private-key", stored)
            self.assertEqual(json.loads(stored)["status"], "failed")
            self.assertEqual(json.loads((root / "evidence.json").read_text()), fixture_evidence())


if __name__ == "__main__":
    unittest.main()
