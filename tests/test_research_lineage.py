"""Counterexamples for fixed-output gates and paired replay accounting."""

import asyncio
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from pcap_mcp.lineage import (
    ATTRIBUTION_TARGETS,
    FACT_TARGETS,
    GATES,
    analyze_saved,
    build_suite,
    deterministic_proposal,
    evaluate_proposal,
    lineage_value,
    model_messages,
    parse_proposal,
    plan_runs,
    summarize,
    validate_suite,
)
from pcap_mcp.lineage_runner import run_study
from pcap_mcp.research import canonical_digest, expand_record

SEED_DIR = Path(__file__).resolve().parents[1] / "benchmarks/lineage"


def ideal_proposal(case):
    result = {"schema_version": 1, "facts": [], "attributions": [],
              "hypotheses": [], "limitations": []}
    for rid, slot in case["slots"].items():
        for kind, properties in (("facts", FACT_TARGETS),
                                 ("attributions", ATTRIBUTION_TARGETS)):
            for prop in properties:
                if prop in case["gold"][slot]:
                    result[kind].append({"record": "E02/" + rid, "property": prop,
                                         "value": case["gold"][slot][prop]})
    return result


class LineageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suite = build_suite(SEED_DIR)

    def case(self, pair, variant="a"):
        return deepcopy(next(case for case in self.suite["cases"]
                             if case["pair"] == pair and case["variant"] == variant))

    def test_same_display_can_require_different_control_answers(self):
        left, right = self.case("control-removal"), self.case("control-removal", "b")
        self.assertEqual(left["records"][0]["display_value"], right["records"][0]["display_value"])
        self.assertEqual(left["gold"]["ua0"]["control_removal_observed"], "no")
        self.assertEqual(right["gold"]["ua0"]["control_removal_observed"], "yes")

    def test_upstream_replacements_do_not_determine_dot_origin(self):
        for variant, count in (("a", 2), ("b", 0)):
            case = self.case("upstream-decoder", variant)
            self.assertEqual(case["gold"]["ua0"][
                "input_decoding.tshark_display_replacement_characters"], count)
            self.assertEqual(
                lineage_value(case["records"][0], "middle_dot_origin"), "decoded_source"
            )

    def test_full_correct_proposals_have_full_coverage_in_each_gate(self):
        for case in self.suite["cases"]:
            result = evaluate_proposal(ideal_proposal(case), case)
            for gate in GATES:
                for kind in ("facts", "attributions"):
                    self.assertTrue(result["gates"][gate][kind]["all_required_correct"])

    def test_deterministic_baseline_reads_evidence_not_gold_answers(self):
        case = self.case("control-removal")
        case["gold"]["ua0"]["present"] = "secret_wrong_answer"
        proposal = deterministic_proposal(case)
        self.assertIs(proposal["facts"][0]["value"], True)
        self.assertEqual(proposal["attributions"][0]["value"], "analysis_program")

    def test_field_gate_does_not_fix_false_attribution(self):
        case = self.case("control-removal")
        proposal = ideal_proposal(case)
        proposal["attributions"][0]["value"] = "decoded_source"
        result = evaluate_proposal(proposal, case)["gates"]
        self.assertEqual(result["field"]["attributions"]["defined_incorrect"], 1)
        self.assertEqual(result["field-and-lineage"]["attributions"]["defined_incorrect"], 0)
        self.assertEqual(result["field-and-lineage"]["attributions"]["covered"], 1)
        self.assertFalse(result["field-and-lineage"]["attributions"]["all_required_correct"])

    def test_false_fact_is_removed_with_same_proposal_hash(self):
        case = self.case("control-removal")
        proposal = ideal_proposal(case)
        proposal["facts"][5]["value"] = 3
        digest = canonical_digest(proposal)
        result = evaluate_proposal(proposal, case)
        self.assertEqual(result["proposal_sha256"], digest)
        self.assertEqual(canonical_digest(proposal), digest)
        self.assertEqual(result["gates"]["off"]["facts"]["defined_incorrect"], 1)
        self.assertEqual(result["gates"]["field"]["facts"]["defined_incorrect"], 0)
        self.assertEqual(result["gates"]["field"]["facts"]["covered"], 7)

    def test_independent_gold_exposes_corrupted_record_acceptance(self):
        case = self.case("control-removal")
        case["records"][0]["transformations"]["unicode_controls_removed"] = 7
        proposal = ideal_proposal(case)
        proposal["facts"][5]["value"] = 7
        result = evaluate_proposal(proposal, case)["gates"]["field"]["facts"]
        # Matching a tampered record is not independent proof of correctness.
        self.assertEqual(result["defined_incorrect"], 1)

    def test_missing_counts_require_unknown_not_zero(self):
        case = self.case("missing-lineage", "b")
        self.assertEqual(lineage_value(case["records"][0], "middle_dot_origin"), "unknown")
        proposal = ideal_proposal(case)
        proposal["attributions"][0]["value"] = "none"
        proposal["facts"].append({
            "record": "E02/F4:http.user_agent/0",
            "property": "transformations.unicode_controls_removed", "value": 0,
        })
        result = evaluate_proposal(proposal, case)["gates"]["field-and-lineage"]
        self.assertEqual(result["facts"]["out_of_scope"], 0)
        self.assertTrue(any(
            item["status"] == "property_unavailable" for item in result["decisions"]
        ))
        self.assertEqual(result["attributions"]["covered"], 1)

    def test_invalid_count_types_do_not_create_known_labels(self):
        for value in (True, -1, 1.0, "1"):
            record = self.case("control-removal")["records"][0]
            record["transformations"]["unicode_controls_removed"] = value
            self.assertEqual(lineage_value(record, "control_removal_observed"), "unknown")

    def test_both_and_none_are_distinct_closed_labels(self):
        record = self.case("control-removal")["records"][0]
        record["transformations"]["middle_dots_in_decoded_source"] = 2
        self.assertEqual(lineage_value(record, "middle_dot_origin"), "both")
        self.assertEqual(lineage_value(self.case("reference-relabel")["records"][0],
                                       "middle_dot_origin"), "none")

    def test_unknown_reference_does_not_pass_as_abstention(self):
        case = self.case("missing-lineage", "b")
        proposal = ideal_proposal(case)
        proposal["attributions"][0]["record"] = "E99/F4:http.user_agent/0"
        result = evaluate_proposal(proposal, case)["gates"]["field-and-lineage"]
        self.assertEqual(result["attributions"]["covered"], 1)

    def test_gold_and_pair_names_are_not_sent_to_model(self):
        case = self.case("control-removal")
        case["pair"] = "PRIVATE_PAIR_MARKER"
        case["gold"]["ua0"]["middle_dot_origin"] = "PRIVATE_GOLD_MARKER"
        text = json.dumps(model_messages(case, "structured"))
        self.assertNotIn('"gold"', text)
        self.assertNotIn("PRIVATE_PAIR_MARKER", text)
        self.assertNotIn("PRIVATE_GOLD_MARKER", text)
        self.assertNotIn("plain-directive", text)

    def test_flat_view_preserves_record_values_and_missingness(self):
        case = self.case("missing-lineage", "b")
        text = model_messages(case, "flat")[1]["content"]
        body = text.split('\">\n', 1)[1].rsplit("\n</untrusted_pcap_data>", 1)[0]
        record = json.loads(body)["field_records"][0]
        self.assertEqual(expand_record(record), case["records"][0])

    def test_relabelled_record_requires_new_reference(self):
        case = self.case("reference-relabel", "b")
        proposal = ideal_proposal(case)
        proposal["facts"][0]["record"] = "E02/F4:http.user_agent/0"
        result = evaluate_proposal(proposal, case)["gates"]["field"]["facts"]
        self.assertEqual(result["covered"], 7)

    def test_duplicate_and_conflicting_outputs_cannot_inflate_coverage(self):
        case = self.case("control-removal")
        proposal = ideal_proposal(case)
        proposal["facts"].extend([deepcopy(proposal["facts"][0])] * 10)
        wrong = deepcopy(proposal["facts"][0])
        wrong["value"] = False
        proposal["facts"].append(wrong)
        result = evaluate_proposal(proposal, case)["gates"]
        self.assertEqual(result["off"]["facts"]["covered"], 7)
        self.assertEqual(result["field"]["facts"]["covered"], 8)

    def test_empty_proposal_has_no_precision_and_zero_coverage(self):
        case = self.case("control-removal")
        data = ideal_proposal(case)
        data["facts"], data["attributions"] = [], []
        result = evaluate_proposal(data, case)["gates"]["field-and-lineage"]
        self.assertIsNone(result["facts"]["supported_output_fraction"])
        self.assertEqual(result["facts"]["unambiguous_required_coverage"], 0)

    def test_attribution_cannot_be_laundered_as_a_field_fact(self):
        case = self.case("control-removal")
        data = ideal_proposal(case)
        data["facts"].append(deepcopy(data["attributions"][0]))
        result = evaluate_proposal(data, case)["gates"]["off"]["facts"]
        self.assertEqual(result["out_of_scope"], 1)

    def test_schema_rejects_duplicate_extra_and_boolean_version(self):
        data = ideal_proposal(self.case("control-removal"))
        for bad in (json.dumps({**data, "schema_version": True}),
                    json.dumps({**data, "extra": 1}),
                    json.dumps(data).replace('"schema_version": 1',
                                             '"schema_version": 1, "schema_version": 1')):
            with self.assertRaises(ValueError):
                parse_proposal(bad)

    def test_suite_validator_rejects_source_gold_and_display_conflicts(self):
        suite = deepcopy(self.suite)
        suite["cases"][0]["records"][0]["display_value"] = "tampered"
        with self.assertRaises(ValueError):
            validate_suite(suite)

    def test_plan_is_balanced_and_repeatable(self):
        first = plan_runs(self.suite, 2, 2026)
        self.assertEqual(first, plan_runs(self.suite, 2, 2026))
        self.assertEqual(len(first), 40)
        self.assertEqual(len({item["run_id"] for item in first}), 40)

    def test_failed_and_unattempted_runs_stay_in_pair_and_coverage_denominators(self):
        plan = plan_runs(self.suite, 1, 2026)
        result = summarize(self.suite, plan, [{**plan[0], "status": "failed"}])
        self.assertEqual(result["failed"], 1)
        self.assertEqual(result["not_attempted"], 19)
        self.assertEqual(len(result["pair_trials"]), 30)
        for total in result["totals"]:
            self.assertEqual(total["exact_pair_fraction_all_planned"], 0)
            self.assertEqual(total["attributions"]["coverage_all_planned"], 0)
            self.assertIsNone(total["attributions"]["supported_output_fraction"])


class RunnerTests(unittest.TestCase):
    def run_fake(self, folder, first_bad=False, first_error=False):
        suite = build_suite(SEED_DIR)
        plan = plan_runs(suite, 1, 2026)
        cases = {case["id"]: case for case in suite["cases"]}
        requests = []

        async def create(**args):
            index = len(requests)
            requests.append(args)
            if first_error and index == 0:
                raise RuntimeError("private-api-key https://private-provider.example")
            content = "not JSON" if first_bad and index == 0 else json.dumps(
                ideal_proposal(cases[plan[index]["case_id"]]), ensure_ascii=False
            )
            message = SimpleNamespace(content=content)
            return SimpleNamespace(choices=[SimpleNamespace(message=message)])

        client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
        with patch("builtins.print"):
            result = asyncio.run(run_study(client, "fake-model", suite, folder))
        self.assertEqual(len(requests), 20)
        self.assertTrue(all("tools" not in request for request in requests))
        return result

    def test_fixed_proposals_replay_without_api_and_match_original_analysis(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            expected = self.run_fake(root / "study")
            replay = analyze_saved(root / "study", root / "replayed.json")
            self.assertEqual(expected, replay)
            self.assertEqual(expected["completed"], 20)
            self.assertTrue(all(total["exact_pair_fraction_all_planned"] == 1
                                for total in expected["totals"]))

    def test_format_failure_is_retained_and_never_retried(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = self.run_fake(root / "study", first_bad=True)
            self.assertEqual(result["failed"], 1)
            trial = json.loads((root / "study/run-0001/trial.json").read_text())
            self.assertFalse(trial["format_valid"])
            self.assertTrue((root / "study/run-0001/response.json").is_file())
            self.assertFalse((root / "study/run-0001/proposal.json").exists())

    def test_changed_saved_proposal_cannot_be_called_fixed_output_replay(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.run_fake(root / "study")
            path = root / "study/run-0001/proposal.json"
            data = json.loads(path.read_text())
            data["facts"][0]["value"] = "tampered"
            path.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, "differs"):
                analyze_saved(root / "study", root / "replayed.json")

    def test_changed_suite_cannot_be_replayed_under_old_protocol(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.run_fake(root / "study")
            path = root / "study/suite.json"
            data = json.loads(path.read_text())
            data["scope"] = "changed"
            path.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, "Suite changed"):
                analyze_saved(root / "study", root / "replayed.json")

    def test_api_failure_keeps_request_and_does_not_store_provider_secrets(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = self.run_fake(root / "study", first_error=True)
            self.assertEqual(result["failed"], 1)
            folder = root / "study/run-0001"
            trial = (folder / "trial.json").read_text()
            self.assertNotIn("private-api-key", trial)
            self.assertTrue((folder / "request.json").is_file())
            self.assertFalse((folder / "response.json").exists())

    def test_changed_trial_source_binding_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.run_fake(root / "study")
            path = root / "study/run-0001/trial.json"
            data = json.loads(path.read_text())
            data["request_sha256"] = "0" * 64
            path.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, "different model input"):
                analyze_saved(root / "study", root / "replayed.json")


if __name__ == "__main__":
    unittest.main()
