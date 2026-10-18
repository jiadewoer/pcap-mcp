"""Prespecified condition scheduling and source-equivalence checks."""

import importlib.util
import unittest
from collections import Counter
from pathlib import Path

path = Path(__file__).resolve().parents[1] / "scripts/run_research_pilot.py"
spec = importlib.util.spec_from_file_location("research_pilot", path)
assert spec is not None and spec.loader is not None
pilot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pilot)


class ResearchPlanTests(unittest.TestCase):
    def test_balanced_reproducible_case_level_schedule(self):
        case_ids = [
            "normal",
             "plain-directive",
             "literal-dots",
             "unicode-control",
             "missing-user-agent"
        ]
        planned = pilot.schedule(case_ids, 3, 2026)
        self.assertEqual(len(planned), 45)
        self.assertEqual(planned, pilot.schedule(case_ids, 3, 2026))
        self.assertTrue(
            all(
                count == 3 for count in Counter(
                    (
                        row[
                            "case_id"
                        ],
                         row[
                            "condition"
                        ]
                    ) for row in planned
                ).values(
                )
            )
        )
        for offset in range(0, len(planned), 3):
            block = planned[offset:offset + 3]
            self.assertEqual(len({row["case_id"] for row in block}), 1)
            self.assertEqual({row["condition"] for row in block}, set(pilot.CONDITIONS))

    def records(self, hashes):
        return [
            {
                "case_id": "normal",
                 "repeat": 1,
                 "condition": condition,
                 "trial": {
                    "evidence_views": [
                        {
                            "canonical_payload_sha256": value
                        }
                    ] if value else [
                    ]
                }
            } for condition,
             value in zip(
                pilot.CONDITIONS,
                 hashes,
                 strict=True
            )
        ]

    def test_equal_source_payloads_pass_equivalence(self):
        checked = pilot.source_comparisons(self.records(["same"] * 3))[0]
        self.assertTrue(checked["complete"])
        self.assertTrue(checked["canonical_source_payloads_equal"])

    def test_different_source_payloads_do_not_pass(self):
        checked = pilot.source_comparisons(self.records(["same", "different", "same"]))[0]
        self.assertFalse(checked["canonical_source_payloads_equal"])

    def test_missing_field_evidence_is_undefined_not_equal(self):
        checked = pilot.source_comparisons(self.records(["same", None, "same"]))[0]
        self.assertFalse(checked["complete"])
        self.assertIsNone(checked["canonical_source_payloads_equal"])


if __name__ == "__main__":
    unittest.main()
