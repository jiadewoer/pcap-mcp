"""A failed final report must retain source evidence and count as a failure."""

import json
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from test_research import fixture_evidence

from pcap_mcp.baseline import run


class ResearchBaselineTests(unittest.TestCase):
    def test_failed_report_keeps_field_verification_and_does_not_become_completed(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            capture = root / "synthetic.pcap"
            capture.write_bytes(b"synthetic fixture; verifier simulated below")
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                         "cases": [
                            {
                                "id": "case",
                                 "capture": str(
                                    capture
                                ),
                                 "goal": "检查 HTTP",
                                 "required_tools": [
                                    "inspect_http_requests"
                                ]
                            }
                        ]
                    }
                ),
                 encoding="utf-8"
            )

            def failed(command, **kwargs):
                Path(
                    command[
                        command.index(
                            "--evidence-json"
                        ) + 1
                    ]
                ).write_text(
                    json.dumps(
                        fixture_evidence(
                        )
                    ),
                     encoding="utf-8"
                )
                Path(
                    command[
                        command.index(
                            "--audit-json"
                        ) + 1
                    ]
                ).write_text(
                    json.dumps(
                        {
                            "status": "failed",
                             "format_first_pass_valid": False,
                             "format_attempts": 2,
                             "format_repair_requests": 1,
                             "model_rounds": 3
                        }
                    ),
                     encoding="utf-8"
                )
                return subprocess.CompletedProcess(command, 1, "", "Invalid structured claims")

            verifier = types.ModuleType("pcap_mcp.verify")
            calls = []

            def verify(*args):
                calls.append(args)
                return {"record_count": 4, "matched_count": 4, "all_records_match": True}

            verifier.verify_evidence = verify
            with (
                patch.dict(
                    "os.environ",
                     {
                        "OPENAI_API_KEY": "placeholder",
                         "OPENAI_BASE_URL": "http://localhost/v1/",
                         "OPENAI_MODEL": "fake",
                         "PCAP_MCP_ALLOWED_DIRS": str(
                            root
                        )
                    }
                ),
                 patch(
                    "pcap_mcp.baseline.subprocess.run",
                     side_effect=failed
                ),
                 patch.dict(
                    sys.modules,
                     {
                        "pcap_mcp.verify": verifier
                    }
                )
            ):
                summary = run(
                    manifest,
                     root / "results",
                     repeats=1,
                     evidence_mode="field",
                     report_format="claims"
                )
            trial = summary["trials"][0]
            self.assertEqual(trial["status"], "failed")
            self.assertNotIn("checks", trial)
            self.assertEqual(trial["field_verification"]["matched_count"], 4)
            self.assertEqual(trial["format_diagnostics"]["format_repair_requests"], 1)
            self.assertEqual(trial["evidence_count"], 2)
            self.assertIsNone(calls[0][-1])
            self.assertEqual(summary["totals"]["failed"], 1)
            self.assertEqual(summary["totals"]["completed"], 0)

    def test_flat_control_configuration_is_recorded_and_forwarded(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            capture = root / "sample.pcap"
            capture.write_bytes(b"synthetic")
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                         "cases": [
                            {
                                "id": "case",
                                 "capture": str(
                                    capture
                                ),
                                 "goal": "HTTP"
                            }
                        ]
                    }
                ),
                 encoding="utf-8"
            )
            commands = []

            def failed(command, **kwargs):
                commands.append(command)
                return subprocess.CompletedProcess(command, 1, "", "simulated preflight failure")

            with (
                patch.dict(
                    "os.environ",
                     {
                        "OPENAI_API_KEY": "placeholder",
                         "OPENAI_BASE_URL": "http://localhost/v1/",
                         "OPENAI_MODEL": "fake",
                         "PCAP_MCP_ALLOWED_DIRS": str(
                            root
                        )
                    }
                ),
                 patch(
                    "pcap_mcp.baseline.subprocess.run",
                     side_effect=failed
                )
            ):
                summary = run(
                    manifest,
                     root / "results",
                     repeats=1,
                     evidence_mode="field",
                     evidence_view="flat",
                     temperature=0.0,
                     seed=7
                )
            self.assertEqual(summary["experiment"]["evidence_view"], "flat")
            self.assertEqual(summary["experiment"]["seed"], 7)
            command = commands[0]
            self.assertEqual(command[command.index("--evidence-mode") + 1], "field")
            self.assertEqual(command[command.index("--evidence-view") + 1], "flat")
            self.assertIn("--audit-json", command)


if __name__ == "__main__":
    unittest.main()
