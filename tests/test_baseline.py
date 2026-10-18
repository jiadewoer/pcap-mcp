"""Standard-library tests also run when third-party packages cannot be installed."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pcap_mcp.baseline import load_manifest, run, score


class BaselineTests(unittest.TestCase):
    def test_manifest_validation_and_scoring_does_not_count_index(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "cases.json"
            case = {
                "id": "demo",
                "capture": "fixture.pcap",
                "goal": "检查 HTTP",
                "required_tools": ["summarize_capture", "inspect_http_requests"],
                "warning_tools": ["inspect_http_requests"],
            }
            path.write_text(json.dumps({"schema_version": 1, "cases": [case]}), encoding="utf-8")
            self.assertEqual(load_manifest(path), [case])
            evidence = [
                {"id": "E01", "tool": "summarize_capture", "error": False},
                {"id": "E02", "tool": "inspect_http_requests", "security_warning": True},
            ]
            index = "\n## 证据索引\n| E01 | summary |\n| E02 | HTTP |"
            self.assertFalse(score("没有引用。" + index, evidence, case)["citations_exist"])
            checks = score("HTTP 请求见 [E02]。" + index, evidence, case)
            self.assertTrue(all(checks.values()))
            self.assertFalse(score("错误引用 [E99]。" + index, evidence, case)["citations_exist"])
            path.write_text(
                json.dumps({"schema_version": 1, "cases": [case, case]}), encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                load_manifest(path)

    def test_repeat_runner_retains_hash_and_independent_trials(self):
        fixture = Path(__file__).parent / "fixtures" / "injection_demo.pcap"
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            manifest = root / "cases.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "cases": [
                            {
                                "id": "demo",
                                "capture": str(fixture.resolve()),
                                "goal": "检查 HTTP",
                                "required_tools": ["summarize_capture", "inspect_http_requests"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            counter = 0

            def simulated_agent(command, **kwargs):
                nonlocal counter
                counter += 1
                self.assertEqual(command[:3], [sys.executable, "-m", "pcap_mcp.agent"])
                self.assertEqual(kwargs["encoding"], "utf-8")
                output = Path(command[command.index("--output") + 1])
                output.write_text("事实 [E01][E02]。\n## 证据索引\n", encoding="utf-8")
                evidence = Path(command[command.index("--evidence-json") + 1])
                evidence.write_text(
                    json.dumps(
                        [
                            {"id": "E01", "tool": "summarize_capture", "error": False},
                            {"id": "E02", "tool": "inspect_http_requests", "error": False},
                        ]
                    ),
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(command, 0, "", "")

            environment = {
                "OPENAI_API_KEY": "placeholder",
                "OPENAI_BASE_URL": "http://localhost:11434/v1/",
                "OPENAI_MODEL": "qwen3:8b",
                "PCAP_MCP_ALLOWED_DIRS": str(fixture.parent),
            }
            with (
                patch.dict("os.environ", environment),
                patch("pcap_mcp.baseline.subprocess.run", side_effect=simulated_agent),
            ):
                summary = run(manifest, root / "out", repeats=2)
            self.assertEqual(counter, 2)
            self.assertEqual(len(summary["trials"]), 2)
            self.assertTrue(all(all(x["checks"].values()) for x in summary["trials"]))
            self.assertEqual(len(summary["experiment"]["cases"][0]["capture_sha256"]), 64)
            self.assertNotIn(
                "placeholder", (root / "out" / "experiment.json").read_text(encoding="utf-8")
            )
            with self.assertRaises(FileExistsError):
                with patch.dict("os.environ", environment):
                    run(manifest, root / "out", repeats=1)

    def test_failed_run_is_saved_and_does_not_pass_checks(self):
        fixture = Path(__file__).parent / "fixtures" / "injection_demo.pcap"
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            manifest = root / "cases.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "cases": [
                            {
                                "id": "demo",
                                "capture": str(fixture.resolve()),
                                "goal": "调查",
                                "required_tools": ["summarize_capture"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            environment = {
                "OPENAI_API_KEY": "placeholder",
                "OPENAI_BASE_URL": "http://localhost:11434/v1/",
                "OPENAI_MODEL": "qwen3:8b",
                "PCAP_MCP_ALLOWED_DIRS": str(fixture.parent),
            }
            failure = subprocess.CompletedProcess([], 2, "", "model did not respond")
            with (
                patch.dict("os.environ", environment),
                patch("pcap_mcp.baseline.subprocess.run", return_value=failure),
            ):
                summary = run(manifest, root / "failed", repeats=1)
            self.assertEqual(summary["trials"][0]["status"], "failed")
            self.assertNotIn("checks", summary["trials"][0])
            trial_record = (root / "failed/demo-001/trial.json").read_text(encoding="utf-8")
            self.assertIn("model did not respond", trial_record)


if __name__ == "__main__":
    unittest.main()
