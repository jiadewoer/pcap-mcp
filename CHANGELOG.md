# Changelog

## reporting-acceptance-v1 (core 0.8.0)

- Add program field facts and finite lineage labels; keep model prose explicitly unverified.
- Add heldout compound/boundary records, frozen 2×2 development prompts and development-only selection.
- Add one runner for saved-record/model/actual MCP Agent comparisons and fixed-output replay.
- Preserve old checker/addon bytes and core version required by historical replay.
- Ship original-directory update preflight, backups, rollback and Windows batch acceptance.


## 0.5.0

- 增加可重复的调查基线命令、固定演示任务和逐次运行记录；输出使用独立目录，保留失败试验。
- 记录抓包哈希、模型、调用预算、运行耗时及有限的自动检查。报告证据编号只检查正文，不把证据索引算入。
- 记录 0.4.0 演示报告中的两处人工核验问题；明确自动检查不能验证报告事实。
- 测试输出目录加入忽略规则。真实 Ollama 重复实验需要在用户的本地环境执行。

## 0.4.0

- Add an explicit `--report-language auto|zh|en` setting. For Chinese goals, the controller
  requests Simplified Chinese and checks the model's final prose. If it is still English and a
  model round remains, it makes one rewrite request without tools; it only accepts a rewrite that
  retains existing evidence citations. If the budget is exhausted or the rewrite fails, the
  original report is preserved with a clear language warning.
- Show capture-summary and tool-call progress on stderr without exposing packet content;
  `--quiet` suppresses it. Increase the default model request timeout to 120 seconds and allow
  `--request-timeout` from 15 to 600 seconds for local models.
- Turn invalid-capture and model API connection/timeout failures into concise CLI errors.
  Document PowerShell's explicit UTF-8 read command for reports and evidence files.
- Ignore the example report, evidence JSON, and local `.env` files so a normal Git commit
  does not accidentally include capture-derived metadata or API credentials.
- Add controller regression tests for language repair, budget limits, citation preservation,
  and CLI preflight failures. Real model wording still requires a local acceptance run.

## 0.3.0

- Add `pcap-mcp-agent`, a goal-driven, read-only investigation command over the existing MCP
  server. It always obtains a summary first, lets the model select focused follow-up tools,
  records evidence IDs, and produces a report with an evidence index.
- Bind each investigation to one validated capture path outside the model's control. Reject
  unavailable tools and oversized arguments, reuse repeated calls, and cap tool calls and model
  rounds. Allow optional local Markdown and JSON evidence exports.
- Keep the interactive terminal client as a separate workflow. The new agent uses the existing
  optional `client` dependency group and the same redaction policy as the MCP server.
- Add controller tests with a simulated API and MCP session. A real API provider and real
  Wireshark binaries are still needed for end-to-end validation in a user's environment.

## 0.2.0

- Bound Wireshark stdout and stderr while the subprocess runs, reject any nonzero exit status,
  and limit complete MCP result size. New settings: `PCAP_MCP_MAX_OUTPUT_MB` and
  `PCAP_MCP_MAX_RESULT_CHARS`.
- Redact compressed IPv6 addresses, including bracketed literals. Wrap validation and analysis
  errors as untrusted tool output without echoing the rejected input path.
- Restrict both the predicates and returned fields of `run_display_filter` to approved packet
  metadata. Raw payload, arbitrary field names, and the former decoded-payload convenience field
  are no longer available through this tool.
- Select TLS versions from ServerHello (including the TLS 1.3 supported-version extension),
  classify TCP handshakes using chronological packet directions, separate DNS request counts
  from response codes, and use a defined nearest-rank percentile.
- Make the injection fixture reproducible and add an HTTP User-Agent example. Add real Wireshark
  integration coverage and a Windows/Linux Python test matrix.
- Move the OpenAI-compatible terminal client's dependency to the `client` extra. Use
  `uv sync --extra client` before running that script.

### Upgrade notes

Callers that previously requested `tcp.payload`, `http.file_data`, `_ws.col.Info`, or arbitrary
fields from `run_display_filter` now receive an error. Use approved metadata fields or inspect
the capture in a locally controlled Wireshark session for raw evidence. Tool errors are now
JSON objects wrapped in `<untrusted_pcap_data>`, rather than plain text. TLS `handshakes` counts
observed ServerHello packets; `observed_hello_packets` counts both client and server hellos.
