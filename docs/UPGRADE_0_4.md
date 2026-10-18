# 从 0.3.0 升级并验证 0.4.0

保留已有的 `pcap-mcp-v0.3.0-agent` 目录和生成的 `report.md` / `evidence.json`，把新 ZIP 解压到**另一个目录**。若项目已在 Git 仓库内维护，可把新包与仓库源码对比后在新分支合并；不要覆盖 `.git`、你自己的抓包或 API 配置。此 ZIP 不是补丁文件，而是完整源码。

以下命令在 PowerShell 中进入**新包内能看到 `pyproject.toml` 的 `pcap-mcp` 目录**后执行：

```powershell
uv sync --extra dev --extra client
uv run --no-sync python -c "import pcap_mcp; print(pcap_mcp.__version__)"
uv run --no-sync pytest -q -m "not integration"
uv run --no-sync pytest -q -m integration
```

第一条版本检查应输出 `0.4.0`。单元测试不需要网络抓包工具；两项集成测试需要 `tshark` 和 `capinfos` 在 PATH 中。集成测试的 Agent 使用**模拟模型**，所以还要用你的 Ollama 做一次独立验收：

```powershell
$env:PCAP_MCP_ALLOWED_DIRS = (Resolve-Path .\tests\fixtures).Path
$env:OPENAI_BASE_URL = "http://127.0.0.1:11434/v1/"
$env:OPENAI_API_KEY = "ollama"
$env:OPENAI_MODEL = "qwen3:8b"
$capture = (Resolve-Path .\tests\fixtures\injection_demo.pcap).Path

uv run --no-sync pcap-mcp-agent `
  --capture "$capture" `
  --goal "检查 HTTP 请求的 User-Agent 是否存在提示注入线索，引用证据编号" `
  --report-language zh --max-calls 2 --max-rounds 3 `
  --request-timeout 120 `
  --output .\report.md --evidence-json .\evidence.json

Get-Content .\report.md -Raw -Encoding UTF8
(Get-Content .\evidence.json -Raw -Encoding UTF8 | ConvertFrom-Json) |
  Select-Object id, tool, error, truncated, security_warning
```

期望观察到 `E01=summarize_capture`；当模型选择 HTTP 工具时，还会有 `E02=inspect_http_requests`，其 `security_warning=True`。模型可能提前结束，因此 `E02` 是模型行为的验收目标，不能把“命令完成”直接等同于“已调查 HTTP”。新版运行中会在终端报告概览、工具调用和可能的中文改写；`--quiet` 可隐藏这些进度。

根目录中示例用的 `report.md`、`evidence.json` 和本地 `.env` 已加入 `.gitignore`；自定义输出路径仍需自己检查，不要将敏感抓包证据提交到公开仓库。

项目把报告和证据 JSON 写为 UTF-8。旧版 Windows PowerShell 用不指定编码的 `Get-Content` 可能显示乱码；请使用上面的 `-Encoding UTF8`。模型正文语言与文件编码是两个不同问题：如果模型在中文目标下仍写英文，控制层会在剩余模型轮数内请求一次不带工具的改写；不能修正时会保留原文并标警告。证据编号可以核实**调用发生过**，不能证明模型的每项结论正确。

**面试时可讲的改动：**“0.3.0 的真实 Ollama 测试证明工具选择与证据记录能跑通，但模型把中文问题回答成了英文。我在 0.4.0 把报告语言变成控制层可检查的要求：有剩余预算才改写一次，拒绝丢失既有证据编号的改写，并保留失败警告；同时加了本地模型超时配置和运行进度。”
