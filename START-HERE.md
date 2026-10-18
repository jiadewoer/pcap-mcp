# 从这里开始

当前为工具分析与证据复核版本；自动结论和自动语义验收仍未完成。
在克隆的仓库根目录执行：

```powershell
uv sync --locked --extra dev
powershell -NoProfile -ExecutionPolicy Bypass -File .\pcap-final-v1\Run-PCAP.ps1 -Mode check
powershell -NoProfile -ExecutionPolicy Bypass -File .\pcap-final-v1\Run-PCAP.ps1 -Mode analyze -Capture .\tests\fixtures\injection_demo.pcap -Tools http -RunId demo-http-01
notepad .\baseline-runs\final-demo-http-01\REPORT.md
```

以上不请求模型。先确保 tshark/capinfos 可运行。新克隆的目录无需执行历史覆盖安装器。
baseline-runs/ 保存报告、输入快照和审计资料，不提交到 Git。

需要 Ollama 选择工具时，先启动已安装的 Ollama 和固定版本 qwen3:8b，再执行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\pcap-final-v1\Run-PCAP.ps1 -Mode agent -Capture .\tests\fixtures\injection_demo.pcap -Goal "查看HTTP请求字段的存在性、展示值和转换来源" -RunId demo-agent-01
```

这是一项明确的新调查，最多 1 次模型尝试；当前入口不让模型生成最终结论。
同一 RunId 再次执行只读已有结果；不要改名补跑同一失败来覆盖实验结果。

见 [README](README.md)、[工程说明](pcap-final-v1/docs/PROJECT.md)、[MCP 配置](pcap-final-v1/docs/MCP.md)。
包内旧结项材料描述当时工具工程范围；当前完整目标状态以 [PROJECT-STATUS.md](docs/PROJECT-STATUS.md) 为准。
