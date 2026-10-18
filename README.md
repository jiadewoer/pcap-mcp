# pcap-mcp：可复核的本地抓包分析

通过 MCP 调用 Wireshark 的 tshark/capinfos，提供 12 个只读工具，覆盖 HTTP、DNS、TLS、TCP 等抓包观察。
模型可以选择工具；路径、参数、调用预算、证据保存和报告发布由程序控制。

**当前状态：工具工程版本可使用；模型自动结论与自动语义验收仍待完善。**
历史自动审阅曾漏掉明确错误，因此日常入口发布程序观察，不发布模型自由正文，不自动认定任意调查目标已充分回答。
完整状态见 [PROJECT-STATUS.md](docs/PROJECT-STATUS.md)。

## Windows 首次从 GitHub 安装

需要 Python 3.11 或更新版本、Git、uv，以及可从 PATH 调用的 tshark/capinfos。
在已克隆的仓库根目录执行：

```powershell
uv sync --locked --extra dev
tshark -v
capinfos -v
powershell -NoProfile -ExecutionPolicy Bypass -File .\pcap-final-v1\Run-PCAP.ps1 -Mode check
```

检查实际 MCP 注册的 12 个工具，不调用 Ollama。Git 克隆的源码可直接使用，无需执行历史覆盖安装器。
`Install-Final.ps1` 为旧目录的增量交付保留，会备份并恢复其包内的根目录说明模板。

## 分析演示抓包

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\pcap-final-v1\Run-PCAP.ps1 -Mode analyze -Capture .\tests\fixtures\injection_demo.pcap -Tools http -RunId demo-http-01
notepad .\baseline-runs\final-demo-http-01\REPORT.md
```

演示文件由脚本合成，不含用户真实网络流量；本命令模型调用为 0。
HTTP 导出字段在发布前另做原包复核；其他协议为有采样边界的解析器观察。
将 Capture 换成自己的文件可发起新分析；报告、输入快照、审计记录和 ZIP 写入被 Git 忽略的 baseline-runs/。

## 日常模式

| 模式 | 功能 | 新模型请求 |
| --- | --- | --- |
| check | 环境、源码摘要及实际 MCP 工具注册检查 | 0 |
| analyze | 按指定工具直接分析抓包 | 0 |
| agent | 本机 Ollama 单次选择 0 至 2 个工具 | 最多 1 |
| report | 导出已有结果或失败记录 | 0 |
| serve | MCP stdio 服务 | 服务自身为 0 |

agent 使用已验证的本地 qwen3:8b 摘要；不会自动下载、切换、修复或重试。
RunId 绑定一次调查；同一编号重跑不产生新模型请求。HTTP 500、超时等已发起尝试保留并计入预算。
模型只读取目标和初始概览，不基于后续工具结果开展多轮自主调查。

## 仓库结构

| 路径 | 用途 |
| --- | --- |
| src/pcap_mcp/ | 原包入口与 23 个核心模块，保留兼容和研究接口 |
| pcap-final-v1/ | 已验证的日常入口与独立运行副本，保留原字节和摘要 |
| scripts/ | 客户端、合成样例生成和研究辅助脚本 |
| tests/、benchmarks/ | 测试、合成抓包及开发基准输入 |
| agent-v2/input/ | 核心回归所需的 4 份合成工具输出及清单 |
| report-boundary/、validation-v3/ | 回归测试和历史接口所需的兼容代码 |
| docs/ | 使用说明、安全模型、项目状态及历史设计资料 |
| .github/workflows/ci.yml | Windows 核心回归和 Linux 实际解析器/入口回归 |

src 与日常入口的 runtime 同时保留，避免迁移改变已核验行为；日常入口以独立运行副本为准。
旧实验原始请求、响应、抓包、ZIP 和备份在本地保留，不随仓库同步。
pcap-final-v1/results/ 和验证资料是已有验收摘要，不是原始实验全集。

## 测试

```powershell
& .\.venv\Scripts\python.exe -X utf8 -B -m pytest -q tests
& .\.venv\Scripts\python.exe -X utf8 -B -m pytest -q .\pcap-final-v1\test_final.py
```

模型请求均为模拟。第二条需要实际 tshark/capinfos 和 MCP 子进程。
CI 运行这些回归检查；本次整理没有取得旧 Ruff/Mypy 检查的新通过结果，静态检查问题后续单独整改。
源码和包清单按字节校验，.gitattributes 禁用自动换行转换，避免 Windows checkout 破坏摘要。
GitHub 更新与上传范围见 [PUBLISHING.md](docs/PUBLISHING.md)。

## 实验结果与限制

最后一轮开发对照 A 8/8、B 8/8，冻结关键词规则 4/8；未观察到额外参数提醒增益。
上一轮模型 7/8、规则 8/8 的结果保留。样例已用于开发，不能据此宣称模型普遍优于规则、生产泛化或提示注入防护已全面验证。
详情见 [已有实验台账](pcap-final-v1/docs/RESULTS.md) 和 [安全模型](docs/SECURITY.md)。

MIT License。
