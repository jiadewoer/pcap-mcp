# v3 实际 MCP 验收扩展

这是在当前 0.8.0 工程上新增的验收入口，不更改原 Agent、字段转换、事实生成或旧评测脚本。
默认用现有 `.venv`；本次新增模块只使用已经安装的依赖。运行位置仍是 `D:\projects\pcap-mcp`。

## 安装和默认小批

将本轮交付 ZIP 放到原项目根目录，再运行：

```powershell
Set-Location D:\projects\pcap-mcp
Expand-Archive .\pcap-mcp-v3-continuation-20261011.zip -DestinationPath . -Force
& .\.venv\Scripts\python.exe .\validation-v3-update\apply_update.py --project . --check
& .\.venv\Scripts\python.exe .\validation-v3-update\apply_update.py --project .
powershell -NoProfile -ExecutionPolicy Bypass -File .\validation-v3\Run-Validation.ps1
```

最后一个命令需要 Wireshark、正在运行的 Ollama 和已安装的 `qwen3:8b`。
它不会拉取模型、重新创建环境或重装依赖。默认前两个新合成用例、一个模型、两个正文条件，
最多 **8 次**生成请求，无 SDK 重试、格式修复或失败补跑。每个请求有 120 秒超时；
超时也消耗一次预算，不能提前保证总耗时。

先只检查本地抓包和离线重算，生成请求数为零：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\validation-v3\Run-Validation.ps1 -Offline
```

输出在 `baseline-runs\agent-v3-validation-时间戳.zip`。把这个结果 ZIP 发回来即可继续检查正文。
如果中断，保留目录；已开始的计划不能重跑，避免混入补跑结果。新建一个批次会再次消耗请求。

## 较大批次必须明确增加上限

| 批次 | 抓包数 | 模型数 | 正文条件数 | 共享调查数 | 正文计划数 | 生成请求上限 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 默认小批 | 2 | 1 | 2 | 2 | 4 | 8 |
| 全部新模板 | 8 | 1 | 2 | 8 | 16 | 32 |
| 两模型小批 | 2 | 2 | 2 | 4 | 8 | 16 |
| 两模型全部模板 | 8 | 2 | 2 | 16 | 32 | 64 |

每个共享调查最多两次模型决策，再各发一次 JSON 和精简 schema 正文请求。
概览调用和最多两次聚焦工具调用都是本地 MCP 操作，不计作模型生成请求。
没有获取 HTTP 字段证据时，两个正文条件记为失败，不自动追加工具兜底。

```powershell
# 全部模板；先完成默认小批再考虑此命令
powershell -NoProfile -ExecutionPolicy Bypass -File .\validation-v3\Run-Validation.ps1 -Full -MaxRequests 32

# 第二个模型必须已经安装；替换为本机的准确名称
powershell -NoProfile -ExecutionPolicy Bypass -File .\validation-v3\Run-Validation.ps1 -Model 'qwen3:8b,qwen2.5:7b' -MaxRequests 16
```

## 研究范围

新控制器先通过真实 MCP stdio 会话完成概览和模型选工具，再冻结所得证据。
两种正文请求共享完全相同的证据、提示词、程序摘要和引用列表，只改变 `response_format`。
新请求构造器与旧 `prose-study-v3` 的提示词和请求逐项相等，已有测试核对。
这是“实际调查 + 配对正文条件”的验收；不能当作两套独立完整 Agent 的因果比较。

8 个新模板覆盖混合来源中点、两个控制字符、重复 User-Agent、空 User-Agent、较长普通值、
伪角色前缀、两请求中字段缺失、普通 UTF-8 和来源中点。
其有限预期值来自独立用例配方，未调用被测 `transform_field()` 生成答案。
预检发现解析器版本不支持某用例或预期不匹配时，保留失败，不修改答案来适配结果。
这些仍是新合成流量，不能写成“外部真实流量验证已完成”。

`summary.json` 分开保存：共享调查的程序事实完整性与源重提取、合成 oracle 匹配、
正文结构与引用、非空中文限制、各模型/条件的描述性配对数量。
正文语义验收默认空缺；合法 JSON、合法引用和程序事实不被改写都不能替代语义正确。
小批没有重复采样，不能据此宣称显著提升或稳定的跨模型结论。

响应保存的是本地脱敏副本，并记录原响应哈希、字符数和截断状态。
请求日志在发出前落盘，所有尝试、失败和中断都保留在分母。
模型身份摘要和 Ollama 版本前后核对；`reasoning_effort=none` 是请求值，
不能证明所有后端都关闭了思考。后端上下文与内部 token 上限仍未显式固定。

## 真实自有抓包与语义复核

复制 `external-manifest.example.json`，填入你有权分析的 PCAP/PCAPNG 文件和目标，再传入 `-Manifest`。
相对 capture 路径以 manifest 所在文件夹为基准。每个输入上限 200 MiB；新模板的 oracle 不适用于真实流量。
真实流量缺少预先标注时只能做字段重提取一致性检查，不能称作已验证真实答案。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\validation-v3\Run-Validation.ps1 -Manifest .\my-cases\manifest.json
```

运行结束生成 `review-template.json`。逐条查看 `program-facts.md`、两种正文的 `program-report.md`
和 `response.txt`，检查来源混淆、零计数被说成已发生、缺失被说成空、跨 occurrence 引用、
没有依据的编码/意图/成功判断及不具体的限制。填写 reviewer、decision 和必要 labels，
另存为 `review-completed.json`，再用：

```powershell
& .\.venv\Scripts\python.exe -m pcap_mcp.validation --review .\baseline-runs\实际结果目录 --review-json .\review-completed.json
```

离线复核已有结果（不调用模型）：

```powershell
& .\.venv\Scripts\python.exe -m pcap_mcp.validation --replay .\baseline-runs\实际结果目录 --verify-source
```

Python 包模块应使用 `python -m pcap_mcp.validation` 或 `python -m pcap_mcp.baseline --help`，
不要直接执行 `src\pcap_mcp\baseline.py`；直接执行会丢失包上下文，导致相对导入报错。

官方接口资料（本轮已核对）：
- https://docs.ollama.com/api/openai-compatibility
- https://docs.ollama.com/capabilities/structured-outputs
- https://www.wireshark.org/docs/man-pages/tshark.html
