# reporting-acceptance-v1：整批研究验收

本扩展基于用户提供的当前项目，保留 pcap-mcp 核心版本 0.8.0。旧 type/runtime 实验锁定这个版本及评分代码字节；因此不修改 `claims.py`、`lineage.py`、`research.py` 和两套旧实验脚本。新报告与新实验各自保存版本和代码哈希。

## 本批交付

1. Agent 增加 `--report-format program --program-json ...`。程序枚举完整工具记录中的已定义字段，保留原生布尔、整数、数组和字符串；从有效计数推导两类有限来源标签。缺失、负数、浮点、字符串和布尔计数都不能当成已记录的零。非法字段在 `unavailable` 中保留原因。
2. 模型仍负责工具选择和推测/限制正文。正文仅允许 `{schema_version,hypotheses,limitations}`；禁止模型写入程序事实。无格式修复或事实修复；正文失败单独保留，程序事实可以存在，但不能据此宣称完整模型输出成功。正文的依据引用也会检查是否存在。
3. 开发阶段是固定 native-types 提示的 2×2 对照：原始、可用性提醒、完整性提醒、两者都有。表示、证据、模型采样、reasoning 请求和超时保持一致。
4. 留出阶段比较原始提示、开发阶段选定提示和 program 模式。开发结果按预先写入的规则选择；禁止从留出结果选提示。留出集有新的复合信号、单侧缺失、非法类型、多 occurrence、混合可用性和编码/归因边界。
5. 实际 Agent 阶段通过真实 MCP stdio 调用和原 PCAP 重提取，比较 claims/program 输出架构。两者最终协议不同，这是架构对照。原始字段 fixture 的五个 PCAP 已包含在扩展中。
6. 所有阶段保留计划分母、失败标签、原始响应的本地存储信息、固定请求、代码/输入哈希和离线重算入口。不会覆盖已有尝试；中断后的目录保留为未完成试验，重新运行须创建新目录。

## 先在原目录应用

解压升级 ZIP 到 `D:\projects\pcap-mcp`。文件会放进 `reporting-update`，尚未改动项目源文件。

```powershell
Set-Location D:\projects\pcap-mcp
Expand-Archive .\pcap-mcp-reporting-acceptance-v1.zip -DestinationPath . -Force
powershell -NoProfile -ExecutionPolicy Bypass -File .\reporting-update\Run-Acceptance.ps1 -Offline
```

升级器先验证所有旧文件哈希和 payload 哈希，再备份和应用。任一冲突会在写入前退出；写入异常会回滚本次已写文件。原 `.venv`、`.git`、`.env` 和 baseline-runs 不属于覆盖清单。`uv sync` 在同一个原目录更新现有环境，不创建替代项目目录。升级器接受 Windows CRLF 文本，也支持重复执行。

`-Offline` 会完成升级、原测试、旧 type/runtime 测试和两套程序事实基线。它不调用模型。若检查通过，删除 `-Offline` 即可一次执行完整开发→选型→留出→Agent→重算→打包。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\reporting-update\Run-Acceptance.ps1
```

脚本默认使用已安装的 `qwen3:8b` 和本机 Ollama，不下载模型。保持 Ollama 的上下文与 token 配置不变。模型身份/服务版本会在批次前后读取并比对。另一个已安装模型可通过同一 PowerShell 会话调用：

```powershell
& .\reporting-update\Run-Acceptance.ps1 -Models @("qwen3:8b", "你已安装的第二个模型名称")
```

脚本运行期间会临时设置模型环境变量，结束后恢复先前值。若测试、模型身份核对或固定输出重算出错，脚本停止并保留已创建文件。模型超时和格式失败作为试验结果保留，不会补跑；它们未必让批次命令退出为错误。必须检查生成的 report.md 和 trial.json。

## 预算和输出

默认单模型、每用例一次：

| 阶段 | 计划 | 模型请求预算 |
| --- | --- | --- |
| 开发 | 10 用例 × 2 表示 × 4 提示 | 80 次 |
| 留出 | 12 用例 × 2 表示 × 3 方法 | 72 次 |
| 实际 Agent | 5 抓包 × 2 架构 | 10 次调查、最多 30 次模型请求 |
| 合计 | 三阶段 | 最多 182 次模型请求 |

两个模型、各一次时，上述预算加倍。`-Repeats` 按比例扩展，不产生更多独立用例。程序基线、prepare、check、select 和 replay 都不调用模型。

输出位于新的 `baseline-runs/reporting-acceptance-时间戳`。其中有 offline 检查、development、selection.json、heldout、agent、model-identities.json 和对应 summary/report；自动生成同名 ZIP。

新 trial 的 `request.json` 保存发送体，SDK 的 `extra_body` 只用于传输 `reasoning_effort=none`。客户端重试为零；每逻辑尝试一次请求，无格式修复、类型转换或补跑。`none` 不保证服务内部没有额外计算；响应若仍给 reasoning，会记录其字符数。未显式固定服务器上下文/token 上限；客户端超时不保证服务器已取消请求。

## 分阶段命令

```powershell
# 无模型验收
uv run --no-sync python -m pcap_mcp.reporting_study --check

# 仅冻结开发计划，不调用 API；实际运行前设置 OPENAI_API_KEY/BASE_URL
uv run --no-sync python -m pcap_mcp.reporting_study --prepare --phase development --models qwen3:8b --output-dir .\baseline-runs\reporting-dev
uv run --no-sync python -m pcap_mcp.reporting_study --run .\baseline-runs\reporting-dev

# 留出选择只依赖已完成全部尝试的开发集
uv run --no-sync python -m pcap_mcp.reporting_study --prepare --phase heldout --development-study .\baseline-runs\reporting-dev --models qwen3:8b --output-dir .\baseline-runs\reporting-heldout
uv run --no-sync python -m pcap_mcp.reporting_study --run .\baseline-runs\reporting-heldout

# 实际 Agent：冻结、运行、固定输出重算
uv run --no-sync python -m pcap_mcp.reporting_study --prepare-agent .\benchmarks\field_cases.json --models qwen3:8b --output-dir .\baseline-runs\reporting-agent
uv run --no-sync python -m pcap_mcp.reporting_study --run-agent .\baseline-runs\reporting-agent
uv run --no-sync python -m pcap_mcp.reporting_study --replay-agent .\baseline-runs\reporting-agent --analysis-output .\baseline-runs\reporting-agent\replayed-summary.json
```

研究记录重算使用 `--replay 目录 --analysis-output 新文件`，不新生成模型文本。Agent 重算默认核对固定证据、报告、audit、重提取结果哈希，并再次程序检查字段；增加 `--reextract` 才重新读取原 PCAP 和调用 tshark。此路径不覆盖旧 verification.json。

## 结果能支持的结论

程序基线评价的是“给定完整字段记录，能否完整复制有效属性并按计数规则推导标签”。高分不能推导模型更聪明、报告解释正确、整包调查完整、攻击成功或原字符编码正确。

留出答案是手工声明的工具记录和来源枚举，没有调用被测评分器生成 lineage gold。字段事实的真值限定为声明的记录叶子。留出集是新的复合/边界家族，沿用部分基础计数机制；它不是外部收集的盲测抓包，不能把它写成跨数据集泛化证据。开发、留出、真实 Agent 的指标分别报告。

三个 gate 仍对同一个固定 proposal 进行核验，不重新询问模型。`program` 的字段覆盖在正文/API 失败时可以保留；完整用例列必须同时要求正文结构有效和封闭问题完整正确。推测正文没有经过语义判定，需要另行人工审阅。

旧复测只说明当前 qwen/Ollama/预算组合中 none 的合法输出更稳定；不能据此宣布所有模型中 none 最优。新增批次是在此前诊断基础上冻结机制修正与架构对照，还需要用户本机真实结果来完成经验验证。

## 面试/报告可使用的表述

“我实现了一个受预算约束的 PCAP MCP Agent。发现模型会把展示层中点、原数据中点和上游解码替换混为一谈后，增加了字段来源与转换计数，并用同一输出比较三种核验策略。复测显示单纯过滤错误提议不能填补遗漏，也不能稳定处理缺失 metadata，所以我进一步把封闭字段事实和有限归因交给程序生成，让模型承担工具选择和明确标注的推测，并保留开发选型、留出验证和实际 Agent 的完整失败分母。”

新增本机实验未完成前，用“实现了评测流程”描述留出和实际 Agent 工作；取得真实输出后再补具体结果。不得把模拟 SDK 测试或程序基线成绩当成模型实验成绩。
