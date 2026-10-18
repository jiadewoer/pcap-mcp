# 0.8.0：安全处理之后的证据来源归因

这一版把“工具记录能核验，但模型解释仍错误”变成可被反例推翻的问题。实验代码已经实现，真实模型的结论尚未产生。

## 可检验的主张

在相同显示文本下，模型能否依据来源元数据区分程序新增的分隔点、解码源已有的点，以及程序记录的控制字符移除？当来源计数缺失时，是否承认未知？限定来源核验能否减少获准输出的错误归因，同时保留足够覆盖？

若模型只根据文本外观猜测，配对两侧可能给出相同答案而失败。若核验器只删除所有内容，错误数可能变成零，但覆盖和配对完整正确率也应归零。若字段核验已经足够，新增来源核验的收益应很小。这些结果都允许出现，不预先保证新方法优胜。

## 与相关研究的关系

| 研究 | 已有基础 | 本轮采用的边界 |
| --- | --- | --- |
| [FActScore，EMNLP 2023](https://aclanthology.org/2023.emnlp-main.741/) | 将生成内容分解成原子事实，衡量知识来源支持程度 | 不把“拆成事实”当成本项目的新贡献；此处只检查限定工具属性 |
| [Context-faithful Prompting，Findings 2023](https://aclanthology.org/2023.findings-emnlp.968/) | 研究知识冲突、反事实示例和弃答条件下的上下文忠实性 | 不把“反事实测试”本身当成新贡献；此处针对安全处理的来源元数据 |
| [AgentDojo，NeurIPS 2024](https://proceedings.neurips.cc/paper_files/paper/2024/hash/97091a5177d8dc64b1da8bf3e1f6fb54-Abstract-Datasets_and_Benchmarks_Track.html) | 评估处理不可信工具数据的 Agent、提示注入攻击与防御 | 本回放没有工具行动，也没有攻击者任务成功判定，不能报告可比的攻击成功率 |

潜在贡献是领域问题、可审计干预及失败分类的组合：解码和安全处理改变证据显示后，字段事实正确为何仍不保证来源解释正确。是否足以形成论文贡献，需要更完整文献审查、更多独立实例和真实模型数据。

## 配对基准

种子来自你已提供的 0.6.0 B 组字段证据。保存每份上游 evidence/verification 文件摘要、抓包摘要和旧核验结果。它们说明历史来源，不表示本轮重新运行了 tshark。模型只看 User-Agent 记录；不接收答案表、用例族标签或两侧的答案。

`seed-gold.json` 是显式声明的独立答案表，不由 `check_claims` 或 `lineage_value` 自动生成。建立套件时先比较种子字段与答案表，再冻结干预及摘要。字段复制和两类标签仍是程序可解的限定问题；不是任意自然语言事实核验。

| 配对 | 保持不变 | 实际变化 | 预期 |
| --- | --- | --- | --- |
| control-removal | 两侧最终显示文本 | 使用真实 plain/unicode 种子；移除计数 0→1，上游替换 0→3，启发式类别也变化 | 点来源保持 analysis_program；移除观察 no→yes；不能把上游 3 当移除 3 |
| reference-relabel | 字段属性与解释 | 合成引用重编号 F4→F104，并同步定位字段 | 值保持不变，引用必须更新 |
| record-order | 两条记录及其引用 | 合成记录数组反序 | 不能把不同记录的值串用 |
| upstream-decoder | 显示文本、源已有点和程序新增点计数 | 合成上游 tshark 替换计数 2→0 | 点来源仍为 decoded_source，不受替换计数影响 |
| missing-lineage | 显示文本和其他字段 | 合成删除三个来源计数 | 相关字段事实不应编造为零；两种来源标签均应为 unknown |

每对两侧的显示文本都相同。control-removal 改变多个实际元数据，不能将它的效果单独归因于一个计数。后三类合成操作以及引用重编号并非新 PCAP；包中和请求中都明确标为回放。生产解析和 MCP 工具接口没有新增这些合成行为。

两种呈现采用同一记录内容：structured 保留嵌套，flat 平铺键。每次请求使用独立消息上下文，不把配对另一侧的回答交给模型。默认五对、十个用例、两种呈现，共 20 次请求。

## 固定输出的核验消融

每个条件只让模型提出一次 JSON。解析合格后，保存提议摘要；以下三个策略离线处理同一份提议，完全不重生成模型回答：

| 策略 | 字段事实 | 限定来源标签 |
| --- | --- | --- |
| off | 全部保留，标为未核验 | 全部保留，标为未核验 |
| field | 使用现有字段属性比较器 | 全部保留，标为未核验 |
| field-and-lineage | 同上；不可用属性拒绝 | 用可用的非负整数转换计数推导限定标签，匹配才接受 |

`middle_dot_origin` 只分类已记录的程序新增/解码源已有点计数：analysis_program、decoded_source、both、none、unknown。它不证明网络字节编码，也不对每一个最终显示字符建立位置级来源证明。

`control_removal_observed` 是 yes/no/unknown。no 只表示记录的移除计数为零，不能证明原始网络中没有不可见字符。缺失、负数、字符串、浮点数或布尔型计数都不能当作已知整数计数。

两个限定标签之外的身份、恶意意图、攻击成功、服务器安全策略等推测继续不受语义核验。实验中的来源核验器也不证明输入记录真实；独立负对照测试已展示，记录被篡改时“匹配记录”仍可能接受错误值。

## 评价不能只看剩余错误数

`summary.json` 和 `report.md` 分别保存完整数据与便于审阅的汇总。

- **配对完整正确率**：两侧在字段事实和限定来源标签上均覆盖所需属性、无错误、无未支持项，才算该配对成功。分母是所有计划配对，包括 API、格式失败和中断后尚未尝试的条件。
- **错误与未支持输出**：有定义但值错误，与未知引用/不支持属性/缺失属性分开计数；不把二者都称为一般语义错误。
- **覆盖**：正确且无矛盾的不同 record/property 对数，除以全部计划条件的所需属性对数。重复事实不增加覆盖；同一属性相互矛盾的输出不能贡献覆盖。
- **接受输出的支持比例**：独立答案表支持的输出数/接受输出数；没有输出时是 null，而非 100%。同时报告覆盖，避免“全部拒绝所以正确”的结论。
- **首次格式与 API 失败**：每条件一个逻辑请求，零格式修正；CLI 客户端关闭传输重试。API 没返回内容与格式不合格分开保留，不能删除失败。
- **纯程序基线**：直接读取可用字段，并计算限定标签，不读取答案表、不调用模型。结果保存在 deterministic-baseline.json。它不生成自由解释，也不能和自由报告质量直接等同。

只有五种人工策划的模板。重复次数、事实条数和两侧记录不能充当独立总体样本；本版不给总体置信区间或显著性结论。真实模型数据前不会宣称降低了错误率。

## 输出结构

`protocol.json` 在首个模型请求前保存完整随机顺序、套件摘要、温度、seed、模型名和所声明的运行环境。每次调查保存 request.json、响应脱敏副本及原响应摘要、proposal.json、trial.json。

API 失败时没有响应文件，但已保存请求和失败类型；格式失败时保留响应、不伪造提议。响应文本最多保存 50,000 字符，带截断标记。脱敏可能改变存储副本；离线回放会检查提议摘要，若不同便拒绝称其为原输出回放。摘要防止意外修改和串用，不是数字签名或真实来源认证。

## 本机运行

先完成 START_HERE.md 中的原地升级和完整检查。无模型、无 tshark 的套件检查：

```powershell
$buildDir = Join-Path .\baseline-runs ("lineage-build-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
uv run --no-sync python .\scripts\run_lineage_study.py --build-only --output-dir "$buildDir"
```

应显示 5 pairs、10 cases。随后在现有窗口固定 Ollama 模型并记录摘要：

```powershell
$env:OPENAI_BASE_URL = "http://127.0.0.1:11434/v1/"
$env:OPENAI_API_KEY = "ollama"
$env:OPENAI_MODEL = "qwen3:8b"
$tags = Invoke-RestMethod http://127.0.0.1:11434/api/tags
$selectedModel = $tags.models | Where-Object { $_.name -eq $env:OPENAI_MODEL } | Select-Object -First 1
if (-not $selectedModel) { throw "Configured model is absent; keep the model fixed." }
$env:PCAP_MCP_MODEL_DIGEST = $selectedModel.digest
$env:PCAP_MCP_OLLAMA_VERSION = (ollama --version | Out-String).Trim()

$lineageDir = Join-Path .\baseline-runs ("lineage-pilot-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
uv run --no-sync python .\scripts\run_lineage_study.py `
  --repeats 1 --seed 0 --order-seed 2026 --output-dir "$lineageDir"

Get-Content (Join-Path $lineageDir "report.md") -Raw -Encoding UTF8
uv run --no-sync python .\scripts\run_lineage_study.py `
  --analyze "$lineageDir" --analysis-output (Join-Path $lineageDir "replayed-summary.json")

Compress-Archive -Path (Join-Path $lineageDir "*") -DestinationPath "$lineageDir.zip"
(Get-Item -LiteralPath "$lineageDir.zip").FullName
```

回放应不联系模型，结果应与原 summary 的评价相同。这个实验没有运行真实抓包工具，因此不要求 PCAP_MCP_ALLOWED_DIRS；实际 Agent 研究仍要按 0.7 文档配置抓包权限。

若服务不支持 JSON mode，保留当前失败，再用 `--response-format prompt` 到另一个新目录运行。不得静默切换协议或合并两种结果。

## 怎样进一步提高研究价值

先看三个策略是否出现可解释差异，以及错误数下降是否伴随覆盖损失。再人工审阅所有 hypotheses/limitations，检查模型是否把未核验推测写得像已成立事实。用不同模型时每个模型另建完整目录，保留相同冻结套件；不要只挑表现最好的 seed。

下一阶段应引入独立来源、更多变换类型和未见的字段/模板；由另一人复核答案表，并将开发和最终评价按源抓包或模板族分组隔离。随后在真实 Agent 端到端运行中检查方法能否迁移。闭合标签的小回放只适合检验机制与发现反例，不能独立支撑整体可靠性或安全性论文。
