# 0.7.0：证据表示、限定结论与报告可用性的对照研究

这一版直接针对 0.6.0 三组预实验：A 的零宽字符用例漏警告，B 的 20 条字段记录均匹配但解释仍混淆，C 的五次结构化输出全部格式失败。现在先完善可复查的实验机制；没有宣称已经降低真实模型的错误率，也没有宣称论文创新已经得到验证。

## 研究问题和比较范围

1. 在相同字段提取、取值和保护规则下，嵌套记录与平铺属性是否影响模型的错误解释和遗漏？
2. 采用 JSON 输出、严格属性检查与有限格式修正的报告协议，是否减少获准输出的错误字段事实，同时保持报告可用性与关键事实覆盖？
3. 成功与失败都留档后，系统的格式失败、字段不匹配和自然语言误读各占多少？

第二个问题比较的是一套限定报告协议，包括输出提示、JSON 模式、格式修正和事实检查，不把联合效果全部归因于核验器。若单独评估核验器，应固定同一份模型提出的事实，回放开关核验器后的接受/拒绝结果。新增单元测试验证了其机械边界，但不替代真实模型实验。

## 与 0.6.0 的主要差异

| 改动 | 实现位置 | 边界 |
| --- | --- | --- |
| JSON 模式＋预算内格式修正 | agent._request、_complete_report | JSON 不保证符合完整 schema，更不保证事实正确；修正后的值和引用继续严格比较 |
| 失败也保存证据 | ResearchAudit.evidence、agent._main | 每次完成工具调用即写检查点；连接前失败可能没有工具证据，不伪造 |
| 保存模型响应与格式错误 | ResearchAudit.response、format_result | 保存本地脱敏后的副本、原响应摘要及截断标记，不保证保存内容与原响应逐字节相同 |
| 同数据、不同呈现 | model_view、flatten_record | 两种表示保持字段值、列表、类型、定位、转换和取值元数据；只平铺嵌套键 |
| 事实覆盖与弃答检查 | predicate_statistics | 六个预先指定的 User-Agent 属性覆盖，不等于一般任务完整性或语义正确率 |
| 交错运行及数据一致性检查 | scripts/run_research_pilot.py | 固定随机顺序，逐用例交错三个条件；跨模型、硬件或 tshark 版本仍需另行控制 |

原有 MCP 工具数量、抓包解析后端和权限策略没有扩展。新增代码无第三方依赖。JSON 模式通过 `response_format={"type":"json_object"}` 请求；Ollama 官方兼容文档列出 JSON mode 和 response_format： https://docs.ollama.com/api/openai-compatibility 。仍以本机服务实际支持情况为准。不会在请求报错时静默换回另一协议。

## 三个新条件

| 条件 | HTTP 提取 | 模型看到的证据 | 报告协议 |
| --- | --- | --- | --- |
| flat-narrative | field：同一 PDML 取值与保护流程 | 将嵌套的 metadata 键平铺为 transformations.xxx 等 | 自然语言 |
| structured-narrative | field：同上 | 嵌套字段记录 | 自然语言 |
| structured-claims | field：同上 | 嵌套字段记录 | JSON＋限定事实检查 |

前两组控制证据内容后比较表示形式，不把这称为只改变“证据颗粒度”。两者都保留帧号与字段出现序号。旧 legacy 模式仍可运行，作为整体旧方案基线；它与 field 的区别还包括取值方式，不能纳入只比较表示形式的因果结论。

模型看到的 flat 视图不替换保存的原始受保护字段证据。平铺后的模型视图若超过原有输出/证据预算，会明确失败并保留源证据，不截去属性来制造可比性。每次调查的 audit.json 保存 canonical_payload_sha256、model_view_sha256 和表示字符数。根目录 summary.json 的 source_comparisons 检查同一用例、同一重复的三个条件是否得到相同规范化字段 payload；如果缺失或不同，这个对照不能当作内容受控的比较。

## 格式修正如何受预算约束

默认 max_format_retries=1，max_rounds=3。claims 调查会为最终输出和最多一次格式修正预留轮数。本研究脚本限定概览之后最多一次工具调用，因此通常是：第 1 轮选 HTTP；第 2 轮生成 JSON；若格式不合格，第 3 轮修正格式。

- 只修正 JSON/schema 格式。一个格式合格但值为 1、记录实际为 0 的事实，直接被 check_claims 判为不匹配，不触发格式修正。
- 超过轮数或修正次数就失败；没有生成合法报告时不写一个伪装成成功的 report.md。
- `--max-format-retries 0` 关闭修正；`--claims-response-format prompt` 显式选择只靠提示词的协议。所有设置进入实验记录；不同协议的运行不能悄悄合并。
- 计数是控制层逻辑模型请求轮数；OpenAI 客户端仍保留原有的一次传输层重试。网络失败可能增加 HTTP 尝试次数，不能将逻辑轮数当作严格网络请求数。
- 固定 temperature=0、seed=0 增强可追溯性，不保证不同后端或硬件上的完全确定性输出。

## 记录与评价

| 指标 | 分母与解释 |
| --- | --- |
| 完成率 | 成功产生报告的调查数 / 全部计划并尝试的调查数；失败不能删除 |
| 首次格式合格率 | claims 的首次待解析输出合格数 / 有首次输出的 claims 调查数；API 无输出单独记失败 |
| 修正后格式合格率 | 在固定预算内最终格式合格数 / 全部 claims 调查数 |
| 字段匹配 | 保存的字段记录与同一抓包重提取匹配；输出格式失败时仍可核验已保存证据 |
| 提出、接受和拒绝的事实数 | 限定属性检查结果；另看来源重提取后的结果，不能将 matches_record_only 当成原包核验 |
| User-Agent 属性覆盖 | 对 present、display_value、injection_kinds、控制字符移除、程序新增点、解码源已有点六个属性，计算不同已接受的 record/property 对覆盖率 |
| 无记录或空事实 | 没有记录时覆盖率为 null；有记录但无事实时为 0，均不自动算正确 |
| 自然语言错误与遗漏 | 人工检查所有 narrative，以及 claims 的未核验推测；报告级和句子级分别统计 |
| 成本 | 记录逻辑轮数、响应 usage（后端提供时）、耗时和证据表示长度；失败成本也保留 |

重复的同一事实可以计入模型提出的事实数，但不会增加覆盖率。覆盖率的分母由现有 User-Agent 字段记录和预先指定属性决定，不由模型说了多少句决定。六项覆盖仍不证明任务语义正确：例如它不能证明攻击者身份、意图、攻击成功或整个抓包完整。

人工审阅至少标记：程序新增 `·` 被归给网络对端或 tshark、U+FFFD 数被当成原始控制字符数、错误字段引用/串用取值方式、以 URI 后缀标记或请求数量证明捕获完整、无依据的意图/成功、警告与转换事实遗漏。明确标为未经验证的假设与已经声称成立的事实分开标注。

## 本机单次预实验

升级后沿用现有窗口和虚拟环境。先确认 Ollama 连接，再设置与旧实验相同的模型。下面只针对合成 fixtures：

```powershell
Set-Location D:\projects\pcap-mcp
$env:OPENAI_BASE_URL = "http://127.0.0.1:11434/v1/"
$env:OPENAI_API_KEY = "ollama"
$env:OPENAI_MODEL = "qwen3:8b"
$env:PCAP_MCP_ALLOWED_DIRS = (Resolve-Path .\tests\fixtures).Path

$tags = Invoke-RestMethod http://127.0.0.1:11434/api/tags
$selectedModel = $tags.models | Where-Object { $_.name -eq $env:OPENAI_MODEL } | Select-Object -First 1
if (-not $selectedModel) { throw "Configured model is absent from Ollama tags; keep the model fixed." }
$env:PCAP_MCP_MODEL_DIGEST = $selectedModel.digest
$env:PCAP_MCP_OLLAMA_VERSION = (ollama --version | Out-String).Trim()

$researchDir = Join-Path .\baseline-runs ("research-0.7-pilot-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
uv run --no-sync python .\scripts\run_research_pilot.py `
  --repeats 1 --max-rounds 3 --seed 0 --order-seed 2026 `
  --output-dir "$researchDir"

Get-Content (Join-Path $researchDir "summary.json") -Raw -Encoding UTF8
Compress-Archive -Path (Join-Path $researchDir "*") -DestinationPath "$researchDir.zip"
(Get-Item -LiteralPath "$researchDir.zip").FullName
```

五个用例、每个三个条件，共 15 次。protocol.json 事先保存具体顺序，summary.json 每次调查后更新；子目录包含试验参数与结果。C 格式失败时应看到 evidence.json、audit.json，若获得 HTTP 记录还应有 verification.json；这时 status 仍必须是 failed。

若服务明确不支持 JSON mode，先保留失败记录，再使用 `--claims-response-format prompt` 跑到另一个新目录。这是另一个条件，不能覆盖或混入 JSON 模式结果。不要只通过增加轮数来声称问题已解决。

先看：三组数据摘要是否相同、C 完成率是否改善、首次与修正后格式率有何差别、错误值是否被拒绝、关键事实是否被覆盖、未核验推测是否仍误读。单次试通后再以同一方案 `--repeats 3` 做 45 次；它仍只适合发现问题，不能支撑总体可靠性结论。

## 接下来怎样形成研究价值

先冻结指标、标注规则和协议，在更丰富的正常/异常用例、非 ASCII 输入、多个字段出现值和证据不足情形上验证。之后选定模型、独立人工复核样本，并把格式失败、拒绝、遗漏与解释错误同时报告。扩展场景前先确认上述最小实验可以稳定留档与核验。

论文论点不能只写“加了包号”或“加了 JSON”。更具体的问题是：安全处理和解码改变证据显示时，受控证据表示与限定结论检查能否减少错误归因，同时维持可用性与事实覆盖。是否具有足够新意，仍需文献比较、更多数据和实验支持。
