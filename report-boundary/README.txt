pcap-mcp 报告边界 v1（离线增量）

这次新增的能力
程序负责 User-Agent 每个 occurrence 的存在性、显示值、启发式匹配、解码依据、
三类转换计数与有限来源说明。模型只提供推测和限制，正文默认不进入报告。
格式正确、引用存在、字段重提取通过，都不能替代正文语义审阅。

Windows：在原项目与原 .venv 中运行
powershell -NoProfile -ExecutionPolicy Bypass -File .\report-boundary\Run-ReportBoundary.ps1

默认选择 baseline-runs 下名称最新且已有 artifact-sha256.json / summary.json 的
agent-v3-validation-* 目录，先打印选中的 Study。默认没有审阅输入，所有正文为 pending。
可以显式选择本次实机目录：
powershell -NoProfile -ExecutionPolicy Bypass -File .\report-boundary\Run-ReportBoundary.ps1 -StudyPath .\baseline-runs\agent-v3-validation-20261011-205027-6886180

带入已完成的四条拒绝审阅（保留原审阅文件，不把旧版批准自动升级）：
powershell -NoProfile -ExecutionPolicy Bypass -File .\report-boundary\Run-ReportBoundary.ps1 -StudyPath .\baseline-runs\agent-v3-validation-20261011-205027-6886180 -LegacyRejections .\report-boundary\prior-review\assistant-semantic-review.json

输出 baseline-runs\report-boundary-时间戳 目录及同名 ZIP：
- group-*\report.md：程序字段事实、有限限制、各模型正文的纳入状态。
- group-*\program-facts.json：类型经过核对的事实；无效或缺失计数不补零。
- group-*\source-check.json：已保存来源重提取凭据的覆盖、计数、capture SHA 核对。
- review-only\：原始模型回复字节副本、审阅状态，属于审阅材料。
- review-template.json：当前实现、实验、回复、请求、证据、重提取凭据的 SHA 绑定。
- publication.json：完整分母、正文纳入门槛与零新增模型调用。
- input-sha256.json / artifact-sha256.json：输入不变与新输出的字节校验。

人工审阅流程
复制本次输出 review-template.json，逐条对照 program-facts 和 review-only 的原回复。
只编辑 decision / reviewer_kind / reviewer / labels / note。声明人工审阅时填写
reviewer_kind="human"、实际审阅者和具体说明；确认通过才填写 approved，且 labels=[]。
若语义错误，填写 rejected 并给出错误标签；不能确定则保留 pending。
通过 -ReviewPath 指向填好的新审阅文件，生成新的报告目录；不会覆盖旧报告。

powershell -NoProfile -ExecutionPolicy Bypass -File .\report-boundary\Run-ReportBoundary.ps1 -StudyPath <原实验目录> -ReviewPath <填好的新审阅文件>

系统核对的是文件声明和绑定，不认证身份或独立性，不自动证明任意正文语义。
assistant 的 approved 不能让正文进入报告。旧版拒绝标为 legacy_unverified：保留拒绝，
不认证旧审阅身份。旧版 approved 一律恢复 pending，必须使用新模板逐条重新审阅。
任何正文纳入还要求已保存来源精确校验通过、User-Agent 必需字段完整、格式与引用有效、
中文正文与限制非空、该 trial 已完成。程序事实不受模型正文或审阅结论影响。

边界
本模块不连接 Ollama、不调用模型、不生成新实验、不重提取抓包，不修改 src/pcap_mcp。
保存的校验凭据来自原实验；本次不会用其他 Wireshark 版本替换原始来源元数据。
SHA 绑定检测文件变化，不是第三方签名或来源真实性认证。
当前实机只含两组合成案例、一个模型、四段正文，不能据此声称通用模型准确率或条件优劣。
这层减少未验收正文进入报告的机会，不证明模型已经变得更准确。

开发检查（现有环境）
& .\.venv\Scripts\python.exe -m pytest -q tests\test_report_boundary.py
& .\.venv\Scripts\python.exe -m pytest -q
PowerShell 包装器在 Linux 侧检查了语法树，尚未在 Windows 上实际执行。
