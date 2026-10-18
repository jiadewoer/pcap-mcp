# pcap-mcp 工程完成版 · 从这里开始

当前交付：2026-10-18。统一入口为 `pcap-final-v1\Run-PCAP.ps1`。
此版本使用独立运行源码，保留原 `src` 和全部历史实验。

## 第一次安装

将完成版ZIP解压到现有工程根目录，然后执行：

```powershell
Set-Location D:\projects\pcap-mcp
powershell -NoProfile -ExecutionPolicy Bypass -File .\pcap-final-v1\Install-Final.ps1 -Project .
```

安装会检查解析器和实际MCP注册表，并备份后更新根目录的 README.md、START-HERE.md。
安装不请求模型、不安装依赖，也不修改旧批次。

## 直接查看程序结果

现有工程的合成演示抓包可直接使用：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\pcap-final-v1\Run-PCAP.ps1 -Mode analyze -Capture .\tests\fixtures\injection_demo.pcap -Tools http -RunId demo-http-01
```

这条命令不调用Ollama。将 Capture 换成自己的文件即可。
Tools支持 `overview`、`http`、`dns`、`tls`、`tcp`、逗号分隔组合，或默认的 `all`。
该演示文件是合成测试材料，不能称为独立真实数据。

结果位于 `baseline-runs\final-demo-http-01`，主要看 REPORT.md。
旁边同名ZIP包含计划、原始工具结果、程序报告、来源复核和文件摘要。
若状态为partial_observations，表示部分调用被拒绝、报错或输出截断；脚本退出码为1，完整原因仍保存在结果目录。

## 让本机模型选择工具

先开启已有的Ollama与qwen3:8b，再执行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\pcap-final-v1\Run-PCAP.ps1 -Mode agent -Capture .\tests\fixtures\injection_demo.pcap -Goal "查看HTTP请求字段的存在性、展示值和转换来源" -RunId demo-agent-01
```

这是一次明确的新调查，最多1次模型请求、0至2次后续工具调用。
模型只看到目标和初始概览；工具执行结果由程序保存和报告，不再交给模型写正文。
结果中的观察不代表已自动判断“目标已充分回答”。

同一RunId再次执行只读取已有结果或失败记录，不会再请求模型。
要启动一项不同的新调查，请明确使用新的RunId；不要改名来重试同一失败。
模型固定为已验证的本地qwen3:8b摘要，不自动下载或切换模型。

## 只导出已有结果

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\pcap-final-v1\Run-PCAP.ps1 -Mode report -RunId demo-agent-01
```

不调用Ollama，不续跑，不改变原始响应。文件摘要不符时停止发布。

## 检查环境

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\pcap-final-v1\Run-PCAP.ps1 -Mode check
```

本检查验证当前运行源码、tshark/capinfos和实际MCP的12个工具，不检查模型服务，也不生成回答。

## 详细说明

- [工程介绍、能力与边界](pcap-final-v1/docs/PROJECT.md)
- [实验结果与结项说明](pcap-final-v1/docs/RESULTS.md)
- [MCP客户端连接](pcap-final-v1/docs/MCP.md)
- [完整历史核查](pcap-final-v1/results/project-history-review.txt)

以上相对链接以本文件安装在工程根目录为准。
