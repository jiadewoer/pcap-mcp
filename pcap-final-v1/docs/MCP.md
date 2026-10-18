# 连接MCP客户端

完成版以stdio运行，不开放HTTP服务端口。客户端启动Python进程，通过标准输入输出调用工具。
AllowedDir必须是已存在的目录，工具只允许读取该目录内符合限制的抓包。

示例配置（把目录换成你实际存放抓包的位置）：

```json
{
  "mcpServers": {
    "pcap-mcp": {
      "command": "D:\\projects\\pcap-mcp\\.venv\\Scripts\\python.exe",
      "args": [
        "-X", "utf8", "-B",
        "D:\\projects\\pcap-mcp\\pcap-final-v1\\run_project.py",
        "--mode", "serve",
        "--allowed-dir", "D:\\projects\\pcap-mcp\\captures"
      ]
    }
  }
}
```

服务本身不请求Ollama。使用外部MCP客户端时，模型请求、预算和正文发布行为由那个客户端负责；
不能把本工程agent入口的一次请求上限或报告边界自动推广到任意外部客户端。

手动启动服务会等待MCP客户端协议消息，不会弹出交互界面。
日常直接分析请用Run-PCAP.ps1的analyze模式，不需要手工输入stdio消息。

源码、依赖、tshark/capinfos状态可先用Mode check验证。
完成版不配置外部账户、不自动下载模型、不安装Wireshark或Npcap。
需要实际网卡抓包时仍使用已有Wireshark/dumpcap流程，本入口主要读取已有抓包文件。
