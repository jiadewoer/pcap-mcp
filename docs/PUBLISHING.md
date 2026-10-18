# 将当前项目更新到原 GitHub 仓库

此包根据本轮上传的两个 ZIP 整理。它包含可以提交的代码目录 repository/，没有本地虚拟环境、原始实验全集、真实抓包和历史结果 ZIP。
原来的 D:\projects\pcap-mcp 保留。新建 D:\projects\pcap-mcp-github 作为发布工作副本。
这是更新原仓库：通过 git clone 保留原提交历史，在新分支上覆盖选中的文件；不需要 git init，也不需要强制推送。

## 1. 先核对仓库地址

你发的地址是 https://github.com/jiadewoer/pcap-mcpmain 。
检索到的公开账号页列出 pcap-mcp；不能据此认定两个名称是同一个仓库。
在浏览器打开你要更新的仓库，点击 Code → Local → HTTPS → 复制。
下面通过 Read-Host 接收这条地址，避免把代码推到另一个项目。

## 2. 下载、解压上传包

把本次 ZIP 保存为 D:\projects\pcap-mcp-github-update-20261018.zip，打开 PowerShell 后逐段执行。
如果已有下面某个新目录，先给此次发布另取目录名，不要覆盖旧发布工作副本。

```powershell
Set-Location D:\projects
$Bundle = "D:\projects\pcap-mcp-upload-20261018"
if (Test-Path -LiteralPath $Bundle) { throw "Extraction directory exists; choose a new directory." }
Expand-Archive -LiteralPath .\pcap-mcp-github-update-20261018.zip -DestinationPath $Bundle
```

解压后应有 repository/、UPDATE-GUIDE.md、CONTENTS.json、VALIDATION.json。
只把 repository/ 的内容放进仓库，其他文件是这次更新的操作及核验材料。

## 3. 克隆原仓库并建立更新分支

```powershell
$RepoUrl = Read-Host "Paste the target repository HTTPS clone URL"
$Publish = "D:\projects\pcap-mcp-github"
if (Test-Path -LiteralPath $Publish) { throw "Publish directory exists; choose a new directory." }
git clone $RepoUrl $Publish
if ($LASTEXITCODE -ne 0) { throw "Clone failed; check repository URL and access." }
Set-Location -LiteralPath $Publish
git remote -v
$BaseBranch = git branch --show-current
Write-Host "Original default branch: $BaseBranch"
git switch -c update/current-tools-20261018
if ($LASTEXITCODE -ne 0) { throw "Could not create update branch." }
```

确认 remote 指向你要更新的原仓库。不要把旧文件夹或其他仓库的 .git 复制过来。

## 4. 放入整理后的代码

继续在同一 PowerShell 会话执行：

```powershell
Get-ChildItem -LiteralPath (Join-Path $Bundle "repository") -Force | Copy-Item -Destination $Publish -Recurse -Force
git status --short
git diff --stat
```

复制会覆盖此发布工作副本中的同名文件，不修改原开发目录；远端独有而本包没有的文件暂时保留。
目标根目录应直接看到 src/、tests/、pcap-final-v1/ 和 pyproject.toml，不能再多套一层 repository/ 或 pcap-mcp/。
Get-ChildItem 使用 -Force，因此 .gitignore、.gitattributes 和 .github 也会复制。

## 5. 安装依赖并检查新副本

```powershell
uv sync --locked --extra dev
if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed." }
& .\.venv\Scripts\python.exe -X utf8 -B -m pytest -q tests
if ($LASTEXITCODE -ne 0) { throw "Core tests failed." }
& .\.venv\Scripts\python.exe -X utf8 -B -m pytest -q .\pcap-final-v1\test_final.py
if ($LASTEXITCODE -ne 0) { throw "Daily-entry tests failed." }
powershell -NoProfile -ExecutionPolicy Bypass -File .\pcap-final-v1\Run-PCAP.ps1 -Mode check
if ($LASTEXITCODE -ne 0) { throw "Environment or source check failed." }
```

需要 tshark/capinfos 在 PATH 中。以上模型请求均为模拟，最后的 check 不联系 Ollama。
新副本有自己的 .venv，不复制旧虚拟环境。依赖锁已补齐 jsonschema 的直接依赖记录并通过 uv 离线一致性检查。
原包 src 和当前日常 runtime 保留原字节；本次没有修改抓包分析逻辑、模型提示、预算和旧分数。
在 Git 克隆的副本可直接 Run-PCAP，不需要再运行历史 Install-Final.ps1。

可以额外演示一次程序分析：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\pcap-final-v1\Run-PCAP.ps1 -Mode analyze -Capture .\tests\fixtures\injection_demo.pcap -Tools http -RunId demo-http-01
notepad .\baseline-runs\final-demo-http-01\REPORT.md
```

模型请求仍为 0。该结果只在新的发布副本产生，不改动原目录已有 demo-http-01。

## 6. 暂存并核对提交范围

```powershell
git add --all
git diff --cached --stat
git diff --cached --name-only
git ls-files -ci --exclude-standard
```

检查暂存清单中没有 .venv、baseline-runs、真实抓包、密钥、缓存或结果 ZIP。
六个明确允许的合成测试 PCAP 可以出现：injection_demo.pcap 和 tests/fixtures/field_cases/ 下五个样例。
最后一条正常应无输出；若有输出，说明旧仓库曾跟踪现在应忽略的文件。先单独检查路径。
.gitignore 只阻止未跟踪文件加入，不能自动移除旧提交中已经跟踪的文件。
确需停止跟踪某个本地结果目录时，在确认目录后用 git rm -r --cached -- 路径；它保留本地文件，但这个移除仍需要提交。
不要对整个仓库使用 git rm --cached .；本流程不需要重建全部索引。
如果旧历史已有密钥，.gitignore 和删除当前文件都不能抹掉历史中的密钥，应先撤销该密钥并单独处理历史。

## 7. 提交、推送更新分支

检查完成再执行：

```powershell
git commit -m "Update PCAP tools, evidence verification and daily entry"
if ($LASTEXITCODE -ne 0) { throw "Commit failed; inspect Git output." }
git push -u origin HEAD
if ($LASTEXITCODE -ne 0) { throw "Push failed; inspect Git authentication or remote output." }
```

Git 若要求登录，按本机 Git 凭据管理器的浏览器提示操作；不要把 token 放进仓库 URL 或源码。
如果 Git 提示未配置身份，可在此仓库内配置，不必改全局设置：

```powershell
git config user.name "你的GitHub用户名"
git config user.email "你的GitHub邮箱或GitHub提供的noreply邮箱"
```

配置后再运行上一段提交、推送命令。流程没有 --force，也没有推送覆盖默认分支。

## 8. 在 GitHub 合并

1. 打开原仓库，点击 Compare & pull request。
2. base 选第 3 步显示的原默认分支，compare 选 update/current-tools-20261018。
3. 标题：更新 PCAP 工具、证据复核与日常运行入口。
4. 说明保留模型只选工具、自动语义审阅仍待完成的限制，不写成全自动结论已验收。
5. 创建 Pull Request，检查 Files changed，等待实际 GitHub Actions 结果。
6. 检查通过后点击 Merge pull request → Confirm merge。

新 CI 覆盖 Windows 核心回归及 Linux 实际 tshark/MCP/入口回归。旧 Ruff/Mypy 检查没有在此次取得新的通过结果，README 和项目状态已明确说明。
本地验证不等于已经取得云端 Actions 通过。若云端失败，保留分支、查看日志后再修复，不要跳过失败直接合并。
合并后默认分支才正式更新。原开发目录仍保留原实验数据和预算记录；后续新功能使用常规分支继续开发。

## 上传与不上传的清单

| 当前路径 | 处理 | 原因 |
| --- | --- | --- |
| src/pcap_mcp/ | 上传源码；排除 pyc、缓存、bak | 核心包与原 CLI |
| pcap-final-v1/ | 完整上传本包内 56 个文件 | 日常入口、运行副本及其字节清单需要一起保留 |
| tests/ | 上传测试和明确允许的合成样例 | 克隆后可以运行回归 |
| scripts/ | 上传 6 个源码文件 | 客户端与样例/研究辅助脚本 |
| benchmarks/ | 上传 10 份开发基准输入 | 核心测试依赖，不是实验结果全集 |
| agent-v2/input/ | 仅上传 4 份合成输入和清单 | 当前类型/控制器测试依赖 |
| report-boundary/、validation-v3/ | 上传本包选中的兼容代码和说明 | 当前回归直接导入这些模块 |
| docs/、README.md、START-HERE.md、CHANGELOG.md、LICENSE | 上传 | 使用说明、状态和许可 |
| pyproject.toml、uv.lock | 一起上传 | 安装依赖与锁文件须一致 |
| .gitignore、.gitattributes、.github/ | 上传 | 忽略规则、字节保持和回归工作流 |
| baseline-runs/、根 verification/ | 不上传；本地保留 | 原始模型响应、输入快照、实验全集及结果 ZIP |
| upgrade-backups/、snapshot/、*.bak、*.before-final-* | 不上传；本地保留 | 历史备份 |
| .venv/、__pycache__/、.pytest_cache/、*.pyc | 不上传 | 环境和缓存由新机器生成 |
| .env、mcp-inspector.json、密钥及本机配置 | 不上传 | 含凭据或机器路径 |
| 根 injection_demo.pcap、真实业务 PCAP、公共下载样例 | 不上传 | 根演示是测试目录的重复项；真实输入与下载数据另存 |
| 各种交付 ZIP、旧安装器和中间研究目录 | 不上传；本地保留 | 不作为当前使用入口 |

例如 guarded-*、external-*、multigoal-routing-v1、parameter-paraphrase-v1、research-*、review-*、prose-study*、runtime-study 等当前不整体放入公开代码仓库。
若以后需要发布完整研究复现材料，应另选经过检查的脚本、数据许可与已整理结果，不能直接把工作目录整体上传。

进度：本次仓库更新准备以 VALIDATION.json 为准；实际推送和合并由你执行。工具工程已交付，自动结论与自动语义验收仍待完成。
