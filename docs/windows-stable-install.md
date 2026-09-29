# Windows 本机录入：稳定安装与恢复

适用场景：用户在 Codex App 的不同聊天中，让 SecretBox 为已授权项目
录入 API Key。录入不依赖 Docker；Linux Worker 是另一个 MCP 服务。

## 一次受信安装

由用户或用户明确授权的安装维护任务执行。普通录入 Agent 不应自行
更换工作区、扩大写入权限或安装软件。先审查并检出固定 Git 修订，构建 wheel：

```powershell
python -m pip install build
python -m build --wheel
powershell -NoProfile -ExecutionPolicy Bypass -File deploy/windows/Manage-SecretBox.ps1 `
  -Mode Install -Wheel dist/openagent_secretbox-0.1.0a1-py3-none-any.whl `
  -Workspace 'E:\YourProject' -Python python
```

安装器把 wheel、独立虚拟环境、依赖版本清单和管理脚本放在
`%USERPROFILE%\.local\share\OpenAgentSecretBox`，并限制目录权限为当前用户。
该路径避开 Windows 商店应用对 AppData 的虚拟化重定向。
不使用 editable install；服务不再依赖源码目录或开发 `.venv`。
Python 使用 `-I` 隔离导入，避免聊天当前目录或 `PYTHONPATH` 中的同名模块劫持服务。
仍需保留创建环境时使用的基础 Python 安装，卸载它后需重新安装 SecretBox。
每次安装创建新版本目录，先验证实际 MCP 握手和三个工具，再更新注册。
依赖在安装时解析，已安装环境不自动更新；这不是依赖供应链的完全可复现构建。

全局 MCP 名称为 `openagent-secretbox`，只注册：

- `open_secret_intake`
- `get_secret_intake_status`
- `cancel_secret_intake`

工作区固定为安装时指定目录，目标白名单**仅 `.env.local`**；禁止覆盖。
即使从另一个项目的聊天调用，也只能写此工作区。Agent 必须先展示目标项目。
目前一份全局注册不提供自动项目切换；更换项目需用户明确授权后重新安装绑定。
不应按聊天当前目录猜测写入位置，也不能用一个全盘白名单解决多项目需求。

## 健康检查、修复、回退

安装后桌面有 `SecretBox Doctor`（检查）和 `SecretBox Repair`（修复）两个入口，
可双击运行，窗口保留检查结果；无需寻找安装目录。已有同名快捷方式不会被覆盖。

以下命令从任何目录执行，无需源码目录：

```powershell
$manager = Join-Path $env:USERPROFILE '.local\share\OpenAgentSecretBox\Manage-SecretBox.ps1'
& $manager -Mode Doctor
& $manager -Mode Repair
& $manager -Mode Rollback
```

Doctor 验证独立运行时、实际 stdio MCP 握手、三个工具和注册的完整命令及权限边界。
不会打开录入页、读取目标文件或尝试提交。Repair 只按受信安装记录修复本服务注册，
不扩大权限、不重置其他 MCP，也不能修复已经被删除的 Python 运行时。
运行时损坏应重新安装审核过的 wheel；Rollback 切回上一个健康的独立安装版本。
第一次安装没有受管理的旧版本，不能回退到旧开发环境。

每次注册前，Codex 配置会备份到受保护安装目录；其中可能含其他 MCP 的配置凭据，
不得上传到 GitHub、聊天或工单。回退只修改本 MCP 项，不整体还原旧配置。
保留旧版本以便回退，不自动清理。管理操作使用排他文件锁，避免同时升级/修复。

Codex 在建立 stdio 连接时启动服务，不需要 Windows 常驻守护进程。
主机退出、会话断开会使未完成的录入失效，这是安全边界。
健康检查成功不代表已打开聊天热加载成功；重新连接 MCP 或退出应用后新建聊天。
参见 [Codex 官方 MCP 说明](https://developers.openai.com/codex/mcp)。
没有后台监视器自动改写用户配置；配置被其他软件重置时需运行 Repair。

## 写入失败的明确提示

`apply_blocked` 下的 `env_syntax_invalid` 表示已有文件或提交的环境块不符合
支持的环境文件格式。没有值或原始解析异常返回 Agent。
由受信维护操作检查格式；不要在聊天贴文件，也不要靠关闭禁止覆盖来绕过。
现有变量值不同会报告冲突，不能据此自动覆盖。

## 用户验收清单

- [ ] 重启 Codex 后新建聊天，可发现录入、状态、取消三个工具。
- [ ] 请求录入前，确认界面显示的是获授权项目及 `.env.local`。
- [ ] Docker 不运行时，本机录入仍可用。
- [ ] 开发仓库切分支或开发虚拟环境不可用时，Doctor 仍通过。
- [ ] 录入测试在一次性测试项目执行；成功、冲突、过期均有明确状态。
- [ ] 删除测试配置里的 MCP 注册后，Doctor 报缺失，Repair 恢复且不影响其他 MCP。
- [ ] 安装两个版本后，Rollback 能恢复前一个版本并通过握手。

自动化检查不替代用户重启电脑后的实际 App 工具发现验证；不要宣称
仅完成独立 MCP 握手就已经验证所有聊天或系统重启。

### 2026-09-29 本机验证记录

- 全量 Python 测试：276 通过，4 项因 Windows 符号链接/POSIX 条件跳过。
- Ruff、Mypy、wheel 与 sdist 构建通过。
- 独立 wheel 环境真实启动 MCP，发现完整三个录入工具。
- 模拟注册缺失：Doctor 拒绝；Repair 恢复固定工作区和单目标权限。
- 两次独立安装后回退：恢复之前的安装目录，MCP 握手通过。
- 对比受保护配置快照：除本录入 MCP 项以外的持久配置完全一致。
- 隔离解释器确认模块来自独立安装环境，不来自开发仓库。
- 未重启电脑，未宣称已有聊天热加载成功；本轮未收集新密钥。
