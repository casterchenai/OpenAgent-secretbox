# OpenAgent SecretBox

## Windows / Codex App：稳定启用本机录入

如果你只想在聊天之外填写 API Key，使用 **`openagent-secretbox` 录入 MCP**，
不需要 Docker。`secretbox-linux-worker` 是远程任务执行服务，不能替代录入工具。

新增[独立安装、健康检查、注册修复与回退](docs/windows-stable-install.md)：
从审核过的 wheel 安装到用户专用目录，脱离开发仓库和开发虚拟环境；
按固定项目授权，仅允许 `.env.local`。服务由 Codex 按需启动。
安装后的管理入口提供 `Doctor`、`Repair`、`Rollback`，不是反复要求用户重启。

## 受限 Linux 执行 Worker

新增 **Phase 2 真实 Linux 容器执行链路**：独立凭据服务、mTLS 任务 API、
固定目标和操作白名单、持久防重放、超时、取消、重启恢复及独立恢复确认。
在本机 Docker 的隔离 PostgreSQL 中实际执行连接检查、`pg_restore` 和计数验证，
不复用现有 Supabase 容器或凭据。另提供 `secretbox-linux-worker` MCP 适配器，
不再依赖本机凭据 intake 来完成执行任务。

业务场景是让 AI 申请“使用服务端凭据执行一个批准的隔离恢复任务”，
而不是让 AI 读取密码或执行任意 SSH 命令。**当前恢复适配器只支持审核过的
合成测试备份，不等于实际 ECS/RDS 或任意业务备份已经验收。**
参见 [真实部署与可调用接口](docs/remote-worker-deployment.md)、
[可执行验收清单](docs/remote-worker-runbook.md)、
[协议](docs/remote-worker-protocol.md)、[威胁模型](docs/remote-worker-threat-model.md)、
[操作约束](docs/remote-worker-operations.md)和[凭据边界](docs/remote-worker-secrets.md)。

**让用户在 AI 聊天之外输入 API Key、环境变量和私密文件，再由 SecretBox 精准写入 Agent 所在的项目。**

Agent 只声明“需要什么、写到哪里”，用户在独立页面中填写或上传。SecretBox
按受信策略写入目标文件，Agent 只收到脱敏状态，不会收到用户提交的值或文件内容。

当前代码是 `0.1.0a1` 预发布版本，已经支持本机单次表单和远端固定 Gateway。
项目尚未经过独立安全审计，也没有可用的 PyPI 发布或 GitHub Release；请从已审查的
源码修订安装，不要把它作为生产凭据的唯一安全控制。

## 先判断你的使用场景

| 你的实际情况 | 应该使用 | 用户体验 | 网络要求 |
|---|---|---|---|
| Codex App、Claude Code App 或其他桌面 Agent 与项目在同一台电脑 | **本机模式** | Agent 知道深层目录；浏览器自动打开 `127.0.0.1` 单次表单，用户只需填写或上传 | 不开放公网端口 |
| Hermes 在阿里云等远端服务器，用户通过 Web UI、飞书或微信对话 | **固定 Gateway 模式** | 聊天只给出一个固定 HTTPS 门户；登录后选择待处理请求，文件直接写入服务器项目 | 复用现有公网 `443`；内部固定端口只监听 `127.0.0.1` |
| 平台本身提供环境变量表单和精准文件上传，例如托管沙箱 | **优先使用平台原生能力** | 由平台完成隔离和注入 | 通用托管沙箱适配是后续阶段 |
| 纯 CLI 用户愿意自己编辑文件和路径 | **通常不需要 SecretBox** | CLI 主要用于受信部署、诊断和集成，不是产品的主要交互界面 | 取决于部署方式 |

远端模式不会为每次请求新开公网端口，也不需要反复修改云安全组。每个请求只是同一
Gateway 中的一条内存记录；用户始终访问同一个门户，例如
`https://secretbox.example.com`。

## 它解决什么问题

典型任务是 Agent 需要把支付证书写入服务器上的
`config/payment/certs/apiclient_key.pem`，并把 API Key 合并到 `.env.local`。
用户不必寻找 Agent 的安装目录、SSH 编辑文件或处理权限，只需在 SecretBox 页面中：

1. 核对工作区、变量名、文件目标和 merge-only 策略。
2. 在聊天之外输入值或上传文件。
3. 提交一次；页面明确显示成功、冲突、取消、过期或已使用状态。
4. 让 Agent 根据脱敏结果继续任务。

默认写入策略：

- 环境变量只合并缺失项，不覆盖不同的已有值；
- 文件只写入受信 allowlist 内的相对路径；
- 拒绝绝对路径、`..`、符号链接、Windows reparse point 和不安全硬链接；
- 目标文件采用 POSIX `0600` 或 Windows 当前用户专用 ACL；
- 单个目标原子替换，但多个目标之间不是分布式事务；
- 默认不创建持久备份，避免复制另一份秘密。

## 安全边界

以下内容绝不能进入 Agent 聊天、模型上下文或 Agent 可见结果：

- 用户提交的值、上传文件内容及其可逆或编码版本；
- Gateway Owner Key；
- 浏览器 session ID、Cookie、CSRF token 或一次性 bearer；
- 带 intake 路径、请求 ID、查询参数或 fragment 的 URL。

远端 Agent 可以返回固定的 `portal_url`，但它只能是 HTTPS origin 根地址，例如
`https://secretbox.example.com`。它是公共入口定位符，不是授权凭据。MCP 的
`intake_id` 只是进程内轮询/取消句柄，绝不能拼进 URL 或当作浏览器凭据。

SecretBox 的核心目标是阻止秘密经过聊天传递，并减少误写。它**不能**阻止拥有同一
OS 用户无限制 shell 权限的 Agent 在写入后读取目标文件，也不能抵御主机、项目依赖
或运行时已经被攻破。需要更强隔离时，应使用独立 OS 用户、容器边界、受限运行身份
或外部 KMS/Vault。

## 从源码安装

当前没有可声明为已发布的 PyPI 包或 GitHub Release。受信管理员应先审查并固定一个
Git commit，然后在运行 Agent 的 Python 环境中安装源码：

```bash
git clone https://github.com/casterchenai/OpenAgent-secretbox.git
cd OpenAgent-secretbox
git checkout <reviewed-full-commit-sha>
python -m pip install ".[mcp]"
secretbox-mcp --help
```

开发者需要修改源码时，可以使用 editable 安装或仓库锁定环境：

```bash
python -m pip install -e ".[mcp]"
```

```bash
uv sync --extra dev
uv run pytest
```

## Hermes Agent Skill 一键安装

安装 Skill 只负责教 Hermes 正确调用已经配置好的 SecretBox MCP；它不会安装 Python
包、创建 Owner Key、选择工作区、扩大 allowlist 或开放网络端口。

当前仓库的一键 Skill 安装明确支持 Hermes。Codex App、Claude Code App 和其他 Agent
可以使用同一 MCP tools，但各客户端的自动安装与权限配置尚未作为通用安装器发布。

审查目标源码修订后，用一条命令安装完整 Hermes Skill：

```bash
hermes skills install "https://raw.githubusercontent.com/casterchenai/OpenAgent-secretbox/main/integrations/hermes/skills/openagent-secretbox/SKILL.md" --category security
```

正式部署时应把 URL 中的 `main` 替换成已审查的完整 Git commit SHA，然后执行
`/reload-skills`。本地源码树也可以作为 Hermes 的 `external_dirs`：

```yaml
skills:
  external_dirs:
    - /absolute/path/to/OpenAgent-secretbox/integrations/hermes/skills
```

完整安装、MCP 注册和兼容性说明见
[Hermes integration](./integrations/hermes/README.md)。

## 受信管理员设置

这些命令决定 SecretBox 可以写哪个工作区和哪些目标，必须由服务器或电脑的所有者
在 Agent 聊天之外执行。不要让 Agent 生成、读取或修改这些启动参数。

### 本机 App

把 MCP server 注册到本机 Agent，并由受信用户固定工作区：

```bash
secretbox-mcp --workspace /absolute/path/to/project
```

默认授权 `.env`、`.env.*` 和 `secrets/*`。只有在应用确实需要时，才在受信配置中用
重复的 `--allow-target PATTERN` 增加经过审查的目标。

本机 `open_secret_intake` 会直接打开 loopback 浏览器页面，返回
`browser_opened: true`，不会把 URL 交给 Agent。

### 远端 Hermes 固定 Gateway

先在服务器上生成 Owner Key。命令拒绝覆盖已有文件，限制为 owner-only 权限，而且
不会打印 Key：

```bash
secretbox gateway keygen --output /path/to/owner.key
```

Gateway 启动时只接受已经是 owner-only 的 Key 文件；如果权限过宽会直接拒绝启动，
不会边修复权限边继续信任一个可能已经泄露的 Key。

然后用固定工作区、HTTPS origin、loopback 地址、内部端口和 Owner Key 启动 MCP：

```bash
secretbox-mcp \
  --workspace /srv/project \
  --gateway-public-origin https://secretbox.example.com \
  --gateway-bind 127.0.0.1 \
  --gateway-port 17321 \
  --gateway-owner-key-file /path/to/owner.key
```

Gateway 是一个可同时承载多个请求的长驻监听器。它只允许绑定
`127.0.0.1`；不要改成 `0.0.0.0`，也不要在云安全组中开放 `17321`。

使用现有 Caddy 或 Nginx 在公网 `443` 终止 TLS，并只把专用域名转发到内部端口。
最小 Caddy 示例：

```caddyfile
secretbox.example.com {
    reverse_proxy 127.0.0.1:17321
}
```

反向代理必须保留配置的 Host/Origin，关闭请求正文、Cookie 和 Authorization 日志，
限制请求体并对登录入口限速。SecretBox 不自动配置 DNS、TLS、云防火墙或反向代理，
也不信任任意 `Forwarded` / `X-Forwarded-*` 头。

远端 `open_secret_intake` 返回 `browser_opened: false` 和固定 HTTPS
`portal_url`。用户用 Owner Key 登录后才能看到请求列表；未认证的链接预览不能查看
或消费请求。Owner 登录会话和待处理请求保存在内存中，Gateway 重启后失效。

## Agent 的日常行为

配置完成后，Agent 只使用三个 MCP tools：

| Tool | 作用 |
|---|---|
| `open_secret_intake` | 提交不含秘密的请求元数据并打开本机页面，或创建远端待处理请求 |
| `get_secret_intake_status` | 获取生命周期状态和脱敏写入结果 |
| `cancel_secret_intake` | 在写入开始前原子取消 |

Agent 可以声明公开名称、说明、是否必填和相对目标，但不能更改工作区、host allowlist、
Gateway origin、监听地址、端口或 Owner Key。用户也不应把任何秘密作为聊天回复发送给
Agent。

如果取消与提交并发，写入开始后会返回 `apply_in_progress`；Agent 必须继续轮询，直到
得到权威的 `applied` 或 `failed`，不能把它误报为 `cancelled`。

请求结构和返回协议见 [request schema](./docs/request-schema.md)、
[result protocol](./docs/result-protocol.md) 和
[JSON Schema](./schemas/result-v1.json)。架构决策见
[local-first ADR](./docs/decisions/ADR-001-local-first-secret-intake.md) 与
[fixed Gateway ADR](./docs/decisions/ADR-002-fixed-remote-gateway.md)。

## 用户验收清单

所有验收只使用可删除的假 Key 和测试文件，结束后清理目标内容、浏览器登录和测试请求。

### 本机 Codex / Claude App

- [ ] 让 Agent 申请一个假环境变量和假证书，不在聊天中提供值。
- [ ] 确认浏览器自动打开 `127.0.0.1` 或 `localhost`，聊天中没有 intake URL、token 或 session ID。
- [ ] 确认页面醒目说明只能提交一次，并在提交前显示准确工作区、相对目标和 merge-only 策略。
- [ ] 提交后确认页面明确显示成功且不回显值或文件内容；刷新或后退不会重复写入，并提示需向 Agent 重新申请。
- [ ] 预置一个不同值再提交同名变量，确认返回 conflict/blocked，旧值未被覆盖且没有持久备份。
- [ ] 确认 Agent 只报告名称、相对目标、动作和状态，然后删除所有测试值与文件。

### 远端 Hermes / 飞书 / 微信

- [ ] 确认公网只开放现有 HTTPS `443`，`17321` 只在服务器 `127.0.0.1` 监听。
- [ ] 连续创建两个请求，确认两次聊天只出现同一个 HTTPS portal root，没有 path、query、fragment、intake ID 或 bearer。
- [ ] 未登录或让链接预览访问门户，确认看不到请求且不会消费请求；错误 Owner Key 只显示通用错误。
- [ ] 登录后确认可以区分多个待处理请求，并在打开前看到正确标题；打开后核对服务器工作区和精确目标。
- [ ] 上传一个假文件到已授权的多层目标，确认用户无需寻找服务器路径且文件应用 owner-only 权限。
- [ ] 分别验证成功后刷新、重复打开、取消、短 TTL 过期和 Gateway 重启，页面均给出清晰状态且不会重复写入。
- [ ] 确认 Hermes、聊天、MCP 输出、代理日志和反向代理日志均不含测试值、文件正文、Owner Key 或浏览器凭据。
- [ ] 通过受信管理员路径删除测试目标，退出门户并撤销测试 Owner Key。

更完整的远端阶段用例见
[remote Gateway acceptance](./docs/acceptance/remote-gateway.md)。

## 项目状态与后续方向

当前源码已经包含：严格请求校验、merge-only writer、路径策略、本机单次 intake、MCP
集成、固定多会话 Gateway、Owner 认证和关闭字段集的脱敏结果协议。

后续方向包括托管沙箱适配、外部 KMS/Vault backend、独立 OS 身份隔离、上传类型策略、
持久化审计元数据以及独立安全审计。路线图不改变当前边界：SecretBox 负责让秘密绕开
Agent 聊天，不承诺对同用户无限制 Agent 隐藏已经写入磁盘的内容。

## Security and license

部署前请阅读 [Security Policy](./SECURITY.md) 和
[Threat Model](./docs/threat-model.md)。漏洞请使用 GitHub private security advisory，
不要在公开 issue 中提交凭据、日志、bearer URL 或截图。

License: [MIT](./LICENSE).
