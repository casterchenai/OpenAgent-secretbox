# Worker 验收与后续部署

## Phase 2 真实 Linux 验收

当前已增加真实 Linux 容器实现，部署和调用方式见
[remote-worker-deployment.md](remote-worker-deployment.md)。以下命令会实际连接
隔离 PostgreSQL、执行恢复、暂停测试数据库、强制终止 Worker 并检查恢复状态：

```powershell
.\.venv\Scripts\python.exe .github/scripts/accept_linux_worker.py
.\.venv\Scripts\python.exe .github/scripts/smoke_worker_mcp.py
```

- [ ] mTLS 拒绝未带客户端证书的请求，Agent 不能调用 owner 确认接口。
- [ ] 执行真实连接检查，只收到 connected/version，不收到凭据或连接串。
- [ ] 经确认恢复 1 张合成表、2 行测试数据、1 个主键约束。
- [ ] 重复恢复被目标非空检查拒绝，重复确认和重复请求被拒绝。
- [ ] 超时、取消及强制终止后，无 PostgreSQL 子进程或匿名 pgpass fd 遗留。
- [ ] 数据库暂停时任务有界失败，过期排队任务不会执行。
- [ ] 重启保留终态与防重放记录，未完成任务标记失败而不自动重试。
- [ ] 凭据提供方断开时失败关闭，生成的密码与私钥未出现在服务日志。
- [ ] 独立 MCP 的 create/status/cancel 能实际完成一个数据库连接任务。

自动化测试结束会清理合成表，保留运行中的任务接口、测试凭据和审计元数据，
供用户继续验证。完整实验环境的销毁命令及影响见部署文档。
这不是生产数据库验收，也没有在真实云 ECS/RDS 上执行。

## 历史：Phase 1 Mock 验收

### Mock 能做什么

业务场景：你让 AI 申请“把审核过的备份恢复到隔离测试库”。本阶段先验证
AI 不能换服务器、加 shell 命令、重复执行或跳过确认。不会连接 ECS/RDS，
不会读取现有密码，也不会宣称数据库已经恢复。

## 本机可执行验收

在仓库根目录运行：

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_remote_worker.py -v
```

- [ ] 成功模拟依次经过 created、validated、queued、running、succeeded。
- [ ] 修改 target/operation/parameters 后旧签名失效。
- [ ] 未知目标、生产目标、host、command 等字段被拒绝。
- [ ] 同一个任务重复及并发投递仅能执行一次。
- [ ] 排队过期、运行超时、确认过期均不能成功执行。
- [ ] 恢复模拟停在 awaiting_confirmation，错误或重复确认被拒绝。
- [ ] stdout/stderr 中的假密码、连接串、私钥片段和业务行都不返回。
- [ ] 崩溃、验证失败、清理失败不会显示成功。
- [ ] 取消后不会晚到一个成功结果。
- [ ] 全量测试仍通过，原 SecretBox intake 功能不受影响。

这些是自动化模拟验收，不替代真实 Linux 故障演练。模拟不创建测试凭据文件，
不需要清理数据库。pytest 缓存和构建产物属于普通开发文件。

## 下一阶段进入条件

管理员提供专用测试 ECS、独立 Linux 用户和非生产数据库/模拟服务；
确认网络白名单、凭据提供方及服务证书的管理方式。Agent 不读取凭据。
先实现 mTLS、持久任务/重放账本、独立 watchdog、子进程组清理和重启恢复，
再运行凭据不落盘、输出不泄露、断网/崩溃清理演练。

Phase 3 才接隔离 RDS，先小备份，再审核过的正式隔离备份。
Phase 4 生产迁移单独审批，不能复用隔离恢复入口。
未通过独立安全评审、发布包检查和回滚演练前，不发布真实执行能力。
