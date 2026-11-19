# Go 实例运维

本页介绍已迁移的 Go 实例。第一次在开发副本运行 PCS，请看[开发指南](development.md)。如果原先运行的是名为 `blessing-skin` 的 Go 版本，请先看[更名升级](upgrade.md)。

## 运行 Go 实例

HTTP 服务、worker 和维护命令共享同一个 `APP_LOCK_FILE`。只运行一个 HTTP 实例，并为所有进程使用同一个 deployment root 和 lock mount。这样 `migrate`、`auth-reset` 和 `migrate-mail-brand` 才能在停服期间取得 exclusive instance lock。

用 `-env` 指定 [env 文件](../configs/example.env)时，默认以该文件所在目录为 deployment root。可以用绝对路径 `APP_ROOT` 指定其他目录。只使用进程环境时，必须提供绝对路径 `APP_ROOT`。相对配置路径从 deployment root 解析，同名变量以进程环境为准。

收到中断或终止信号后，HTTP 服务开始排空请求，worker 停止领取新任务。执行 offline 命令前，等所有相关进程退出。

## Worker 与账户邮件

Worker 清理过期认证状态、回收材质文件，并在配置 SMTP 后处理账户邮件。`MAIL_MAILER` 支持 `smtp` 和空值。空值停用新邮件 challenge 的签发，也不注册邮件投递 handler。队列中一旦有到期任务找不到 handler，worker 会报错退出，任务留在 outbox 中。

使用 [`MAIL_*` 配置](../configs/example.env)设置 SMTP。`MAIL_SEND_TIMEOUT` 必须大于零且小于一分钟的任务 lease。`APP_KEY` 用于加密邮件 payload，有待投递邮件时保留原 key。

邮件按至少一次投递处理。临时 SMTP 或网络错误按 `MAIL_RETRY_DELAY` 重排。永久配置、地址或 payload 错误会将任务标为 blocked，留待人工处理。

### 重投 blocked 任务

1. 在 `go_outbox` 查找任务。诊断时查询 `id`、`topic`、`attempts`、`error_class`、`blocked_at`、`available_at` 和 `completed_at` 即可。普通日志不要记录 payload。
2. 修复问题后，按任务 ID 重投。

   ```sh
   dist/paradise-cosmetics-studio outbox-retry -id TASK_ID -env /absolute/path/site.env
   ```

重投只把外部操作送回队列。注册、积分变动和 challenge 签发都不会重做。邮件 challenge 已失效时，worker 将任务作为 obsolete 完成，不发邮件。

## 处理 outbox schema 迁移中断

首次应用 [`010_outbox_failures`](../internal/outbox/outbox.go) 时，`ALTER TABLE` 和写入 migration ledger 分开提交。如果 ALTER 已成功而 ledger 写入失败，保持停服。由维护人员对照该 migration 的 DDL 和 checksum，核对 `blocked_at`、`error_class` 和 `dispatch` index 后修复 ledger。不要直接重跑 ALTER，也不要改动既有 `005_outbox` 的 checksum。

回退 Go 版本前，确认旧版本能读取现有 schema 和 outbox payload。更名升级另有[邮件格式回退要求](upgrade.md#回退到更名前的-go-版本)。

## 从备份恢复

1. 停止 HTTP、worker 和其他写入入口。恢复并核对数据库、材质文件和任务，让它们对应同一业务恢复点。
2. 保持停服，用恢复后要运行的 Go 版本清理临时认证状态。

   ```sh
   dist/paradise-cosmetics-studio auth-reset -env /absolute/path/site.env
   ```

3. 清理成功并核对恢复结果后，再启动 HTTP 和 worker。浏览器和游戏客户端需要重新登录，OAuth 应用重新获取授权凭据，需要验证邮箱或重置密码的用户要重新申请链接。

`auth-reset` 在一个 transaction 中清理 Go 临时认证状态，保留账户、密码、UID 对应的认证版本、OAuth client、角色 UUID、业务数据、密钥、文件和 outbox。
