# Paradise Cosmetics Studio

基于 Blessing Skin Server 6.0.2 的 Go 重写项目，提供 Minecraft cosmetics hosting。业务、协议与迁移工作仍按阶段验收，尚未完成的入口明确返回失败。

构建已使用 Go 1.27.3、Node.js 24.22.1、Yarn 1.22.22 验证。Makefile 固定 Go toolchain，frontend 使用 packageManager 和原 yarn.lock；不使用 PHP 生成 route、翻译或页面资源。

名称校验使用随源码固定的 native PCRE2 10.39 maintenance library。构建需要 C compiler 和 `CGO_ENABLED=1`，library 静态编入 Go binary，不依赖系统 PCRE2。Cross build 需要目标平台的 C toolchain；维护与 qualification 说明见 [internal/pcre/README.md](internal/pcre/README.md)。发行时保留 `dist/licenses/PCRE2.txt` 和 third-party notices。

```sh
make build
dist/paradise-cosmetics-studio version
```

将 [configs/example.env](configs/example.env) 复制到受保护的配置目录，填写已有库、APP_KEY、PWD_METHOD/SALT、原 OAuth RSA private key 和 APP_URL。只支持 MySQL/MariaDB。相对路径按声明的 env 文件目录解析；只用进程环境时必须提供绝对 APP_ROOT。不要把凭据或真实数据库内容提交到仓库。

APP_URL 是此 Go 实例的明确 canonical URL；迁移时应填写原站的有效 URL（核对 options.site_url 与原 env），不能只机械复制原 APP_URL。开发副本可显式使用本机 URL。

在准备好的开发副本停服执行 additive migration，随后分别运行 HTTP 和 worker：

```sh
dist/paradise-cosmetics-studio migrate -env /absolute/path/site.env
dist/paradise-cosmetics-studio serve -env /absolute/path/site.env
dist/paradise-cosmetics-studio worker -env /absolute/path/site.env
```

`migrate` 要求已有业务 schema；不会安装/重建账户、client、业务表或密钥。serve/worker 不自动执行 DDL。当前 worker 实现认证状态 cleanup 和账户邮件 outbox handler；未注册的业务 handler 会保留任务并报错，不能当作已投递成功。

账户邮件支持 SMTP 的原 MAIL_* 配置。空 MAIL_MAILER 禁用新邮件挑战；其他 mailer 会明确报不支持。APP_KEY 用于密封 outbox 邮件 payload，不能在有待投递任务时随意更换。MAIL_SEND_TIMEOUT 默认沿 go-mail 的 15s，必须小于 worker 的一分钟 lease；MAIL_RETRY_DELAY 默认保持一分钟失败重投间隔。临时 SMTP/网络错误会重排，永久配置/地址/payload 错误保留为 blocked；未知 topic 保留任务并停止 worker。SMTP 为至少一次投递。

修复 blocked 任务的原因后，按 `go_outbox.id` 重投外部副作用：

```sh
dist/paradise-cosmetics-studio outbox-retry -id TASK_ID -env /absolute/path/site.env
```

检查任务时只查询 id、topic、attempts、error_class、blocked_at、available_at 和 completed_at，避免将 payload 导出到普通日志。重投不重做注册、积分或 challenge 签发；已失效的邮件挑战按 obsolete 完成。

首次应用 `010_outbox_failures` 时，ALTER 和 migration ledger 各自 commit。若 ALTER 已成功而 ledger 写入失败，保持停服，先核对实际的 blocked_at/error_class columns、dispatch index 与该 migration 的 DDL/checksum，再由维护人员修复 ledger；不能直接重跑或修改既有 `005_outbox` checksum。Go rollback 前也须核对新 schema/任务 reader，不能让旧发行物接管新邮件任务。

OPTIONS_SNAPSHOT_FILE 可声明原有效 cached options 的 JSON 对象（文本键值）。有 snapshot 时它是权威来源，缺键走原 defaults，空对象也有效；不会把 DB 缺省合入 snapshot。未声明时读取 DB options。迁移时须先核对原 DB/cache 的差异，不执行 options.php。

部署使用一个 HTTP 实例与共享 instance lock 文件。HTTP、worker、offline CLI 必须使用同一 deployment root/lock mount。收到中断/终止信号后 HTTP 排空请求，worker 停止领取。

备份恢复期间保持停服，恢复 DB/文件/任务后执行：

```sh
dist/paradise-cosmetics-studio auth-reset -env /absolute/path/site.env
```

该命令原子清理当前 Go 临时认证状态，保留账户、密码、UID version、client、UUID、业务数据、文件和 outbox。完整恢复仍需核对业务/文件/任务恢复点。它不能替代业务数据修复，也不执行 PHP 回退。

日常 checks 使用 `make check`；设置 M2_TEST_DSN 后，数据库 checks 只接受 loopback TCP，创建/清理独立的合成数据库。未设置时会跳过 DB checks，不能把 skip 当作通过。

原 frontend、语言、图像和模板来源及 license 见 [第三方说明](THIRD_PARTY_NOTICES.md)。

## 更名后的升级

CLI 与 binary 使用 `paradise-cosmetics-studio`；部署脚本和 service 定义应更新原 `blessing-skin` 路径。Go module 使用 `paradise-cosmetics-studio`。

`/api` 的品牌字段改为 `pcs`，值为当前 build version，删除 `blessing_skin`。Frontend global 改为 `window.pcs`，DOM IDs 使用 `pcs-globals`、`pcs-extra`，头像 class 使用 `pcs-avatar`；custom CSS/JS 应同步更新。Locale key `admin.status.bs.*` 改为 `admin.status.pcs.*`。旧标识不提供 alias。

浏览器 cookie 改为 `pcs_session`、`pcs_remember`、`pcs_api`，已有 Go 浏览器登录需要重新认证。更名不批量撤销 OAuth/Yggdrasil 凭据，不修改 schema、账户、密码、角色 UUID、业务数据或密钥。

已有数据库和 options snapshot 中的站名、announcement、custom CSS/JS 保持原值；站主管理更新。代码默认品牌为 Paradise Cosmetics Studio。上游来源、License、第三方 package 名和 legacy fixtures 保留原名；现有图像资源未重设计。

### 邮件 payload format 升级

已有 Go 部署升级前，停止 HTTP、worker 和其他写入入口，备份 DB，并保持原 `APP_KEY`、deployment root 与 lock mount。使用新 binary 显式转换邮件 outbox：

```sh
dist/paradise-cosmetics-studio migrate-mail-brand -env /absolute/path/site.env
```

该 offline 命令持有 exclusive instance lock，将 `account.mail.v1` topic 下所有 v1 envelope 转为 v2，包括 blocked/completed 记录。v2 使用 `paradise-cosmetics-studio/account-mail/v2` 作为 HKDF info 和 AEAD associated data；topic 保持不变。转换只更新加密 payload，保留任务 ID、operation key、投递/lease/blocked 状态及明文内容，不发送邮件或创建新 challenge。已是合法 v2 的记录保持原字节，重复运行安全。

任一 payload 损坏、版本未知或 key 不匹配时，整个 transaction 回滚；保持停服，核对备份和原 key 后再处理。新 runtime 只读 v2，不自动转换旧格式；成功转换后再启动服务。回退到只读 v1 的旧 Go binary 时必须恢复配套备份或另行修复，不能让旧 reader 直接接管 v2 outbox。此命令不执行 schema migration 或修改现有 migration checksum。
