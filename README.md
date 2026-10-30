# blessing-skin-go

Blessing Skin 6.0.2 的 Go 重写工作区。目前提供认证与页面基础切片；其余业务入口仍在实施，尚未完成的入口明确返回失败。网页文字、翻译和配置沿用原站。

构建已使用 Go 1.27.3、Node.js 24.22.1、Yarn 1.22.22 验证。Makefile 固定 Go toolchain，frontend 使用 packageManager 和原 yarn.lock；不使用 PHP 生成 route、翻译或页面资源。

名称校验使用随源码固定的 native PCRE2 10.39 maintenance library。构建需要 C compiler 和 `CGO_ENABLED=1`，library 静态编入 Go binary，不依赖系统 PCRE2。Cross build 需要目标平台的 C toolchain；维护与 qualification 说明见 [internal/pcre/README.md](internal/pcre/README.md)。发行时保留 `dist/licenses/PCRE2.txt` 和 third-party notices。

```sh
make build
dist/blessing-skin version
```

将 [configs/example.env](configs/example.env) 复制到受保护的配置目录，填写已有库、APP_KEY、PWD_METHOD/SALT、原 OAuth RSA private key 和 APP_URL。只支持 MySQL/MariaDB。相对路径按声明的 env 文件目录解析；只用进程环境时必须提供绝对 APP_ROOT。不要把凭据或真实数据库内容提交到仓库。

APP_URL 是此 Go 实例的明确 canonical URL；迁移时应填写原站的有效 URL（核对 options.site_url 与原 env），不能只机械复制原 APP_URL。开发副本可显式使用本机 URL。

在准备好的开发副本停服执行 additive migration，随后分别运行 HTTP 和 worker：

```sh
dist/blessing-skin migrate -env /absolute/path/site.env
dist/blessing-skin serve -env /absolute/path/site.env
dist/blessing-skin worker -env /absolute/path/site.env
```

`migrate` 要求已有业务 schema；不会安装/重建账户、client、业务表或密钥。serve/worker 不自动执行 DDL。当前 worker 实现认证状态 cleanup 和账户邮件 outbox handler；未注册的业务 handler 会保留任务并报错，不能当作已投递成功。

账户邮件支持 SMTP 的原 MAIL_* 配置。空 MAIL_MAILER 禁用新邮件挑战；其他 mailer 会明确报不支持。APP_KEY 用于密封 outbox 邮件 payload，不能在有待投递任务时随意更换。MAIL_SEND_TIMEOUT 默认沿 go-mail 的 15s，必须小于 worker 的一分钟 lease；MAIL_RETRY_DELAY 默认保持一分钟失败重投间隔。临时 SMTP/网络错误会重排，永久配置/地址/payload 错误保留为 blocked；未知 topic 保留任务并停止 worker。SMTP 为至少一次投递。

修复 blocked 任务的原因后，按 `go_outbox.id` 重投外部副作用：

```sh
dist/blessing-skin outbox-retry -id TASK_ID -env /absolute/path/site.env
```

检查任务时只查询 id、topic、attempts、error_class、blocked_at、available_at 和 completed_at，避免将 payload 导出到普通日志。重投不重做注册、积分或 challenge 签发；已失效的邮件挑战按 obsolete 完成。

首次应用 `010_outbox_failures` 时，ALTER 和 migration ledger 各自 commit。若 ALTER 已成功而 ledger 写入失败，保持停服，先核对实际的 blocked_at/error_class columns、dispatch index 与该 migration 的 DDL/checksum，再由维护人员修复 ledger；不能直接重跑或修改既有 `005_outbox` checksum。Go rollback 前也须核对新 schema/任务 reader，不能让旧发行物接管新邮件任务。

OPTIONS_SNAPSHOT_FILE 可声明原有效 cached options 的 JSON 对象（文本键值）。有 snapshot 时它是权威来源，缺键走原 defaults，空对象也有效；不会把 DB 缺省合入 snapshot。未声明时读取 DB options。迁移时须先核对原 DB/cache 的差异，不执行 options.php。

部署使用一个 HTTP 实例与共享 instance lock 文件。HTTP、worker、offline CLI 必须使用同一 deployment root/lock mount。收到中断/终止信号后 HTTP 排空请求，worker 停止领取。

备份恢复期间保持停服，恢复 DB/文件/任务后执行：

```sh
dist/blessing-skin auth-reset -env /absolute/path/site.env
```

该命令原子清理当前 Go 临时认证状态，保留账户、密码、UID version、client、UUID、业务数据、文件和 outbox。完整恢复仍需核对业务/文件/任务恢复点。它不能替代业务数据修复，也不执行 PHP 回退。

日常 checks 使用 `make check`；设置 M2_TEST_DSN 后，数据库 checks 只接受 loopback TCP，创建/清理独立的合成数据库。未设置时会跳过 DB checks，不能把 skip 当作通过。

原 frontend、语言、图像和模板来源及 license 见 [第三方说明](THIRD_PARTY_NOTICES.md)。
