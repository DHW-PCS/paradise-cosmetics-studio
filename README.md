# blessing-skin-go

Blessing Skin 6.0.2 的 Go 重写工作区。目前提供认证与页面基础切片；其余业务入口仍在实施，尚未完成的入口明确返回失败。网页文字、翻译和配置沿用原站。

构建已使用 Go 1.27.3、Node.js 24.22.1、Yarn 1.22.22 验证。Makefile 固定 Go toolchain，frontend 使用 packageManager 和原 yarn.lock；不使用 PHP 生成 route、翻译或页面资源。

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

`migrate` 要求已有业务 schema；不会安装/重建账户、client、业务表或密钥。serve/worker 不自动执行 DDL。当前 worker 实现认证状态 cleanup 和 outbox 基础；未注册的业务 handler 会保留任务并报错，不能当作已投递成功。

OPTIONS_SNAPSHOT_FILE 可声明原有效 cached options 的 JSON 对象（文本键值）。有 snapshot 时它是权威来源，缺键走原 defaults，空对象也有效；不会把 DB 缺省合入 snapshot。未声明时读取 DB options。迁移时须先核对原 DB/cache 的差异，不执行 options.php。

部署使用一个 HTTP 实例与共享 instance lock 文件。HTTP、worker、offline CLI 必须使用同一 deployment root/lock mount。收到中断/终止信号后 HTTP 排空请求，worker 停止领取。

备份恢复期间保持停服，恢复 DB/文件/任务后执行：

```sh
dist/blessing-skin auth-reset -env /absolute/path/site.env
```

该命令原子清理当前 Go 临时认证状态，保留账户、密码、UID version、client、UUID、业务数据、文件和 outbox。完整恢复仍需核对业务/文件/任务恢复点。它不能替代业务数据修复，也不执行 PHP 回退。

日常 checks 使用 `make check`；设置 M2_TEST_DSN 后，数据库 checks 只接受 loopback TCP，创建/清理独立的合成数据库。未设置时会跳过 DB checks，不能把 skip 当作通过。

原 frontend、语言、图像和模板来源及 license 见 [第三方说明](THIRD_PARTY_NOTICES.md)。
