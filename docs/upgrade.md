# Go 版本更名升级

本页适用于从更名前的 `blessing-skin` Go 版本升级到 Paradise Cosmetics Studio。旧 PHP 站点请从[迁移演练](development.md#用自己的旧站副本演练)开始。

## 更新部署和站点定制

CLI、binary 和 Go module 现在都叫 `paradise-cosmetics-studio`。先检查部署脚本和 service 定义中是否还有旧 binary 路径，再检查调用 API 的程序及站点自己的 CSS、JavaScript 和 locale 定制。以下标识直接更换，没有旧名 alias。

| 用途 | 新标识 |
| --- | --- |
| `/api` 版本字段 | `pcs` 取代 `blessing_skin`，值为当前 build version |
| Frontend global | `window.pcs` |
| DOM ID 和头像 class | `pcs-globals`、`pcs-extra` 和 `pcs-avatar` |
| 后台状态 locale key | `admin.status.pcs.*` 取代 `admin.status.bs.*` |
| 浏览器 cookie | `pcs_session`、`pcs_remember` 和 `pcs_api` |

cookie 更名后，原 Go 站点的浏览器用户需重新登录。OAuth 和 Yggdrasil 凭据不会因更名被批量撤销。

已有账户、密码、角色 UUID、业务数据、schema 和密钥保持原样。数据库和 options snapshot 中的站名、公告、custom CSS 和 custom JS 也保留原值，由站长按需更新。新品牌用于程序的默认文案，原有图像资源保持不变。

## 转换邮件 outbox

新 runtime 只读 v2 邮件 envelope。升级前先用新 binary 转换现有 outbox，再启动服务。

1. 停止 HTTP、worker 和其他写入入口，备份数据库。保留原 `APP_KEY`、deployment root 和 lock mount。
2. 在停服期间运行转换。

   ```sh
   dist/paradise-cosmetics-studio migrate-mail-brand -env /absolute/path/site.env
   ```

3. 转换成功后，用更新过的 service 定义启动 HTTP 和 worker。

如果 payload 损坏、版本未知或 key 不匹配，整个 transaction 会回滚。保持停服，核对备份和原 key，再处理失败原因。

转换命令持有 exclusive instance lock，处理 `account.mail.v1` 下的所有 v1 envelope，包括 blocked 和 completed 记录。它用 `paradise-cosmetics-studio/account-mail/v2` 作为 HKDF info 和 AEAD associated data 重新加密 payload，保留原明文、任务 ID、operation key、topic 和投递状态。合法的 v2 记录保留原字节，因此可重复运行。

这是一次 payload 转换。它不发邮件，不签发新 challenge，也不执行 schema migration 或修改 migration checksum。

## 回退到更名前的 Go 版本

只读 v1 的旧 binary 无法读取 v2 邮件任务。回退前先核对 schema 和恢复点，再恢复与旧版本配套的备份，或修复 payload 格式后启动旧版本。若升级后已有新写入，恢复旧备份会丢失恢复点之后的数据。
