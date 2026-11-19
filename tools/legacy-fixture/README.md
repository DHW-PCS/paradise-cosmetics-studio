# 旧站迁移 fixture

用这套 fixture 可以在本机启动一个带账户、角色和材质的 PCS 测试站。数据库从 Blessing Skin Server 6.0.2 的 schema 起步，导入后先运行 `migrate`，再测试网页、API 或协议入口。准备副本时无需运行 PHP，也无需手头有一个旧站。

## 1. 生成测试副本

准备[构建工具](../../docs/development.md#构建)、Docker Compose v2 和 Bash。可在 macOS、Linux 或启用 Docker 的 Windows WSL2 中运行。接下来的命令都从仓库根目录在同一个 Bash shell 执行。

```bash
make build && fixture="$(go run ./tools/legacy-fixture)" &&
  printf 'Fixture: %s\n' "$fixture"
```

生成工具会打印一个新的私有临时目录。目录内的 `legacy.sql` 已填入本次生成的密码 hash、邀请记录、OAuth client secret 和 Yggdrasil key，应导入这份 SQL。仓库中的 SQL 是供生成工具使用的模板。

测试账户共用的密码、可用邀请码和 OAuth code client secret 在 `$fixture/credentials.txt` 中。目录里还有数据库口令和签名密钥，整个目录留在本机。

## 2. 导入旧库并迁移

只向新副本的空数据库导入 SQL。Compose 为每个副本创建独立数据卷，并将数据库端口绑定在 `127.0.0.1` 上。

```bash
dc() { docker compose -f "$fixture/compose.yaml" "$@"; }
trap 'dc down' EXIT

dc up -d --wait &&
  dc exec -T db sh -ec \
    'MYSQL_PWD="$MARIADB_PASSWORD" mariadb -u "$MARIADB_USER" "$MARIADB_DATABASE"' \
    < "$fixture/legacy.sql"
```

等导入成功，再读取 Compose 分配的端口并运行迁移。`pcs` 函数为服务单独传入这次的配置和端口，避免当前 shell 中的站点环境变量覆盖它们。

```bash
address="$(dc port db 3306)"
pcs() {
  env -i HOME="$HOME" PATH="$PATH" DB_PORT="${address##*:}" \
    ./dist/paradise-cosmetics-studio "$1" -env "$fixture/pcs.env"
}
pcs migrate
```

## 3. 打开测试站

迁移成功后运行 `pcs serve`，打开[本机测试站](http://127.0.0.1:18080)。如果端口被占用，在生成的 `pcs.env` 中同时修改 `HTTP_ADDR` 和 `APP_URL`。测试站默认关闭邮件。

| 想验证什么 | 从哪里开始 |
| --- | --- |
| 账户和权限 | 用 `normal@example.invalid` 登录。这个已验证的普通账户有 137 积分和一条未读通知。`unverified@example.invalid` 未验证，`banned@example.invalid` 已封禁。`admin@example.invalid` 和 `super@example.invalid` 分别是管理员和超级管理员。 |
| 角色和材质 | `NormalPlayer` 装备 Steve 皮肤和披风，UUID 是 `11111111111141118111111111111111`。另外两个角色有各自的 UUID。材质库有 Alex、HD、私有材质和共享 hash，`MissingFile` 对应的文件特意留空。 |
| 邀请码和举报 | 试用 `credentials.txt` 中的可用邀请码，也可在后台查看一条已用邀请码，以及待处理和已处理举报。 |
| OAuth 和 Yggdrasil | Passport authorization code client ID 是 `1`，redirect URI 是 `http://127.0.0.1:18862/callback`。库中还有 personal access client，外部登录模块没有配置 provider。快照保留角色 UUID 和 Yggdrasil 历史日志，登录、授权和 join 流程从新状态开始。 |
| 旧密码格式 | 默认用 `BCRYPT` 登录。快照也留有 MD5、SHA256 和 SALTED2SHA256 的账户及 hash。要测这些账户的登录，请为各算法单独准备一个副本，再设置对应的全站 `PWD_METHOD`。 |

## 停止和继续

停止 `pcs serve` 后运行 `dc down`，或退出执行上述命令的 Bash shell。两种方式都移除容器和网络，保留数据卷。

继续使用已有副本时，将 `fixture` 指向原目录。如果换了 shell，重做第 2 步中的函数和退出清理设置。运行 `dc up -d --wait` 后重新读取端口，再用 `pcs serve` 启动，跳过 SQL 导入。要从未迁移的状态重新测试，请从第 1 步新建副本。

## 数据来源

SQL schema 和业务行来自用 `bs-php` 和 MariaDB 10.11 新建的隔离 Blessing Skin Server 6.0.2 实例。实例启用了[固定 revision 的四个插件](https://github.com/bs-community/blessing-skin-plugins/tree/de016f4cbb43df7bd6d46193d5625693f8c79b3f)，版本见[模块声明](fixture/modules.json)。公开模板保留数据关系、ID 和 PNG 字节，凭据由每次运行生成。Steve PNG 来自上游发行包，见[第三方说明](../../THIRD_PARTY_NOTICES.md)。
