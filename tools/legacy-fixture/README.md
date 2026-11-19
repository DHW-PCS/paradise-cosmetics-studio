# 旧站迁移测试 fixture

从当前 checkout 建立一个可重复的旧站业务数据库和材质副本。用它验证 `migrate`，或迁移后测试网页、API、OAuth 和 Yggdrasil。不需要 PHP、旧站 checkout、现有数据库或生产配置。

## 1. 准备副本

需要 [PCS 构建工具](../../README.md#构建与运行)、Docker Compose v2 和 Bash。在 macOS、Linux 或启用 Docker 的 Windows WSL2 中，从仓库根目录执行：

```bash
make build
fixture="$(go run ./tools/legacy-fixture)" &&
  printf 'Fixture: %s\n' "$fixture"
```

每次准备都会建立一个新的私有临时目录，写入可导入的 `legacy.sql`、材质、模块声明和配置，并生成该副本的账户密码、邀请码、OAuth client secrets 和两套 RSA 密钥。只在本机查看 `$fixture/credentials.txt`；不要提交生成的目录。仓库中的 SQL 是模板，应导入生成的 SQL。

## 2. 导入并迁移

在同一个 Bash shell 中执行。Compose 使用独立数据卷，只在 `127.0.0.1` 上分配数据库端口。每次从初始状态测试时，先重新执行第 1 步；不要将 SQL 导入已使用的库。

```bash
dc() { docker compose -f "$fixture/compose.yaml" "$@"; }
trap 'dc down' EXIT

dc up -d --wait &&
  dc exec -T db sh -ec \
    'MYSQL_PWD="$MARIADB_PASSWORD" mariadb -u "$MARIADB_USER" "$MARIADB_DATABASE"' \
    < "$fixture/legacy.sql"
```

导入成功后，使用本次 Compose 分配的端口运行 PCS。下列函数不继承 shell 中可能存在的站点配置。

```bash
address="$(dc port db 3306)"
pcs() {
  env -i HOME="$HOME" PATH="$PATH" DB_PORT="${address##*:}" \
    ./dist/paradise-cosmetics-studio "$1" -env "$fixture/pcs.env"
}
pcs migrate
```

若要测试网页或 API，迁移成功后执行 `pcs serve`，打开 [本机测试站](http://127.0.0.1:18080)。如果端口已被占用，在生成的 `pcs.env` 中同时修改 `HTTP_ADDR` 和 `APP_URL`。此 fixture 默认禁用邮件投递。

停止 PCS 后执行 `dc down`，或退出该 shell。两种方式都清理容器和网络并保留数据卷。要继续使用已有副本，指向同一目录执行 `dc up -d --wait` 并重新读取端口；不要再次导入 SQL。

## 3. 选择测试场景

| 场景 | 入口与预期 |
| --- | --- |
| 账户和权限 | `normal@example.invalid` 是普通已验证用户；`unverified@example.invalid` 未验证；`banned@example.invalid` 已封禁；`admin@example.invalid` 和 `super@example.invalid` 分别是管理员和超级管理员。普通用户有 137 积分和一条未读通知。 |
| 材质和角色 | `NormalPlayer` 装备 Steve 皮肤和 Cape，UUID 为 `11111111111141118111111111111111`。另外两个角色具有独立 UUID。材质包括 Alex、HD、私有材质和共享 hash；`MissingFile` 故意没有对应文件。 |
| 邀请码和审核 | 登记一条已使用的邀请码、一条可注册的邀请码，以及待处理和已处理举报。可用邀请码见本地 `credentials.txt`。 |
| OAuth 和 Yggdrasil | Passport authorization code client ID 为 `1`，redirect URI 为 `http://127.0.0.1:18862/callback`；另有 personal access client。外部登录模块不配置 provider。快照保留 UUID 和 Yggdrasil 历史日志，不含旧 Session、授权码、token 或 join 状态。 |
| 旧密码格式 | 默认使用 `BCRYPT`。MD5、SHA256 和 SALTED2SHA256 账户用于验证业务行及 hash 保留；在独立副本用对应的全站 `PWD_METHOD` 测试这些账户的登录。 |

这套 fixture 用于迁移和开发者测试。它不替代 `make check` 创建的独立测试数据库，也不代表真实客户端或生产切换验收。

## 来源

SQL schema 和业务行来自一次全新初始化的 Blessing Skin Server 6.0.2。该实例使用隔离的 `bs-php` 和 MariaDB 10.11，并启用了 [固定 revision](https://github.com/bs-community/blessing-skin-plugins/tree/de016f4cbb43df7bd6d46193d5625693f8c79b3f) 的四个插件；版本见 [模块声明](fixture/modules.json)。公开版保留数据关系、ID 和 PNG 字节，用参数取代原测试凭据。Steve PNG 来自上游发行包，见[第三方说明](../../THIRD_PARTY_NOTICES.md)。
