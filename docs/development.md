# 开发指南

在仓库根目录构建和运行测试。如果只想在本机跑一个有账户和材质的测试站，可以跳到[旧站迁移 fixture](../tools/legacy-fixture/README.md)。

## 构建

已验证的构建环境使用 Go 1.27.3、Node.js 24.22.1 和 Yarn 1.22.22。[Makefile](../Makefile) 固定 Go toolchain，前端通过 Corepack 使用 [package.json](../web/frontend/package.json) 指定的 Yarn 和现有 [yarn.lock](../web/frontend/yarn.lock)。路由、翻译和页面资源均在这套构建流程中生成，无需 PHP。

角色名和材质名校验使用随源码提供的 [PCRE2](../internal/pcre/README.md)。构建时启用 `CGO_ENABLED=1`，并准备目标平台的 C compiler。PCRE2 静态链接到 Go binary，无需安装系统 PCRE2。

```sh
make build
dist/paradise-cosmetics-studio version
```

分发 binary 时一并提供构建输出的 `dist/licenses/PCRE2.txt` 和 `dist/THIRD_PARTY_NOTICES.md`，以及[第三方说明](../THIRD_PARTY_NOTICES.md)列出的适用版权和许可证文本。

## 用自己的旧站副本演练

从隔离的 Blessing Skin Server 6.0.2 数据库和材质文件副本开始。PCS 使用 MySQL 或 MariaDB，材质目录使用本地文件系统。`migrate` 在已有业务 schema 上添加 Go 所需的表、字段和状态记录。它不安装空站，也不重建账户、OAuth client 或密钥。

将 [example.env](../configs/example.env) 复制到受保护的目录。对照旧站填写以下配置，确保演练使用的数据库和目录都指向副本。

- 设置数据库连接和 `DB_PREFIX`，让 `TEXTURES_DIR` 指向 deployment root 内的材质目录。
- 保留 `APP_KEY`、`PWD_METHOD` 和 `SALT`，并将 `OAUTH_PRIVATE_KEY` 指向原 OAuth RSA private key。凭据和数据副本留在 Git 之外。
- 将 `APP_URL` 设为浏览器和客户端实际访问的地址。本机演练可填本机 URL。记录原站有效地址时，核对 `options.site_url` 和旧站环境配置，不能只看原来的 `APP_URL`。
- 如果数据库还没有 `go_module_installations` 记录，通过 `MODULES_MANIFEST_FILE` 声明原站已安装的模块和版本。结构见 [fixture 的 modules.json](../tools/legacy-fixture/fixture/modules.json)，内容以实际副本为准。

如果旧站缓存中的生效配置与数据库不同，将生效配置导出为文本键值的 JSON 对象，通过 `OPTIONS_SNAPSHOT_FILE` 加载。指定 snapshot 时，PCS 在内置默认值上应用 snapshot，缺失的键不从数据库补齐，`{}` 也遵循这一规则。未指定 snapshot 时，PCS 在默认值上应用数据库 `options`。PCS 不执行旧站的 `options.php`。

停止所有会写入副本的进程，再运行迁移。有关相对路径和 instance lock 的配置，见[运行 Go 实例](operations.md#运行-go-实例)。

```sh
dist/paradise-cosmetics-studio migrate -env /absolute/path/site.env
```

迁移成功后启动 HTTP 服务，打开 `APP_URL`，用原账户和密码登录。需要处理后台任务时，在另一个终端启动 worker。两个进程使用同一份配置，启动时均不执行 DDL。

```sh
dist/paradise-cosmetics-studio serve -env /absolute/path/site.env
dist/paradise-cosmetics-studio worker -env /absolute/path/site.env
```

如果仅验证网页和 API，可设 `MAIL_MAILER=` 以停止签发新的邮件验证和重置链接。需要处理邮件任务的副本应使用隔离的 SMTP 配置。

### 生产切换的边界

生产迁移按一次停写接管设计。切换时保留原账户、密码、已验证状态、角色 UUID、业务数据、文件、应用配置和签名密钥。旧的 Session、OAuth 和 Yggdrasil 凭据以及旧邮件链接失效，用户和应用用 Go 服务重新登录或授权。

在 Go 开放真实用户写入前，可以撤回切换并恢复 PHP。Go 开始接受新写入后，故障处理走 Go 版本回退、修复或备份恢复。PHP 不接管 Go 新写入的数据。上面的演练步骤用于开发副本，生产切换仍须完成独立验收。

## 运行测试

```sh
make check
```

需要运行数据库测试时，将 `M2_TEST_DSN` 指向本地 MySQL 或 MariaDB 测试实例，使用 loopback TCP 连接。测试会创建和清理独立的合成数据库，连接账户需要相应权限。未设置 `M2_TEST_DSN` 时，依赖数据库的用例会跳过。

迁移 fixture 用来验证旧 schema 和数据迁移。它与 `make check` 创建的合成数据库各自独立。
