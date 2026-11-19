# Paradise Cosmetics Studio

Paradise Cosmetics Studio（PCS）是一个 Minecraft 皮肤站。玩家可以在网页上管理皮肤、披风和角色，再通过 Yggdrasil 让游戏客户端读取角色与材质。

项目从 [Blessing Skin Server 6.0.2](https://github.com/bs-community/blessing-skin-server) 改写而来。Go 程序提供网页、API 和后台任务，继续使用已有站点的账户、角色和材质数据。当前版本适合本地开发和迁移演练。真实游戏客户端兼容性、生产迁移和恢复验收仍未完成，现有 PHP 站点请继续运行原服务。

## 从哪里开始

| 你要做的事 | 文档 |
| --- | --- |
| 在本机跑一个有账户和材质的测试站 | [旧站迁移 fixture](tools/legacy-fixture/README.md) |
| 从源码构建、运行测试，或用自己的旧站副本演练 | [开发指南](docs/development.md) |
| 把更名前的 Go 版本升级到 PCS | [Go 版本更名升级](docs/upgrade.md) |
| 配置 worker、处理邮件重投或从备份恢复 | [Go 实例运维](docs/operations.md) |

## 许可证

本项目的原创内容采用 [GNU Affero General Public License v3.0](LICENSE)（`AGPL-3.0-only`）。复用的 Blessing Skin Server 内容和其他第三方材料保留各自的许可证与版权声明。来源和声明见 [Third-party notices](THIRD_PARTY_NOTICES.md)。
