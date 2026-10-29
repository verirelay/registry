[English](deployment.md) | 简体中文

# 部署

Registry 以容器镜像 `ghcr.io/verirelay/registry`（由 `docker-compose.yaml` 运行）和 `dist/verirelay-registry` 二进制（`make build`）两种形式提供，数据存放在 PostgreSQL。

Registry 启动时自动建表。没有需要执行的迁移。服务不持有私钥。

## 配置

配置来自环境变量。模板为 `.env.example`，Compose 读取 `.env`。

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `HTTP_ADDR` | `:8080` | HTTP 监听地址 |
| `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PWD` | 必填 | PostgreSQL 连接参数 |
| `DB_SSLMODE` | `verify-full` | PostgreSQL `sslmode`：`disable`、`allow`、`prefer`、`require`、`verify-ca` 或 `verify-full` |
| `DB_MAX_CONNS` | `32` | 最大数据库连接数，2 到 1000 |
| `API_PWD_HASH` | 必填 | API key 的 bcrypt 哈希，建议 cost 10 |
| `RELEASE_PUBLIC_KEY` | 必填 | Release Key 公钥：32 字节 Ed25519 原始公钥的无 padding base64url |

PostgreSQL 的 CA 不在系统根证书中时，用 `PGSSLROOTCERT` 指定其文件。

## Docker Compose

`docker-compose.yaml` 让镜像 `ghcr.io/verirelay/registry:v0.1.0` 和 `postgres` 服务（PostgreSQL 17，数据在命名 volume 中）一起运行。它设置 `HTTP_ADDR=:8080`、`DB_HOST=postgres` 和 `DB_SSLMODE=disable`，并在宿主机端口 `HTTP_PORT`（默认 `8080`）上发布 API。

```bash
docker compose up -d
```

生产环境按 digest 固定镜像：`image: ghcr.io/verirelay/registry@sha256:...`。每个 release 都列出 digest 和验证其 cosign 签名的方法。

`.env` 中的 bcrypt 哈希要用单引号括起来（`API_PWD_HASH='$2a$10$...'`）。不加引号时 Compose 会展开其中的每个 `$`，哈希随之损坏。

以下变量未设置时的默认值：

| 变量 | 默认值 |
| --- | --- |
| `DB_NAME` | `verirelay` |
| `DB_USER` | `verirelay` |
| `DB_PORT` | `5432` |
| `DB_PWD` | `local-development-only` |

本地开发以外的部署请在 `.env` 中设置 `DB_PWD`。
