English | [简体中文](deployment.zh-CN.md)

# Deployment

Registry ships as the container image `ghcr.io/verirelay/registry`, run by `docker-compose.yaml`, and as the `dist/verirelay-registry` binary (`make build`). It is backed by PostgreSQL.

Registry creates its tables on startup. There are no migrations to run. It holds no private key.

## Configuration

Registry reads its configuration from environment variables. `.env.example` is the template, and Compose reads `.env`.

| Variable | Default | Description |
| --- | --- | --- |
| `HTTP_ADDR` | `:8080` | HTTP listen address. |
| `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PWD` | required | PostgreSQL connection. |
| `DB_SSLMODE` | `verify-full` | PostgreSQL `sslmode`: `disable`, `allow`, `prefer`, `require`, `verify-ca`, or `verify-full`. |
| `DB_MAX_CONNS` | `32` | Maximum database connections, 2 to 1000. |
| `API_PWD_HASH` | required | bcrypt hash of the API key; cost 10 is recommended. |
| `RELEASE_PUBLIC_KEY` | required | The Release Key public key: unpadded base64url of the raw 32-byte Ed25519 key. |

For a PostgreSQL CA outside the system roots, set `PGSSLROOTCERT` to its file.

## Docker Compose

`docker-compose.yaml` runs the image `ghcr.io/verirelay/registry:v0.1.0` next to a `postgres` service (PostgreSQL 17, data in a named volume). It sets `HTTP_ADDR=:8080`, `DB_HOST=postgres`, and `DB_SSLMODE=disable`. It publishes the API on host port `HTTP_PORT` (default `8080`).

```bash
docker compose up -d
```

In production, pin the image by digest: `image: ghcr.io/verirelay/registry@sha256:...`. Each release lists the digest and how to verify its cosign signature.

In `.env`, put the bcrypt hash in single quotes (`API_PWD_HASH='$2a$10$...'`). Unquoted, Compose expands every `$` and the hash breaks.

When unset, these variables default to:

| Variable | Default |
| --- | --- |
| `DB_NAME` | `verirelay` |
| `DB_USER` | `verirelay` |
| `DB_PORT` | `5432` |
| `DB_PWD` | `local-development-only` |

Set `DB_PWD` in `.env` for anything but local development.
