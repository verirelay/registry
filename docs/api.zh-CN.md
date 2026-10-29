[English](api.md) | 简体中文

# API

Registry 是 VeriRelay 的可选构建身份注册服务：根据**启动度量**查询对应的仓库、Git commit 和版本。

**签名构建记录**（Signed Build Record）简称**构建记录**（Build Record），带有 Release Key 签名。撤销声明把构建身份标记为不安全。

## 接口

| 接口 | API key | 说明 |
| --- | --- | --- |
| `GET /healthz` | 否 | 存活检查：`{"status":"ok"}` |
| `GET /readyz` | 否 | 数据库就绪检查：`{"status":"ready"}`，数据库不可用时返回 `503` |
| `GET /v1/public-key` | 否 | Release Key：`algorithm`（`ed25519`）、`key_id` 和 `public_key`（32 字节原始公钥的无 padding base64url） |
| `POST /v1/build-records` | 是 | 提交签名构建记录，返回 `201` 和存储后的构建记录 |
| `GET /v1/build-records/by-tag/{tag...}` | 否 | `git_tag` 等于 `{tag}` 的构建记录，`{tag}` 可包含 `/` |
| `GET /v1/build-records/by-measurement/{digest}` | 否 | `measurement` 等于 `{digest}` 的构建记录 |
| `POST /v1/revocations` | 是 | 提交签名的撤销声明，返回 `201` 和存储后的撤销声明 |

`by-measurement` 是精确匹配：不带前缀的 digest 不会匹配带 `sha384:` 前缀的值。

## 签名写入

写入请求带 API key（`X-API-Key` 或 `Authorization: Bearer ...`）和 Release Key 的 Ed25519 签名。请求 body 是一个 JSON 对象 `{"statement": {...}, "signature": "..."}`，最大 1 MiB。

解码是严格的。在任意层级，Registry 都拒绝：

- 未知字段
- 重复键
- 只在大小写上与字段名相同的键

### statement 字段

| 字段 | 规则 |
| --- | --- |
| `version` | 构建记录为 `verirelay-build-record/1`，撤销声明为 `verirelay-revocation/1` |
| `repository` | 带主机名的绝对 `http` 或 `https` URL，1 到 2048 字节 |
| `git_commit` | 完整 commit 哈希：40 或 64 个小写十六进制字符 |
| `git_tag` | 1 到 255 字节 |
| `measurement` | 启动度量：64、96 或 128 个小写十六进制字符，可不带前缀，也可带 `sha256:`（64）、`sha384:`（96）或 `sha512:`（128）前缀 |
| `committed_at` | 仅构建记录，必填，UTC（`Z` 后缀）的 RFC 3339 时间，精度最多到微秒 |
| `reason` | 仅撤销声明，1 到 1000 字节 |
| `revoked_at` | 仅撤销声明，必填，UTC（`Z` 后缀）的 RFC 3339 时间，精度最多到微秒 |

构建记录的身份由 `repository`、`git_commit`、`git_tag` 和 `measurement` 组成。身份不含 `committed_at`，因此同一个 tag 的每个启动度量各有一条构建记录。

撤销声明必须指向一条已存储构建记录的身份。每条构建记录只能撤销一次。

### canonical 输入

Registry 按提交的原样存储 statement，从不改写任何值。不是 canonical 形式的值返回 `400 invalid_statement`：

- 字符串字段首尾带 Unicode White_Space 字符
- `git_commit` 或 `measurement` 含大写十六进制字符，或算法前缀为大写
- 时间的时区偏移不是 `Z`，或精度超过微秒

### canonical bytes

canonical bytes 是 statement 编码成的单个 UTF-8 JSON 对象：

- 每个字段都始终出现，字段顺序如下：
  - 构建记录：`version`、`repository`、`git_commit`、`git_tag`、`measurement`、`committed_at`
  - 撤销声明：`version`、`repository`、`git_commit`、`git_tag`、`measurement`、`reason`、`revoked_at`
- token 之间没有空白。
- 字符串中的以下字符要转义。其余字符（包括 `/` 和非 ASCII 字符）按 UTF-8 原样写出。
  - `"` 和 `\` 写成 `\"` 和 `\\`
  - U+0008、U+0009、U+000A、U+000C 和 U+000D 写成 `\b`、`\t`、`\n`、`\f` 和 `\r`
  - 其他小于 U+0020 的字符写成小写十六进制的 `\u00xx`
  - `<`、`>` 和 `&` 写成 `\u003c`、`\u003e` 和 `\u0026`
  - U+2028 和 U+2029 写成 `\u2028` 和 `\u2029`
- 时间为 UTC（`Z` 后缀）的 RFC 3339。去掉小数秒末尾的 0，小数部分为 0 时不写小数。例如 `2026-08-10T12:30:00Z` 或 `2026-08-10T03:30:00.123456Z`。

例如，`git_tag` 为 `release/<test>&` 加 U+2028 再加 `end` 的构建记录，canonical bytes 如下：

```json
{"version":"verirelay-build-record/1","repository":"https://github.com/verirelay/release","git_commit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","git_tag":"release/\u003ctest\u003e\u0026\u2028end","measurement":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","committed_at":"2026-08-10T03:30:00Z"}
```

### 签名与 proof

Ed25519 签名覆盖的正是这些 canonical bytes。`signature` 是 64 字节签名的 canonical 无 padding base64url。

每条存储的构建记录和撤销声明都附带 `proof`，其中 `signed_payload` 等于返回的 `statement` 的 canonical bytes。

| 字段 | 取值 |
| --- | --- |
| `algorithm` | `ed25519` |
| `key_id` | `sha256:` 加 32 字节 Release Key 原始公钥的 SHA-256 小写十六进制 |
| `signed_payload` | canonical bytes 的无 padding base64url |
| `signature` | 签名的无 padding base64url |

## 响应

查询返回 `{"items": [...], "count": n}`，包含所有匹配的构建记录，`committed_at` 最新的在前。`count` 为条目数。

查询响应带 `Cache-Control: no-cache`，`GET /v1/public-key` 带 `Cache-Control: public, max-age=300`。

`POST /v1/build-records` 以下表的形式返回一条构建记录。

| 字段 | 说明 |
| --- | --- |
| `id` | Registry 的记录 ID |
| `statement` | 按提交原样存储的 statement |
| `proof` | 见「签名与 proof」一节 |
| `revoked` | 构建记录已撤销时为 `true` |
| `revocation` | 仅在已撤销时出现：对应的撤销声明 |
| `created_at` | Registry 存储该记录的时间，UTC 的 RFC 3339 时间 |

撤销声明包含 `id`、`statement`、`proof` 和 `created_at`。`POST /v1/revocations` 返回一条撤销声明。

## 错误

错误响应为 `{"error":{"code":"...","message":"..."}}`。

| 状态码 | `code` | 原因 |
| --- | --- | --- |
| `400` | `invalid_request` | 请求 body 不是请求格式的单个 JSON 对象，不符合严格解码规则，或超过 1 MiB |
| `400` | `invalid_statement` | statement 不符合字段规则或不是 canonical 形式，错误信息会指出字段名 |
| `400` | `invalid_tag`, `invalid_measurement` | 查询路径中的值不符合对应字段的规则 |
| `401` | `unauthorized` | 缺少 API key 或 API key 错误 |
| `403` | `invalid_signature` | `signature` 不是 canonical 的无 padding base64url，或不是 Release Key 对 canonical bytes 的有效签名 |
| `404` | `build_record_not_found` | 撤销声明指向的构建记录不存在 |
| `409` | `build_record_exists` | 已存在身份相同的构建记录 |
| `409` | `revocation_exists` | 该构建记录已被撤销 |
| `500` | `internal_error` | 服务器内部错误 |
| `503` | `not_ready` | `GET /readyz` 无法连接数据库 |
