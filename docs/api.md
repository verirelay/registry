English | [简体中文](api.zh-CN.md)

# API

Registry is VeriRelay's optional build identity registry: it maps a **Launch Measurement** to its repository, Git commit, and version.

A **Signed Build Record** (short: **Build Record**) carries the Release Key signature. A revocation marks a build identity as unsafe.

## Endpoints

| Endpoint | API key | Description |
| --- | --- | --- |
| `GET /healthz` | no | Liveness: `{"status":"ok"}`. |
| `GET /readyz` | no | Database readiness: `{"status":"ready"}`, or `503` when the database is unavailable. |
| `GET /v1/public-key` | no | The Release Key: `algorithm` (`ed25519`), `key_id`, and `public_key` (the raw 32-byte key as unpadded base64url). |
| `POST /v1/build-records` | yes | Submit a Signed Build Record. Returns `201` and the stored Build Record. |
| `GET /v1/build-records/by-tag/{tag...}` | no | Build Records whose `git_tag` is `{tag}`, which may contain `/`. |
| `GET /v1/build-records/by-measurement/{digest}` | no | Build Records whose `measurement` is `{digest}`. |
| `POST /v1/revocations` | yes | Submit a signed revocation. Returns `201` and the stored revocation. |

`by-measurement` matching is exact: a bare digest does not match a `sha384:`-prefixed one.

## Signed writes

Writes carry an API key (`X-API-Key` or `Authorization: Bearer ...`) and an Ed25519 signature by the Release Key. A request body is one JSON object `{"statement": {...}, "signature": "..."}` of at most 1 MiB.

Decoding is strict. At every depth, Registry rejects:

- unknown fields;
- duplicate keys;
- keys that match a field name only case-insensitively.

### Statement fields

| Field | Rule |
| --- | --- |
| `version` | `verirelay-build-record/1` for a Build Record, `verirelay-revocation/1` for a revocation. |
| `repository` | Absolute `http` or `https` URL with a host, 1 to 2048 bytes. |
| `git_commit` | Full commit hash: 40 or 64 lowercase hex characters. |
| `git_tag` | 1 to 255 bytes. |
| `measurement` | The Launch Measurement: 64, 96, or 128 lowercase hex characters, bare or prefixed with `sha256:` (64), `sha384:` (96), or `sha512:` (128). |
| `committed_at` | Build Record only. Required RFC 3339 timestamp in UTC with a `Z` suffix and at most microsecond precision. |
| `reason` | Revocation only. 1 to 1000 bytes. |
| `revoked_at` | Revocation only. Required RFC 3339 timestamp in UTC with a `Z` suffix and at most microsecond precision. |

A Build Record's identity is its `repository`, `git_commit`, `git_tag`, and `measurement`, so a tag has one Build Record per Launch Measurement.

A revocation must name the identity of a stored Build Record. Each Build Record can be revoked once.

### Canonical input

Registry stores a statement exactly as submitted. A value that is not canonical returns `400 invalid_statement`:

- a string field with leading or trailing Unicode White_Space;
- uppercase hex in `git_commit` or `measurement`, or an uppercase algorithm prefix;
- a timestamp with a UTC offset other than `Z`, or with sub-microsecond digits.

### Canonical bytes

The canonical bytes are the statement as one UTF-8 JSON object:

- Every field is always present, and fields appear in this order:
  - Build Record: `version`, `repository`, `git_commit`, `git_tag`, `measurement`, `committed_at`.
  - Revocation: `version`, `repository`, `git_commit`, `git_tag`, `measurement`, `reason`, `revoked_at`.
- There is no whitespace between tokens.
- Strings escape the characters below. Every other character, including `/` and non-ASCII, is literal UTF-8.
  - `"` and `\` as `\"` and `\\`;
  - U+0008, U+0009, U+000A, U+000C, and U+000D as `\b`, `\t`, `\n`, `\f`, and `\r`;
  - other characters below U+0020 as `\u00xx` with lowercase hex;
  - `<`, `>`, and `&` as `\u003c`, `\u003e`, and `\u0026`;
  - U+2028 and U+2029 as `\u2028` and `\u2029`.
- Timestamps are RFC 3339 in UTC with a `Z` suffix. Trailing zeros of the fractional seconds are dropped, and there is no fraction when it is zero. Examples: `2026-08-10T12:30:00Z`, `2026-08-10T03:30:00.123456Z`.

For example, a Build Record with `git_tag` `release/<test>&` followed by U+2028 and `end` has these canonical bytes:

```json
{"version":"verirelay-build-record/1","repository":"https://github.com/verirelay/release","git_commit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","git_tag":"release/\u003ctest\u003e\u0026\u2028end","measurement":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","committed_at":"2026-08-10T03:30:00Z"}
```

### Signature and proof

The Ed25519 signature covers exactly the canonical bytes. `signature` is the 64-byte signature as canonical unpadded base64url.

Every stored Build Record and revocation carries a `proof`. Its `signed_payload` equals the canonical bytes of the returned `statement`.

| Field | Value |
| --- | --- |
| `algorithm` | `ed25519` |
| `key_id` | `sha256:` followed by the lowercase hex SHA-256 of the raw 32-byte Release Key public key. |
| `signed_payload` | The canonical bytes as unpadded base64url. |
| `signature` | The signature as unpadded base64url. |

## Responses

Lookups return `{"items": [...], "count": n}` with every matching Build Record, newest `committed_at` first. `count` is the number of items.

Lookups send `Cache-Control: no-cache`, and `GET /v1/public-key` sends `Cache-Control: public, max-age=300`.

`POST /v1/build-records` returns one Build Record in the form below.

| Field | Description |
| --- | --- |
| `id` | Registry's record ID. |
| `statement` | The statement as submitted. |
| `proof` | The proof described under Signature and proof. |
| `revoked` | `true` when the Build Record is revoked. |
| `revocation` | Only when revoked: the revocation. |
| `created_at` | When Registry stored the record, as an RFC 3339 timestamp in UTC. |

A revocation has `id`, `statement`, `proof`, and `created_at`. `POST /v1/revocations` returns one revocation.

## Errors

Errors return `{"error":{"code":"...","message":"..."}}`.

| Status | `code` | Cause |
| --- | --- | --- |
| `400` | `invalid_request` | The body is not one JSON object of the request form, breaks the strict decoding rules, or exceeds 1 MiB. |
| `400` | `invalid_statement` | The statement breaks a field rule or is not canonical; the message names the field. |
| `400` | `invalid_tag`, `invalid_measurement` | A lookup path value breaks its field rule. |
| `401` | `unauthorized` | The API key is missing or wrong. |
| `403` | `invalid_signature` | `signature` is not canonical unpadded base64url, or not a valid Release Key signature over the canonical bytes. |
| `404` | `build_record_not_found` | The revocation names no stored Build Record. |
| `409` | `build_record_exists` | A Build Record with the same identity exists. |
| `409` | `revocation_exists` | The Build Record is already revoked. |
| `500` | `internal_error` | Unexpected server error. |
| `503` | `not_ready` | `GET /readyz` cannot reach the database. |
