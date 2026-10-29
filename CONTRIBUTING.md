# Contributing

## Before opening a pull request

Run the checks CI runs (`.github/workflows/ci.yml`):

```bash
go run mvdan.cc/gofumpt@v0.12.0 -l .
go vet ./...
golangci-lint run
go test ./...   # with REGISTRY_TEST_DATABASE_URL set, see docs/development.md
make build
actionlint
```

CI pins golangci-lint v2.15.0 and actionlint v1.7.12 and runs the tests against PostgreSQL 17.

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/).

## Cross-repo contracts

Some changes touch contracts shared with other repositories and need coordinated changes in every affected repo:

- The Build Record and revocation statements (`verirelay-build-record/1`, `verirelay-revocation/1`) and their canonical encoding (Release signs and posts them; Verifier checks them).
- The lookup responses and their `proof` fields (Verifier reads `by-measurement`; Release reads `/v1/public-key` and `by-tag`).

Both are defined in [docs/api.md](docs/api.md).

`internal/buildrecord/testdata/registry-vector.json` is a verbatim copy of Release's golden Build Record vector, which `TestReleaseGoldenVector` checks. Update it together with Release and Verifier.

Open the companion pull requests together and reference them from each other.

## Reporting security issues

Vulnerabilities go through private reporting; see [SECURITY.md](SECURITY.md).
