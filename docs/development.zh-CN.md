[English](development.md) | 简体中文

# 开发

```sh
go run mvdan.cc/gofumpt@v0.12.0 -w .
go vet ./...
golangci-lint run
REGISTRY_TEST_DATABASE_URL='postgres://user:password@localhost:5432/database?sslmode=disable' go test ./...
go build ./...
```

PostgreSQL 集成测试仅在设置 `REGISTRY_TEST_DATABASE_URL` 时运行，每个测试使用独立的临时 schema。
