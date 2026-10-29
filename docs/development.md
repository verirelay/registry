English | [简体中文](development.zh-CN.md)

# Development

```sh
go run mvdan.cc/gofumpt@v0.12.0 -w .
go vet ./...
golangci-lint run
REGISTRY_TEST_DATABASE_URL='postgres://user:password@localhost:5432/database?sslmode=disable' go test ./...
go build ./...
```

The PostgreSQL integration tests run only when `REGISTRY_TEST_DATABASE_URL` is set, each in its own temporary schema.
