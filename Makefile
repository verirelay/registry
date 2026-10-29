.PHONY: build test lint check clean

DIST_DIR := dist
REGISTRY := $(DIST_DIR)/verirelay-registry

build:
	mkdir -p $(DIST_DIR)
	go build -o $(REGISTRY) ./cmd/registry

test:
	go test ./...

lint:
	golangci-lint run

check: test build lint

clean:
	rm -rf $(DIST_DIR)
