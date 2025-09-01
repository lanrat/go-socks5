default: test

RELEASE_DEPS=test fmt lint 
include release.mk

ALL_SOURCES := $(shell find . -type f -name '*.go')

.PHONY: fmt lint test cover coverhtml

test:
	go test -timeout=60s $(shell go list ./...) 
	@echo "< ALL TESTS PASS >"

update-deps: go.mod
	GOPROXY=direct go get -u ./...
	go mod tidy

deps: go.mod
	go mod download

fmt:
	go fmt ./...

coverage.out: $(ALL_SOURCES)
	go test -coverprofile=coverage.out $(shell go list ./...)

cover: coverage.out
	go tool cover -func=coverage.out

coverhtml: coverage.out
	go tool cover -html=coverage.out

lint:
	golangci-lint run ./...
