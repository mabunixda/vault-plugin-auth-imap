GOARCH = $(shell go env GOARCH)
OS = $(shell go env GOOS)

.DEFAULT_GOAL := all

all: fmt build

build:
	mkdir -p vault/plugins
	./scripts/localbuild.sh

start:
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=./dist/vault-plugin-auth-imap_$(OS)_$(GOARCH)/

enable:
	vault auth enable -path=imap vault-plugin-auth-imap

clean:
	rm -f ./dist/vault-plugin-auth-imap_$(OS)_$(GOARCH)/vault-plugin-auth-imap

fmt:
	go fmt $$(go list ./...)

.PHONY: build clean fmt start enable test test-cover


test:
	@go test -v -short -cover -covermode=atomic -race -timeout 120s -coverprofile=coverage.out $(shell go list ./...)

test-coverage: test
	go tool cover -html=coverage.out -o coverage.html
	go tool cover -func=coverage.out
	rm -f coverage.out

porcelain::
	gofmt -w -l $$(find . -name '*.go')
	go mod tidy
	test -z "$$(git status --porcelain)" || (git status; git diff; false)

assets::
	go generate ./...
