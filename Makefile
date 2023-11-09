GOARCH = $(shell go env GOARCH)
OS = $(shell go env GOOS)

.DEFAULT_GOAL := all

all: fmt build start

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

.PHONY: build clean fmt start enable
