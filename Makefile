GOARCH = $(shell go env GOARCH)
OS = $(shell go env GOOS)

IMAGE_NAME=$(shell yq e '.project_name' .goreleaser.yaml)
TAG_NAME := $(shell test -d .git && git describe --abbrev=0 --tags)
SHA := $(shell test -d .git && git rev-parse --short HEAD)
COMMIT := $(SHA)
# hide commit for releases
VERSION := $(TAG_NAME)
ifneq ($(RELEASE),1)
	VERSION := $(TAG_NAME)-$(SHA)
endif
BUILD_DATE := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
BUILD_TAGS := -tags=release
GOVERSION=$(shell go version | sed 's/.*go\(.*\) .*/\1/')
GIT_DIRTY=$(shell test -n "`git status --porcelain`" && echo "dirty" || echo "clean")
LD_FLAGS := -s -w -X "github.com/mabunixda/imap/version.Version=$( VERSION )" \
      -X "github.com/mabunixda/imap/version.BuildDate=$( BUILD_DATE )" \
      -X "github.com/mabunixda/imap/version.GoVersion=$(GOVERSION)" \
      -X "github.com/mabunixda/imap/version.GitCommit=$( COMMIT )" \
      -X "github.com/mabunixda/imap/version.GitDirty=$( GIT_DIRTY )"
BUILD_ARGS := -o $(IMAGE_NAME) -trimpath -ldflags='$(LD_FLAGS)'

.DEFAULT_GOAL := all
.PHONY: build clean fmt start enable test test-cover

all: build

ldflags:
	@echo $(LD_FLAGS)

prepare: clean fmt
	@echo "Preparing build with:"
	@echo "  VERSION:     $(VERSION)"
	@echo "  COMMIT:      $(COMMIT)"
	@echo "  BUILD_DATE:  $(BUILD_DATE)"
	@echo "  GOVERSION:   $(GOVERSION)"
	@echo "  GIT_DIRTY:   $(GIT_DIRTY)"
	@echo "  LD_FLAGS:    $(LD_FLAGS)"
	mkdir -p vault/plugins

build: snapshot

snapshot: prepare
	@LD_FLAGS='$(LD_FLAGS)' goreleaser build --snapshot --single-target

release: prepare
	@LD_FLAGS='$(LD_FLAGS)' RELEASE=1 goreleaser release

start: build
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=./dist/vault-plugin-auth-imap_$(OS)_$(GOARCH)_v8.0/

enable:
	vault auth enable -path=imap vault-plugin-auth-imap

clean:
	rm -rf ./dist/

fmt:
	go fmt $$(go list ./...)

test:
	@go test -v -short -cover -covermode=atomic -race -timeout 120s -coverprofile=coverage.out ./...

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
