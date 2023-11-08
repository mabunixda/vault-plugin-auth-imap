#!/usr/bin/env bash

set -eo pipefail

for cmd in "date" "git" "go" "goreleaser" "yq"; do
    if ! command -v ${cmd} >/dev/null ; then
        echo "Please verify that ${cmd} is installed!"
        exit 1
    fi
done

GITHUB_SHA=$(git log --format="%H" -n 1)
BUILD_DATE=$(date +'%Y-%m-%d %H:%M:%S')
GOVERSION=$(go version)
VERSION="$(git describe --tags 2>/dev/null || echo "0.0.0" )-local)"
GIT_DIRTY=$(test -n "`git status --porcelain`" && echo "dirty" || echo "clean")

export GITHUB_SHA BUILD_DATE GOVERSION VERSION IMAGE_NAME GIT_DIRTY

goreleaser build --snapshot --clean --single-target
