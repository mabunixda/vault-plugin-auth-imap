#!/usr/bin/env bash

set -xeo pipefail

for cmd in "date" "git" "go" "goreleaser" "yq"; do
    if ! command -v ${cmd} >/dev/null ; then
        echo "Please verify that ${cmd} is installed!"
        exit 1
    fi
done

GITHUB_SHA=$(git log --format="%H" -n 1)
GOVERSION=$(go version)
GIT_DIRTY=$(test -n "`git status --porcelain`" && echo "dirty" || echo "clean")

export GITHUB_SHA GOVERSION GIT_DIRTY

goreleaser build --snapshot --clean --single-target $@
