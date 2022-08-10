#   Copyright IBM Corporation 2020
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

BINNAME     ?= move2kube-api
BINDIR      := $(CURDIR)/bin
DISTDIR		:= $(CURDIR)/_dist
TARGETS     := darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64
REGISTRYNS  := quay.io/konveyor
SWAGGER_UI_VERSION := 3.52.3

GO_VERSION   ?= $(shell go run ./scripts/detectgoversion/detect.go 2>/dev/null || printf '1.18')
GOPATH        = $(shell go env GOPATH)
GOX           = $(GOPATH)/bin/gox
GOTEST        = ${GOPATH}/bin/gotest
GOLANGCILINT  = $(GOPATH)/bin/golangci-lint
GOLANGCOVER   = $(GOPATH)/bin/goveralls

PKG        := ./...
LDFLAGS    := -w -s

SRC        = $(shell find . -type f -name '*.go' -print)
ARCH       = $(shell uname -p)
GIT_COMMIT = $(shell git rev-parse HEAD)
GIT_SHA    = $(shell git rev-parse --short HEAD)
GIT_TAG    = $(shell git tag --points-at | tail -n 1)
GIT_DIRTY  = $(shell test -n "`git status --porcelain`" && echo "dirty" || echo "clean")
HAS_UPX    = $(shell command -v upx >/dev/null && echo true || echo false)

GOGET     := cd / && GO111MODULE=on go install 

MULTI_ARCH_TARGET_PLATFORMS := linux/amd64,linux/arm64

ifdef VERSION
	BINARY_VERSION = $(VERSION)
endif
BINARY_VERSION ?= ${GIT_TAG}
ifneq ($(BINARY_VERSION),)
	LDFLAGS += -X github.com/konveyor/${BINNAME}/cmd/version.version=${BINARY_VERSION}
	VERSION ?= $(BINARY_VERSION)
endif

VERSION ?= latest

VERSION_METADATA = unreleased
ifneq ($(GIT_TAG),)
	VERSION_METADATA =
endif
LDFLAGS += -X github.com/konveyor/${BINNAME}/cmd/version.buildmetadata=${VERSION_METADATA}

LDFLAGS += -X github.com/konveyor/${BINNAME}/cmd/version.gitCommit=${GIT_COMMIT}
LDFLAGS += -X github.com/konveyor/${BINNAME}/cmd/version.gitTreeState=${GIT_DIRTY}
LDFLAGS += -extldflags "-static"

# Setting container tool
DOCKER_CMD := $(shell command -v docker 2> /dev/null)
PODMAN_CMD := $(shell command -v podman 2> /dev/null)

ifdef DOCKER_CMD
	CONTAINER_TOOL = 'docker'
else ifdef PODMAN_CMD
	CONTAINER_TOOL = 'podman'
endif

# HELP
# This will output the help for each task
.PHONY: help
help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[0-9a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# -- Build --

.PHONY: build
build: get $(BINDIR)/$(BINNAME) ## Build go code
	@printf "\033[32m-------------------------------------\n BUILD SUCCESS\n-------------------------------------\033[0m\n"

$(BINDIR)/$(BINNAME): $(SRC) assets/swagger
	go build -ldflags '$(LDFLAGS)' -o $(BINDIR)/$(BINNAME) ./cmd/main
ifeq ($(HAS_UPX),true)
	@echo 'upx detected. compressing binary...'
	upx $(BINDIR)/$(BINNAME)
else
	@echo 'In order to compress the produced binaries please install upx:'
	@echo 'MacOS: brew install upx'
	@echo 'Linux: sudo apt-get install upx'
endif
	cp $(BINDIR)/$(BINNAME) $(GOPATH)/bin/

.PHONY: get
get: go.mod
	go mod download

.PHONY: generate
generate: 
	go generate ${PKG}

.PHONY: get_swagger
get_swagger:
	curl -Lo swagger-ui.tgz https://github.com/swagger-api/swagger-ui/archive/refs/tags/v$(SWAGGER_UI_VERSION).tar.gz \
    && tar -xzf swagger-ui.tgz \
    && mv swagger-ui-$(SWAGGER_UI_VERSION)/dist assets/swagger \
    && cp assets/openapi.json assets/swagger/openapi.json \
    && cp assets/index.html assets/swagger/index.html \
    && rm swagger-ui.tgz \
    && rm -rf swagger-ui-$(SWAGGER_UI_VERSION)

assets/swagger:
	make get_swagger
 
.PHONY: update_swagger
update_swagger:
	rm -rf assets/swagger
	make get_swagger

# -- Test --

.PHONY: test
test: ## Run tests
	go test -run . $(PKG) -race
	@printf "\033[32m-------------------------------------\n TESTS PASSED\n-------------------------------------\033[0m\n"

${GOTEST}:
	${GOGET} github.com/rakyll/gotest@v0.0.6

.PHONY: test-verbose
test-verbose: ${GOTEST}
	gotest -run . $(PKG) -race -v

${GOLANGCOVER}:
	${GOGET} github.com/mattn/goveralls@v0.0.11

.PHONY: test-coverage
test-coverage: ${GOLANGCOVER} ## Run tests with coverage
	go test -run . $(PKG) -coverprofile=coverage.txt -covermode=atomic

${GOLANGCILINT}:
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOPATH)/bin v1.45.2

.PHONY: test-style
test-style: ${GOLANGCILINT}
	${GOLANGCILINT} run --timeout 3m
	scripts/licensecheck.sh
	@printf "\033[32m-------------------------------------\n STYLE CHECK PASSED\n-------------------------------------\033[0m\n"

# -- CI --

.PHONY: ci
ci: clean build test test-style ## Run CI routine

# -- Release --

$(GOX):
	${GOGET} github.com/mitchellh/gox@v1.0.1

.PHONY: build-cross
build-cross: $(GOX) clean
	CGO_ENABLED=0 $(GOX) -parallel=3 -output="$(DISTDIR)/{{.OS}}-{{.Arch}}/$(BINNAME)" -osarch='$(TARGETS)' -ldflags '$(LDFLAGS)' ./cmd/main

.PHONY: dist
dist: clean build-cross ## Build Distribution
	mkdir -p $(DISTDIR)/files
	cp -r ./LICENSE $(DISTDIR)/files/
	cd $(DISTDIR) && go run ../scripts/dist/builddist.go -b $(BINNAME) -v $(VERSION)

.PHONY: clean
clean:
	rm -rf $(BINDIR) $(DISTDIR)
	go clean -cache

.PHONY: info
info: ## Get version info
	@echo "Version:           ${VERSION}"
	@echo "Git Tag:           ${GIT_TAG}"
	@echo "Git Commit:        ${GIT_COMMIT}"
	@echo "Git Tree State:    ${GIT_DIRTY}"

# -- Container Image --

.PHONY: cbuild
cbuild: ## Build container image
ifndef CONTAINER_TOOL
	$(error No container tool (docker, podman) found in your environment. Please, install one)
endif

	@echo "Building image with $(CONTAINER_TOOL)"

	DOCKER_BUILDKIT=1 ${CONTAINER_TOOL} build -t ${REGISTRYNS}/${BINNAME}-builder:${VERSION} --cache-from ${REGISTRYNS}/${BINNAME}-builder:latest --target builder                          --build-arg VERSION=${VERSION} --build-arg GO_VERSION=${GO_VERSION} .
	DOCKER_BUILDKIT=1 ${CONTAINER_TOOL} build -t ${REGISTRYNS}/${BINNAME}:${VERSION}         --cache-from ${REGISTRYNS}/${BINNAME}-builder:latest --cache-from ${REGISTRYNS}/${BINNAME}:latest --build-arg VERSION=${VERSION} --build-arg GO_VERSION=${GO_VERSION} .
	${CONTAINER_TOOL} tag ${REGISTRYNS}/${BINNAME}-builder:${VERSION} ${REGISTRYNS}/${BINNAME}-builder:latest
	${CONTAINER_TOOL} tag ${REGISTRYNS}/${BINNAME}:${VERSION} ${REGISTRYNS}/${BINNAME}:latest

.PHONY: cpush
cpush: ## Push container image
ifndef CONTAINER_TOOL
	$(error No container tool (docker, podman) found in your environment. Please, install one)
endif

	@echo "Pushing image with $(CONTAINER_TOOL)"

	# To help with reusing layers and hence speeding up build
	${CONTAINER_TOOL} push ${REGISTRYNS}/${BINNAME}-builder:${VERSION}
	${CONTAINER_TOOL} push ${REGISTRYNS}/${BINNAME}:${VERSION}

.PHONY: crun
crun: ## Run container image
ifndef CONTAINER_TOOL
	$(error No container tool (docker, podman) found in your environment. Please, install one)
endif

	@echo "Running image with $(CONTAINER_TOOL)"

ifdef DOCKER_CMD
	${CONTAINER_TOOL} run --rm -p 8080:8080 -v /var/run/docker.sock:/var/run/docker.sock -v ${PWD}/:/workspace ${REGISTRYNS}/${BINNAME}:${VERSION}
else
	${CONTAINER_TOOL} run --rm -p 8080:8080 --network=bridge ${REGISTRYNS}/${BINNAME}:${VERSION}
endif

.PHONY: cmultibuildpush
cmultibuildpush: ## Build and push multi arch container image
ifndef DOCKER_CMD
	$(error Docker wasn't detected. Please install docker and try again.)
endif
	@echo "Building image for multiple architectures with $(CONTAINER_TOOL)"

	## TODO: When docker exporter supports exporting manifest lists we can separate out this into two steps: build and push

	${CONTAINER_TOOL} buildx create --name m2k-builder-2 --driver-opt network=host --use --platform ${MULTI_ARCH_TARGET_PLATFORMS}

	${CONTAINER_TOOL} buildx build --platform ${MULTI_ARCH_TARGET_PLATFORMS} --tag ${REGISTRYNS}/${BINNAME}-builder:${VERSION} --tag ${REGISTRYNS}/${BINNAME}-builder:latest --cache-from ${REGISTRYNS}/${BINNAME}-builder:latest --target builder --build-arg VERSION=${VERSION} --build-arg GO_VERSION=${GO_VERSION} --push .;
	${CONTAINER_TOOL} buildx build --platform ${MULTI_ARCH_TARGET_PLATFORMS} --tag ${REGISTRYNS}/${BINNAME}:${VERSION} --tag ${REGISTRYNS}/${BINNAME}:latest --cache-from ${REGISTRYNS}/${BINNAME}-builder:latest --cache-from ${REGISTRYNS}/${BINNAME}:latest --build-arg VERSION=${VERSION} --build-arg GO_VERSION=${GO_VERSION} --push .;

	${CONTAINER_TOOL} buildx rm m2k-builder-2

