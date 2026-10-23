VERSION ?= $(shell cat VERSION)
GO_IMAGE ?= docker.io/library/golang:1.25-bookworm
LDFLAGS := -s -w -X main.version=$(VERSION)
DOCKER_GO := docker run --rm -u $(shell id -u):$(shell id -g) \
	-v $(CURDIR):/src -w /src \
	-e GOCACHE=/src/.cache/go-build -e GOMODCACHE=/src/.cache/go-mod -e GOFLAGS=-buildvcs=false \
	-e CGO_ENABLED=0 $(GO_IMAGE)

.PHONY: build build-local build-all deb docker tidy test vet fmt clean

build:
	$(DOCKER_GO) go build -trimpath -ldflags "$(LDFLAGS)" -o dist/farol ./cmd/farol

build-local:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/farol ./cmd/farol

build-all:
	$(DOCKER_GO) sh -c 'for a in amd64 arm64; do GOARCH=$$a go build -trimpath -ldflags "$(LDFLAGS)" -o dist/farol-linux-$$a ./cmd/farol || exit 1; done'

deb: build-all
	scripts/build-deb.sh --version $(VERSION) --arch amd64
	scripts/build-deb.sh --version $(VERSION) --arch arm64

docker:
	docker build --build-arg VERSION=$(VERSION) -t ghcr.io/dgolveira/farol-guard:$(VERSION) .

tidy:
	$(DOCKER_GO) go mod tidy

test:
	$(DOCKER_GO) go test ./...

vet:
	$(DOCKER_GO) go vet ./...

fmt:
	$(DOCKER_GO) gofmt -l -w cmd internal

clean:
	rm -rf dist
