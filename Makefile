VERSION ?= $(shell cat VERSION)
GO_IMAGE ?= docker.io/library/golang:1.26-bookworm
LDFLAGS := -s -w -X main.version=$(VERSION)
DOCKER_GO := docker run --rm -u $(shell id -u):$(shell id -g) \
	-v $(CURDIR):/src -w /src \
	-e GOCACHE=/src/.cache/go-build -e GOMODCACHE=/src/.cache/go-mod -e GOFLAGS=-buildvcs=false \
	-e CGO_ENABLED=0 $(GO_IMAGE)

NFPM_IMAGE ?= docker.io/goreleaser/nfpm:v2.47.0
GOTOOLCHAIN ?= auto
PREFIX ?= /usr/local
DESTDIR ?=

.PHONY: build build-local build-all deb rpm archpkg packages install uninstall docker tidy test vet fmt clean

build:
	$(DOCKER_GO) go build -trimpath -ldflags "$(LDFLAGS)" -o dist/farol ./cmd/farol

build-local:
	GOTOOLCHAIN=$(GOTOOLCHAIN) CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/farol ./cmd/farol

build-all:
	$(DOCKER_GO) sh -c 'for a in amd64 arm64; do GOARCH=$$a go build -trimpath -ldflags "$(LDFLAGS)" -o dist/farol-linux-$$a ./cmd/farol || exit 1; done'

deb: build-all
	scripts/build-deb.sh --version $(VERSION) --arch amd64
	scripts/build-deb.sh --version $(VERSION) --arch arm64

rpm: build-all
	for a in amd64 arm64; do \
		install -Dm755 dist/farol-linux-$$a dist/nfpm/farol && \
		docker run --rm -u $(shell id -u):$(shell id -g) -v $(CURDIR):/src -w /src \
			-e FAROL_ARCH=$$a -e FAROL_VERSION=$(VERSION) $(NFPM_IMAGE) \
			package -f packaging/nfpm/nfpm.yaml -p rpm -t dist/ || exit 1; \
	done
	rm -rf dist/nfpm

archpkg: build-all
	for a in amd64 arm64; do \
		install -Dm755 dist/farol-linux-$$a dist/nfpm/farol && \
		docker run --rm -u $(shell id -u):$(shell id -g) -v $(CURDIR):/src -w /src \
			-e FAROL_ARCH=$$a -e FAROL_VERSION=$(VERSION) $(NFPM_IMAGE) \
			package -f packaging/nfpm/nfpm.yaml -p archlinux -t dist/ || exit 1; \
	done
	rm -rf dist/nfpm

packages: deb rpm archpkg

install:
	install -Dm755 dist/farol $(DESTDIR)$(PREFIX)/bin/farol
	install -Dm644 packaging/deb/farol-guard.desktop $(DESTDIR)$(PREFIX)/share/applications/farol-guard.desktop
	install -Dm644 internal/server/web/icon.svg $(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps/farol-guard.svg
	install -d $(DESTDIR)$(PREFIX)/lib/systemd/user
	for u in farol-guard-ui.service farol-guard-check.service farol-guard-check.timer; do \
		sed 's|/usr/bin/farol|$(PREFIX)/bin/farol|g' packaging/systemd/$$u > $(DESTDIR)$(PREFIX)/lib/systemd/user/$$u || exit 1; \
	done

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/farol $(DESTDIR)$(PREFIX)/share/applications/farol-guard.desktop \
		$(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps/farol-guard.svg
	for u in farol-guard-ui.service farol-guard-check.service farol-guard-check.timer; do \
		rm -f $(DESTDIR)$(PREFIX)/lib/systemd/user/$$u; \
	done

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
