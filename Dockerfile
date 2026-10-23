FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26-bookworm AS build
ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/farol ./cmd/farol \
 && mkdir -p /out/home/.ssh

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/farol /usr/bin/farol
COPY --from=build --chmod=0755 /out/home /home/farol
ENV HOME=/home/farol \
    XDG_CONFIG_HOME=/config \
    FAROL_GUARD_DATA=/data \
    XDG_CACHE_HOME=/data/cache \
    FAROL_GUARD_KNOWN_HOSTS=/config/known_hosts
VOLUME ["/config", "/data"]
EXPOSE 7380
ENTRYPOINT ["/usr/bin/farol"]
CMD ["ui", "--no-open", "--listen", "0.0.0.0:7380"]
