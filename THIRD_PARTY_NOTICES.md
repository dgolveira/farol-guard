# Third-party notices

farol-guard is distributed under the MIT License. It includes the following
third-party Go modules, each under its own license:

| Module | Version | License |
| --- | --- | --- |
| golang.org/x/crypto | v0.43.0 | BSD-3-Clause |
| golang.org/x/sys | v0.37.0 | BSD-3-Clause |
| golang.org/x/term | v0.36.0 | BSD-3-Clause |
| gopkg.in/yaml.v3 | v3.0.1 | MIT and Apache-2.0 |
| github.com/zalando/go-keyring | v0.2.6 | MIT |
| github.com/godbus/dbus/v5 | v5.1.0 | BSD-2-Clause |
| github.com/danieljoos/wincred | v1.2.2 | MIT |
| al.essio.dev/pkg/shellescape | v1.5.1 | MIT |

The full license texts are available in each module source, for example with
`go mod download -json <module>` or on <https://pkg.go.dev>.

## Data sources

CVE information is retrieved at runtime from the [OSV.dev](https://osv.dev)
API (Google, Apache-2.0 for the service schema), which aggregates the Debian
Security Tracker and Ubuntu Security Notices. farol-guard does not redistribute
that data.

## Runtime components referenced in examples

The deployment examples reference, without bundling them:
`docker.io/library/caddy`, `quay.io/oauth2-proxy/oauth2-proxy` and
`gcr.io/distroless/static-debian12`.
