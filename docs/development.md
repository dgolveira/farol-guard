# Development

## Requirements

- Go 1.26 (or only Docker: every `make` target runs inside
  `docker.io/library/golang:1.26-bookworm`).
- Docker with the compose plugin for the test lab.
- `dpkg-deb` to build the `.deb` packages.

## Common tasks

```bash
make build        # dist/farol for the host architecture (inside Docker)
make build-local  # same, with a local Go toolchain
make build-all    # dist/farol-linux-amd64 and dist/farol-linux-arm64
make test         # unit tests
make vet
make deb          # dist/farol-guard_<version>_{amd64,arm64}.deb
make docker       # container image
```

## Test lab

`test/lab` starts Debian 12, Ubuntu 24.04 and Ubuntu 22.04 containers running
`sshd` on `127.0.0.1:2201-2203`, plus an unreachable host, with a throwaway key
generated in `.cache/lab/` (ignored by git). The Debian container enables weak
`sshd` settings on purpose so findings show up.

```bash
test/lab/setup.sh                 # build and start, writes test/lab/inventory.yaml
make build
./dist/farol check -c test/lab/inventory.yaml \
  --known-hosts .cache/lab/known_hosts --accept-new -o .cache/lab/report.html

XDG_CONFIG_HOME=$PWD/.cache/lab/config FAROL_GUARD_DATA=$PWD/.cache/lab/data \
  FAROL_GUARD_KNOWN_HOSTS=$PWD/.cache/lab/known_hosts \
  ./dist/farol ui -c test/lab/inventory.yaml

test/lab/setup.sh --down          # stop and remove the containers
```

Use the lab for anything that writes keys. Never point development builds at
production hosts.

## Layout

| Path | Purpose |
| --- | --- |
| `cmd/farol` | CLI entry point (`check`, `ui`, `keys`, `hosts`, `init`) |
| `internal/collect` | remote collector script (`collect.sh`) and parser |
| `internal/analyze` | findings and severities |
| `internal/vuln` | OSV.dev lookup (querybatch + cached advisories), CVSS scoring |
| `internal/keys`, `internal/keyops` | key store, keyring secret, remote `authorized_keys` operations |
| `internal/server` | dashboard HTTP API and embedded web UI |
| `internal/report` | HTML, JSON and Markdown reports |
| `internal/i18n` | English and Brazilian Portuguese strings |
| `packaging`, `scripts` | `.deb` layout and build script, systemd user units |
| `deploy` | Docker Compose and Kubernetes examples |

## Conventions

- Code, comments, commit messages and documentation in English; UI strings in
  English and Brazilian Portuguese through `internal/i18n`.
- No emojis anywhere.
- Container images always fully qualified (`docker.io/...`, `ghcr.io/...`).
- Shell scripts start with the project header and use `[[ ]]`, quoted variables
  and `$()`.
- Randomness for keys and secrets only from `crypto/rand` (enforced by a test).
