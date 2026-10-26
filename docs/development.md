# Development

## Requirements

- Go 1.26 (or only Docker: every `make` target runs inside
  `docker.io/library/golang:1.26-bookworm`).
- Docker with the compose plugin for the test lab.
- `dpkg-deb` to build the `.deb` packages (`.rpm` and Arch packages are built
  with `docker.io/goreleaser/nfpm`).

## Common tasks

```bash
make build        # dist/farol for the host architecture (inside Docker)
make build-local  # same, with a local Go toolchain
make build-all    # dist/farol-linux-amd64 and dist/farol-linux-arm64
make test         # unit tests
make vet
make deb          # dist/farol-guard_<version>_{amd64,arm64}.deb
make rpm          # dist/farol-guard-<version>-1.{x86_64,aarch64}.rpm
make archpkg      # dist/farol-guard-<version>-1-{x86_64,aarch64}.pkg.tar.zst
make packages     # all of the above
make install      # install dist/farol and desktop/systemd files (PREFIX, DESTDIR)
make docker       # container image
```

## Test lab

`test/lab` starts containers running `sshd` on `127.0.0.1`, plus an unreachable
host, with a throwaway key generated in `.cache/lab/` (ignored by git):

| Port | Host | Notes |
| --- | --- | --- |
| 2201 | Debian 12 | weak `sshd` settings on purpose so findings show up |
| 2202, 2203 | Ubuntu 24.04, 22.04 | 22.04 logs in as `deploy` with sudo |
| 2204 | Linux Mint 22 | Mint image with the real Mint `os-release` mounted (derivative mapping) |
| 2205 to 2207 | Rocky 9.4, AlmaLinux 9.4, CentOS Stream 9 | old point releases, so security advisories show up |
| 2208 | Fedora | `dnf5`, logs in as `deploy` |
| 2209, 2210 | Oracle Linux 9, Amazon Linux 2023 | |
| 2211 | Arch Linux | |

`test/lab` also has Amazon Linux 2 and CentOS 7 (yum, 2212-2213) and openSUSE
Leap 16.0 and Tumbleweed (zypper, 2214-2215).

### Virtual machines

`test/vm/run.sh up` boots KVM virtual machines from official cloud images
(Debian 13, Rocky 9, Fedora, openSUSE Leap 16) with real systemd, kernels and
reboots, SSH on `127.0.0.1:2301-2304` and the lab key for root, and writes
`test/vm/inventory.yaml`. Disks are copy-on-write in `.cache/vm`;
`test/vm/run.sh down` powers them off and `reset` deletes the disks. The Arch
cloud image does not start sshd from cloud-init, so Arch is covered by the
container lab only.

```bash
test/vm/run.sh up
./dist/farol check -c test/vm/inventory.yaml --known-hosts .cache/vm/known_hosts --accept-new --refresh
test/vm/run.sh down
```

### Package repositories

`scripts/build-repo.sh --key <fingerprint> --passphrase-file <file>` signs the
packages in `dist/` and builds the apt, dnf/zypper and pacman repositories in
`dist/site` (the release workflow publishes it to GitHub Pages). Test it with a
throwaway key and `python3 -m http.server` before changing the workflow.

To exercise pending updates on an up-to-date image, downgrade a package inside
the container, for example `docker exec lab-fedora-1 dnf -y downgrade sudo`.

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
