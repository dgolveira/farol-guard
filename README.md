<p align="center">
  <img src="internal/server/web/icon.svg" width="72" height="72" alt="farol-guard">
</p>

<h1 align="center">farol-guard</h1>

<p align="center">
  Agentless SSH auditor for Linux server fleets (Debian, Ubuntu, RHEL family,
  Fedora, Amazon Linux, Arch and derivatives): users, keys, sshd, updates, CVEs
  and resources, with a local dashboard and safe SSH key rotation.
</p>

<p align="center">
  <a href="https://github.com/dgolveira/farol-guard/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/dgolveira/farol-guard/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/dgolveira/farol-guard/actions/workflows/codeql.yml"><img alt="CodeQL" src="https://github.com/dgolveira/farol-guard/actions/workflows/codeql.yml/badge.svg"></a>
  <a href="https://github.com/dgolveira/farol-guard/releases"><img alt="Release" src="https://img.shields.io/github/v/release/dgolveira/farol-guard?sort=semver"></a>
  <a href="https://goreportcard.com/report/github.com/dgolveira/farol-guard"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/dgolveira/farol-guard"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
</p>

<p align="center">
  <b>English</b> | <a href="README.pt-BR.md">Português (Brasil)</a>
</p>

---

<p align="center"><img src="docs/images/fleet.png" alt="Fleet overview" width="900"></p>

*Farol* is Portuguese for lighthouse. farol-guard watches a fleet of Linux
servers from the outside: it connects over SSH, runs a read-only collector,
and tells you who can log in, with which keys, what is outdated or vulnerable,
and what is about to run out of disk, all without installing anything on the
servers.

## Highlights

- **Agentless and public-key only.** One SSH session per host, a read-only
  collector over `bash -s`, `sudo -n` when you do not log in as root. No
  daemon, no open port, no password logins.
- **Access audit.** Users, UID 0 accounts, sudoers and `NOPASSWD`, every
  `authorized_keys` line with fingerprints, effective `sshd -T` settings, SSH
  logins grouped by source IP and by key.
- **Updates and CVEs.** Pending and security updates (`apt`, `dnf`, `pacman`),
  end-of-support dates, reboot required, and CVEs with the fixed version and
  the exact upgrade command, from [OSV.dev](https://osv.dev) (Debian, Ubuntu
  and derivatives), the host's own `dnf` security advisories (RHEL family,
  Fedora, Amazon Linux) and the Arch Linux security tracker.
- **Health.** Disks and inodes, memory, swap, load, CPU, network interface
  errors, kernel errors, failed systemd units, listening ports, firewall,
  fail2ban, NTP, containers and snaps.
- **Safe key management.** Deploy, rotate and remove keys with dry run,
  backups, login verification and automatic rollback. A dedicated app key
  generated from kernel entropy, encrypted with a passphrase kept in the system
  keyring, installed with `restrict` and optionally `from=`.
- **Dashboard and reports.** Local web UI (English and Brazilian Portuguese,
  light and dark themes), live activity log, inventory editor with groups and
  filters, report history, and self-contained HTML, JSON and Markdown reports.
- **Easy to ship.** A single static Go binary, `.deb` packages for amd64 and
  arm64, a distroless container image, and examples for Docker Compose and
  Kubernetes.

## Screenshots

| Host details | Inventory |
| --- | --- |
| <img src="docs/images/host.png" alt="Host details" width="440"> | <img src="docs/images/inventory.png" alt="Inventory" width="440"> |

| Key management | HTML report |
| --- | --- |
| <img src="docs/images/keys.png" alt="Key management" width="440"> | <img src="docs/images/report-modal.png" alt="HTML report" width="440"> |

<p align="center"><img src="docs/images/fleet-dark.png" alt="Dark theme" width="700"></p>

## How it works

farol-guard never stores SSH passwords and does not support password logins:
**every connection uses an SSH key**. A public key must already be authorized
on each server, for `root` or for a user with passwordless `sudo`, before the
first check. You can reuse the key you already have, or follow
[Getting started](docs/getting-started.md#path-b-prepare-the-access-manually)
to create a dedicated, restricted user and app key by hand.

```text
farol (your workstation) --SSH key--> server: bash -s collector (read-only)
                        <--sections--
       parse, analyze, OSV.dev lookup (package names and versions only)
       -> findings, dashboard, HTML/JSON/Markdown reports
```

## Install

**Signed repositories** for apt, dnf, zypper and pacman, with the setup
commands for each distribution: <https://dgolveira.github.io/farol-guard/>.

**Packages** (from the [releases](https://github.com/dgolveira/farol-guard/releases), amd64 and arm64):

```bash
sudo apt install ./farol-guard_1.1.0_amd64.deb                 # Debian, Ubuntu, Mint, Pop!_OS...
sudo dnf install ./farol-guard-1.1.0-1.x86_64.rpm              # Fedora, RHEL, Rocky, Alma, Oracle, Amazon Linux
sudo zypper install --allow-unsigned-rpm ./farol-guard-1.1.0-1.x86_64.rpm   # openSUSE
sudo pacman -U ./farol-guard-1.1.0-1-x86_64.pkg.tar.zst        # Arch, Manjaro, EndeavourOS
farol version
```

Each package installs the `farol` binary, a **farol-guard** icon in the
applications menu (it starts the dashboard in the background and opens the
browser; right click offers "Stop dashboard"), and optional systemd user units
for a daily check and for the dashboard (disabled by default).

**Container image** ([GitHub Container Registry](https://github.com/dgolveira/farol-guard/pkgs/container/farol-guard), amd64 and arm64):

```bash
docker run --rm ghcr.io/dgolveira/farol-guard:1.1.0 version
```

See [container image](docs/container.md), [deploy/docker](deploy/docker) and [hosting](docs/hosting.md).

**From source on any distribution** (Go and make; an older distro Go downloads
Go 1.26 automatically):

```bash
sudo dnf install golang make git        # or: apt install golang-go make git / pacman -S go make git / zypper in go make git
git clone https://github.com/dgolveira/farol-guard.git
cd farol-guard
make build-local                        # output in dist/farol
sudo make install                       # /usr/local: binary, menu icon, systemd user units
```

With only Docker: `make build` (binary) and `make packages` (`.deb`, `.rpm` and
Arch packages for amd64 and arm64). See [supported platforms](docs/platforms.md).

## Quick start

```bash
farol init                                   # sample inventory in ~/.config/farol-guard
$EDITOR ~/.config/farol-guard/inventory.yaml # add your hosts
farol check -o report.html                   # audit and write a report
farol open                                   # start the dashboard and open the browser
```

Useful flags for `farol check`: `-g group`, `-H host`, `--refresh` (refreshes
package metadata first: `apt-get update`, `dnf makecache`), `--no-cve`,
`--fail-on high` (exit code 3 for cron or CI), `-v` (step by step log),
`-f json|md|html`, `--lang en|pt-BR`.

## Security model

The source code is public, so nothing in it can help an attacker. Keys and
secrets are generated at runtime from the kernel CSPRNG on each installation,
there are no default or embedded keys, and the app key is protected by the
system keyring, `restrict` and optionally `from=`. The dashboard listens on
`127.0.0.1` with a session token, a Host header check and CSRF protection.

Details: [SSH keys and security model](docs/keys.md),
[hosting](docs/hosting.md), [security policy](SECURITY.md).

**What leaves your machine:** only package names and versions, sent to
`api.osv.dev` for the CVE lookup of Debian and Ubuntu hosts. For Arch hosts the
public advisory list is downloaded from `security.archlinux.org` and matched
locally; nothing is sent. RHEL family hosts use their own repositories. No
hostnames, IPs or users leave your machine. Use `--no-cve` (or the dashboard
option) to skip the lookup.

## Documentation

- [Getting started](docs/getting-started.md): access model, first access, inventory
- [Supported platforms](docs/platforms.md): audited distributions, CVE sources, client packages
- [SSH keys and security model](docs/keys.md)
- [Hosting](docs/hosting.md): SSH tunnel, Docker with Caddy, Kubernetes with oauth2-proxy
- [Development](docs/development.md): build, test lab, layout

## FAQ

**Do I need to install anything on the servers?**
No. farol-guard only needs SSH access with a key, and `sudo -n` (or root) for a
complete audit.

**Does it change anything on the servers?**
Checks are read-only. The only optional write during a check is refreshing
package metadata (`apt-get update`, `dnf makecache`) when you enable "Refresh
package lists". Key operations change
`authorized_keys`, always with dry run, backup and verification.

**Which distributions are supported?**
Debian, Ubuntu and their derivatives (Linux Mint, Pop!_OS, Zorin, elementary,
Raspberry Pi OS), the RHEL family (RHEL, CentOS Stream, Rocky, AlmaLinux,
Oracle Linux), Fedora, Amazon Linux, openSUSE Leap, Tumbleweed and SLES, and
the Arch family (Arch, Manjaro, EndeavourOS). Other distributions are collected partially, without update and
CVE evaluation. Details in [supported platforms](docs/platforms.md).

**Why are kernel CVEs only counted?**
OSV lists thousands of advisories for kernel packages. farol-guard counts them
and relies on security updates and the reboot-required flag for the kernel instead of downloading hundreds of megabytes.

**Does it run on WSL?**
Yes, on Ubuntu or Debian under WSL2. `farol open` (and the menu icon under
WSLg) detects WSL and opens the dashboard in Microsoft Edge on Windows as an app
window, falling back to the default Windows browser; the dashboard stops 20
seconds after the window closes. The GNOME keyring is usually missing on WSL,
so pass the app key passphrase with `FAROL_GUARD_APP_PASSPHRASE`, and enable
`systemd=true` in `/etc/wsl.conf` to use the systemd units.

**My server blocked me after a few checks.**
Tools like sshguard and fail2ban count aborted handshakes. farol-guard opens at
most one aborted connection per new host (to capture its host key) and skips
hosts whose key is still pending review.

**Is there a login screen for hosting?**
Not built in. Put it behind an authenticating proxy, see [hosting](docs/hosting.md).
Contributions are welcome.

## Contributing

Issues and pull requests are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md)
and the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately
as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Third-party components are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). CVE data comes from
[OSV.dev](https://osv.dev) and its upstream sources (Debian Security Tracker,
Ubuntu Security Notices), the distributions' own `dnf` advisories and the
[Arch Linux security tracker](https://security.archlinux.org).
