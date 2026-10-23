# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.2] - 2026-10-23

### Added

- `farol open`: starts the dashboard in the background when it is not running
  (through the `farol-guard-ui` systemd user unit when installed, otherwise as a
  detached process) and opens the browser; `farol stop` stops it. The desktop
  entry now runs `farol open` without a terminal and offers "Stop dashboard".
- The dashboard session token is stored in `~/.config/farol-guard/ui-token`
  (mode 600) and reused across restarts, unless `FAROL_GUARD_TOKEN` is set.

### Changed

- The container image is published only on GitHub Container Registry
  (`ghcr.io/dgolveira/farol-guard`). Docker Hub (`dgzin01/farol-guard`) is no
  longer updated after 0.2.1.
- Desktop entry categories fixed so the icon appears once in the menu.

## [0.2.1] - 2026-10-23

### Security

- Build with Go 1.26.10 and `golang.org/x/crypto` v0.56.0. Version 0.2.0 was
  built with Go 1.25 and `x/crypto` v0.43.0, which are affected by
  vulnerabilities reported by govulncheck in the SSH client, `net/http`,
  `html/template`, `crypto/tls` and `crypto/x509`. Upgrade from 0.2.0.

### Added

- Container image published on Docker Hub (`ghcr.io/dgolveira/farol-guard`),
  multi-arch (amd64, arm64).

## [0.2.0] - 2026-10-23

First public release.

### Added

- `farol check`: agentless audit over SSH of users, root and sudo accounts,
  authorized keys, effective sshd settings, OS support dates, pending and
  security updates, reboot required, CVEs from OSV.dev with fixed versions and
  upgrade commands, SSH access by source IP, network and kernel errors, disks,
  memory, CPU, services, ports, firewall, fail2ban, NTP, containers and snaps.
- HTML (overview with per-host details), JSON and Markdown reports in English
  and Brazilian Portuguese; `--fail-on` exit codes for automation.
- `farol ui`: local dashboard with fleet overview, live activity log, host
  details, inventory editor with groups, filters, cloning and connection tests,
  report history, light and dark themes.
- Host key handling: unknown keys are captured once, reviewed in bulk and
  trusted without reconnecting; pending hosts are skipped to avoid triggering
  sshguard or fail2ban.
- Key management: generate, deploy, rotate and remove keys with dry run,
  backups, login verification and rollback; keys from `~/.ssh` and the agent.
- Dedicated app key with installation signature, kernel CSPRNG generation,
  passphrase in the system keyring (or environment / systemd credential),
  `restrict` and optional `from=`; replace and protect operations.
- `.deb` packages (amd64, arm64), distroless container image, Docker Compose
  with Caddy and Kubernetes with oauth2-proxy examples, hosting guide.
