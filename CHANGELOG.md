# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
