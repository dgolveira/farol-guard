# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.2] - 2026-10-23

### Fixed

- Report downloads (HTML, JSON, Markdown) now open the native "Save as" dialog
  where the browser supports it, so they work visibly inside the app window,
  which does not show the browser download bar. Other browsers fall back to a
  normal download. A notice confirms the saved file.
- The scope picker on the fleet view opened behind the summary cards, and a
  stray "-" marker showed under it.

### Added

- "Download HTML" next to JSON and Markdown in the fleet view and report history.
- Fix commands panel in the CVE section of each host: a single command that
  upgrades every package with a fixed CVE (non-interactive, keeps modified
  config files), a simulation command, an alternative covering all pending
  security updates, and post-upgrade checks (services to restart, pending
  reboot, failed units). A risk notice comes first and flags packages that
  usually need a restart or reboot and fixes missing from the apt lists. The
  dashboard opens it as a modal with copy buttons; the static HTML report shows
  it as an expandable block. The JSON report gains `fix_plan`.
- Findings for high/critical CVEs without a fix, pending and security updates
  and kernel errors now list the items behind the count (CVE, package, severity
  and summary; package and versions; log lines). Advisory IDs link to OSV,
  and lists with more than two items are collapsed behind "Show details".


## [1.0.1] - 2026-10-23

### Fixed

- Connection errors are explained in plain language (name not in DNS, port
  refused, timeout or firewall/fail2ban, no route, key rejected, host key
  changed, locked key, reset during handshake) in the connection test, the
  check progress and the report findings; the raw error stays available on
  hover and in the finding details.
- The dashboard uses up to 1480 px of width, so the inventory table no longer
  scrolls sideways or cuts the action buttons on wide screens and in Portuguese.
- Switching the language during a running check no longer blanks the progress
  and activity log; the full log and state are reloaded immediately.

### Added

- "Cancel check" button while a check runs: hosts not started yet are skipped,
  running collections are interrupted and a cancelled check is not saved to the
  history.
- Clear end of check: the progress bar turns green, a summary shows how many
  hosts were ok, failed or have a pending host key, and the button changes to
  "Check again".

## [1.0.0] - 2026-10-23

First stable release. The CLI flags, inventory format, report JSON fields and
dashboard API used by the bundled UI are considered stable from this version;
breaking changes will only happen in a new major version.

### Added

- `farol open` opens the dashboard as an app window (own window, no tabs) when
  the default browser is Chromium based (Edge, Chrome, Chromium, Brave, Vivaldi,
  Opera), using a dedicated browser profile; closing the window stops the
  dashboard. Other default browsers get a normal tab. `--no-app` and
  `FAROL_GUARD_BROWSER` override the choice.
- Presence tracking: every page served by the dashboard sends a heartbeat. When
  started by `farol open` or the desktop icon (`--idle-exit 20s`), the dashboard
  exits once no page has been open for 20 seconds, never during a check or a key
  operation. `farol ui`, Docker and Kubernetes keep running unless
  `--idle-exit`/`FAROL_GUARD_IDLE_EXIT` is set.
- Backend status indicator in the dashboard top bar: green while the backend
  answers, red and pulsing when the connection is lost.

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
