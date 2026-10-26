# Supported platforms

## Audited servers

farol-guard detects the package manager on each host (`dpkg`, `rpm` with
`dnf`/`yum`, or `pacman`) and reads `/etc/os-release` to find the base
distribution. Derivatives are evaluated as their base: Linux Mint 22 is
reported as "based on Ubuntu 24.04", Raspberry Pi OS 12 as Debian 12.

| Family | Distributions | Updates | CVE source | End of life |
| --- | --- | --- | --- | --- |
| Debian | Debian 10 to 13, Raspberry Pi OS, other derivatives that declare `DEBIAN_CODENAME` or a Debian `VERSION_CODENAME` | `apt` | [OSV.dev](https://osv.dev) (Debian Security Tracker) | yes |
| Ubuntu | Ubuntu 18.04 to 26.04, Linux Mint, Pop!_OS, Zorin OS, elementary OS and other derivatives with `UBUNTU_CODENAME` | `apt` | OSV.dev (Ubuntu Security Notices) | yes |
| RHEL | RHEL, Rocky Linux, AlmaLinux, Oracle Linux (8 and later), Amazon Linux 2023 | `dnf` | the host's `dnf updateinfo` security advisories, plus unfixed CVEs from [Red Hat security data](https://access.redhat.com/security/data) for EL 8 to 10 | yes |
| Legacy yum | Amazon Linux 2, CentOS 7 (both past end of life) | `yum` | `yum updateinfo` security advisories | yes |
| Fedora | current Fedora releases (`dnf5`) | `dnf` | `dnf advisory` (Bodhi updates) | no |
| CentOS Stream | 9 and 10 | `dnf` | no advisories are published, so only unfixed CVEs from Red Hat security data and pending updates are shown | yes |
| SUSE | openSUSE Leap 15.6 and 16.0, openSUSE Tumbleweed, SLES | `zypper` | OSV.dev (SUSE security advisories) | yes (Leap) |
| Arch | Arch Linux, Manjaro, EndeavourOS and other `ID_LIKE=arch` systems | `pacman -Qu` (`checkupdates` with `--refresh`) | [Arch Linux security tracker](https://security.archlinux.org), matched locally | rolling |

Everything else (users, keys, sshd, logins, disks, memory, network, systemd,
firewall) works on any Linux. Distributions outside these families, such as
Alpine, Gentoo, NixOS or Kali (rolling, no fixed base release), are collected without
update, CVE and end-of-life evaluation, and the report says so.

### Notes per family

- **Debian and Ubuntu**: CVEs include those without a fix yet. Kernel packages
  with thousands of advisories are counted, not detailed.
- **RHEL family and Fedora**: the CVE list comes from the security advisories in
  the host's repositories, so it only contains CVEs with a fix available in
  those repositories. Metadata is read from the dnf cache (`dnf -C`); use
  "Refresh package lists" (`--refresh`, runs `dnf makecache`) when the cache is
  old or missing. Reboot detection uses `needs-restarting -r` when installed.
- **RHEL family unfixed CVEs**: for each source package the Red Hat security
  data API is asked which CVEs affect the EL major release; CVEs without a fixed
  build get their per-release state ("Affected", "Fix deferred", "Will not fix",
  "Under investigation"). This also applies to Rocky, AlmaLinux, Oracle Linux
  and CentOS, which rebuild the same sources. The first lookup takes a few
  minutes; results are cached (lists for 24 hours, CVE states for 7 days). Only
  source package names leave your machine.
- **SUSE family**: CVEs come from SUSE advisories in OSV.dev, matched by source
  package with the per-binary fixed versions SUSE publishes; OSV carries no
  severity for them, so they show as "unknown". On Tumbleweed (rolling) the fix
  is always `zypper dup`; on Leap and SLES `zypper update` or
  `zypper patch --category security`.
- **Arch family**: the tracker list (about 1 MB) is downloaded by the machine
  running farol-guard and cached for 6 hours; package versions are compared
  locally with pacman's version rules. Arch does not support partial upgrades,
  so the suggested fix is always `pacman -Syu`. `--refresh` uses `checkupdates`
  (from `pacman-contrib`), which never touches the system package database.

## Machine running farol-guard

The client is a static Go binary for amd64 and arm64 and runs on any Linux
distribution.

| Distribution | Package | Install |
| --- | --- | --- |
| Debian, Ubuntu and derivatives | `.deb` | `sudo apt install ./farol-guard_<version>_amd64.deb` |
| Fedora, RHEL, Rocky, AlmaLinux, Oracle Linux, Amazon Linux | `.rpm` | `sudo dnf install ./farol-guard-<version>-1.x86_64.rpm` |
| openSUSE | `.rpm` | `sudo zypper install --allow-unsigned-rpm ./farol-guard-<version>-1.x86_64.rpm` |
| Arch, Manjaro, EndeavourOS | `.pkg.tar.zst` | `sudo pacman -U ./farol-guard-<version>-1-x86_64.pkg.tar.zst` |
| Any other | binary or source | `make build-local && sudo make install` |
| Windows (WSL2) | as the Linux distribution inside WSL | `farol open` opens Microsoft Edge on Windows |

### Package repositories

Signed apt, dnf/zypper and pacman repositories are published with each release
at <https://dgolveira.github.io/farol-guard/>, which lists the setup commands
for every distribution. RPMs are signed with rpmsign, Arch packages carry
detached signatures, repository indexes are signed, and the release assets
include `SHA256SUMS.asc`. Release key fingerprint:
`F298 B0C2 3F87 FEAC AC95 3023 04EB 9326 3E1F 5972`
([packaging/signing/farol-guard.asc](../packaging/signing/farol-guard.asc)).

### Building from source

Any distribution with Go and make works. When the distribution's Go is older
than the version in `go.mod`, `make build-local` sets `GOTOOLCHAIN=auto` and Go
downloads the right toolchain.

```bash
sudo apt install golang-go make git     # Debian, Ubuntu
sudo dnf install golang make git        # Fedora, RHEL family
sudo pacman -S go make git              # Arch
sudo zypper install go make git         # openSUSE

git clone https://github.com/dgolveira/farol-guard.git
cd farol-guard
make build-local
sudo make install                       # PREFIX=/usr/local by default
farol version
```

`make install` copies the binary, the menu entry, the icon and the systemd user
units; `sudo make uninstall` removes them. Tested on Debian 13, Ubuntu 24.04,
Fedora, Rocky Linux 9, Arch Linux and openSUSE Tumbleweed.
