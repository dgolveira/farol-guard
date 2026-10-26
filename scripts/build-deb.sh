#!/bin/bash
# -----------------------------------------------------------------------------
# Script Name: build-deb.sh
# Description: Builds the farol-guard .deb package from a prebuilt static
#              binary using dpkg-deb (no other packaging tools required).
# Author:      Douglas Oliveira <contato@dgoliveira.com.br>
# Role:        Infrastructure Analyst
# Created:     2026-10-23
#
# Usage:       scripts/build-deb.sh --version 0.1.0 --arch amd64 \
#                --binary dist/farol-linux-amd64 [--out dist]
# Options:
#   --version  Package version (default: content of VERSION)
#   --arch     Debian architecture: amd64 or arm64 (default: amd64)
#   --binary   Path to the farol binary for that architecture
#   --out      Output directory (default: dist)
#   --dry-run  Print the package layout without building it
# -----------------------------------------------------------------------------
set -e

root_dir="$(cd "$(dirname "$0")/.." && pwd)"
version="$(cat "$root_dir/VERSION")"
arch="amd64"
binary=""
out_dir="$root_dir/dist"
dry_run=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) version="$2"; shift 2 ;;
    --arch) arch="$2"; shift 2 ;;
    --binary) binary="$2"; shift 2 ;;
    --out) out_dir="$2"; shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$binary" ]]; then
  binary="$root_dir/dist/farol-linux-$arch"
fi
if [[ ! -f "$binary" ]]; then
  echo "binary not found: $binary (run 'make build-all' first)" >&2
  exit 1
fi
version="${version#v}"
pkg="farol-guard_${version}_${arch}"
staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT
pkg_root="$staging/$pkg"

install -Dm755 "$binary" "$pkg_root/usr/bin/farol"
install -Dm644 "$root_dir/packaging/deb/farol-guard.desktop" "$pkg_root/usr/share/applications/farol-guard.desktop"
install -Dm644 "$root_dir/internal/server/web/icon.svg" "$pkg_root/usr/share/icons/hicolor/scalable/apps/farol-guard.svg"
for unit in farol-guard-ui.service farol-guard-check.service farol-guard-check.timer; do
  install -Dm644 "$root_dir/packaging/systemd/$unit" "$pkg_root/usr/lib/systemd/user/$unit"
done
install -Dm644 "$root_dir/LICENSE" "$pkg_root/usr/share/doc/farol-guard/copyright"

installed_kb="$(du -sk "$pkg_root/usr" | cut -f1)"
mkdir -p "$pkg_root/DEBIAN"
cat > "$pkg_root/DEBIAN/control" <<CONTROL
Package: farol-guard
Version: $version
Section: admin
Priority: optional
Architecture: $arch
Installed-Size: $installed_kb
Recommends: openssh-client, xdg-utils
Maintainer: Douglas Oliveira <contato@dgoliveira.com.br>
Homepage: https://github.com/dgolveira/farol-guard
Description: Agentless SSH auditor for Linux server fleets
 farol-guard connects to Debian, Ubuntu, RHEL family, Fedora, Amazon Linux
 and Arch servers over SSH and audits users, root accounts, authorized
 keys, sshd configuration, pending and security updates, CVEs, SSH
 access by IP, network errors, disks,
 memory and CPU. It produces HTML/JSON/Markdown reports, serves a local
 web dashboard and rotates SSH keys with verification and rollback.
CONTROL

if [[ "$dry_run" == "1" ]]; then
  echo "[DRY-RUN] would build $out_dir/$pkg.deb with:"
  (cd "$pkg_root" && find . -type f | sort)
  exit 0
fi

mkdir -p "$out_dir"
dpkg-deb --build --root-owner-group "$pkg_root" "$out_dir/$pkg.deb" >/dev/null
echo "$out_dir/$pkg.deb"
