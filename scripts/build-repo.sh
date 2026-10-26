#!/bin/bash
# -----------------------------------------------------------------------------
# Script Name: build-repo.sh
# Description: Signs the release packages and builds the apt, dnf/zypper and
#              pacman repositories published on GitHub Pages. RPMs are signed
#              with rpmsign (and copied back to the dist directory), Arch
#              packages get detached signatures, and every repository index
#              is signed with the release key. Compute and sign SHA256SUMS
#              after this script, since signing changes the RPM files. The repository tools run in containers, so only
#              docker and gpg are needed on the host.
# Author:      Douglas Oliveira <contato@dgoliveira.com.br>
# Role:        Infrastructure Analyst
# Created:     2026-10-26
#
# Usage:       scripts/build-repo.sh --key <fingerprint> [options]
#   --key FPR               GPG key (already in the gpg keyring) used to sign
#   --passphrase-file FILE  file with the key passphrase (omit for no passphrase)
#   --dist DIR              directory with the packages (default: dist)
#   --out DIR               output site directory (default: dist/site)
#   --base-url URL          public URL of the site
#                           (default: https://dgolveira.github.io/farol-guard)
#   --dry-run               print what would be done without changing anything
#
# Example:     scripts/build-repo.sh --key 0123ABCD... --passphrase-file pass.txt
# -----------------------------------------------------------------------------
set -e

root_dir="$(cd "$(dirname "$0")/.." && pwd)"
dist="$root_dir/dist"
out=""
key=""
pass_file=""
base_url="https://dgolveira.github.io/farol-guard"
dry_run=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --key) key="$2"; shift 2 ;;
    --passphrase-file) pass_file="$2"; shift 2 ;;
    --dist) dist="$(cd "$2" && pwd)"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --base-url) base_url="${2%/}"; shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
out="${out:-$dist/site}"

if [[ -z "$key" ]]; then
  echo "--key is required" >&2
  exit 2
fi
shopt -s nullglob
debs=("$dist"/farol-guard_*.deb)
rpms=("$dist"/farol-guard-*.rpm)
archpkgs=("$dist"/farol-guard-*.pkg.tar.zst)
if [[ ${#debs[@]} -eq 0 || ${#rpms[@]} -eq 0 || ${#archpkgs[@]} -eq 0 ]]; then
  echo "missing packages in $dist (run 'make packages' first)" >&2
  exit 1
fi

if [[ "$dry_run" == "1" ]]; then
  echo "[DRY-RUN] would sign ${#rpms[@]} rpm and ${#archpkgs[@]} Arch packages with $key"
  echo "[DRY-RUN] would build $out/{apt,rpm,arch} for $base_url"
  exit 0
fi

gpg_args=(--batch --yes --local-user "$key")
if [[ -n "$pass_file" ]]; then
  gpg_args+=(--pinentry-mode loopback --passphrase-file "$pass_file")
fi
sign_detached() { gpg "${gpg_args[@]}" --detach-sign "$@"; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
gpg --batch --armor --export "$key" > "$work/public.asc"
if [[ -n "$pass_file" ]]; then
  gpg --batch --pinentry-mode loopback --passphrase-file "$pass_file" --armor --export-secret-keys "$key" > "$work/secret.asc"
  cp "$pass_file" "$work/pass"
else
  gpg --batch --armor --export-secret-keys "$key" > "$work/secret.asc"
  : > "$work/pass"
fi
chmod 600 "$work/secret.asc" "$work/pass"

uid="$(id -u):$(id -g)"
run() {
  local image="$1"; shift
  docker run --rm -v "$work":/work -v "$out":/site -v "$dist":/dist "$image" bash -c "$*"
}

rm -rf "$out"
mkdir -p "$out/apt/pool" "$out/rpm/x86_64" "$out/rpm/aarch64" "$out/arch/x86_64" "$out/arch/aarch64"
out="$(cd "$out" && pwd)"
cp "$work/public.asc" "$out/farol-guard.asc"

for r in "${rpms[@]}"; do
  case "$r" in
    *.x86_64.rpm) cp "$r" "$out/rpm/x86_64/" ;;
    *.aarch64.rpm) cp "$r" "$out/rpm/aarch64/" ;;
  esac
done
run docker.io/library/fedora:44 "
  set -e
  dnf -y -q install rpm-sign createrepo_c gnupg2 >/dev/null
  export GNUPGHOME=/tmp/gnupg; mkdir -m 700 \$GNUPGHOME
  gpg --batch --pinentry-mode loopback --passphrase-file /work/pass --import /work/secret.asc 2>/dev/null
  rpm --import /work/public.asc
  for f in /site/rpm/*/*.rpm; do
    rpmsign --addsign \
      --define '_gpg_name $key' \
      --define '_gpg_sign_cmd_extra_args --pinentry-mode loopback --passphrase-file /work/pass' \
      \"\$f\" >/dev/null
    rpm -K \"\$f\" | grep -q 'signatures OK'
  done
  for a in x86_64 aarch64; do createrepo_c -q --general-compress-type=gz /site/rpm/\$a; done
  chown -R $uid /site
"
for a in x86_64 aarch64; do
  sign_detached --armor --output "$out/rpm/$a/repodata/repomd.xml.asc" "$out/rpm/$a/repodata/repomd.xml"
done
cp "$out"/rpm/*/*.rpm "$dist/"
cat > "$out/rpm/farol-guard.repo" <<REPO
[farol-guard]
name=farol-guard
baseurl=$base_url/rpm/\$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=$base_url/farol-guard.asc
REPO

cp "${debs[@]}" "$out/apt/pool/"
run docker.io/library/debian:13 "
  set -e
  apt-get update -qq >/dev/null && apt-get install -y -qq apt-utils >/dev/null
  cd /site/apt
  for a in amd64 arm64; do
    mkdir -p dists/stable/main/binary-\$a
    apt-ftparchive --arch \$a packages pool > dists/stable/main/binary-\$a/Packages
    gzip -9kf dists/stable/main/binary-\$a/Packages
  done
  apt-ftparchive \
    -o APT::FTPArchive::Release::Origin=farol-guard \
    -o APT::FTPArchive::Release::Label=farol-guard \
    -o APT::FTPArchive::Release::Suite=stable \
    -o APT::FTPArchive::Release::Codename=stable \
    -o APT::FTPArchive::Release::Architectures='amd64 arm64' \
    -o APT::FTPArchive::Release::Components=main \
    release dists/stable > /tmp/Release
  mv /tmp/Release dists/stable/Release
  chown -R $uid /site
"
gpg "${gpg_args[@]}" --clearsign --output "$out/apt/dists/stable/InRelease" "$out/apt/dists/stable/Release"
sign_detached --armor --output "$out/apt/dists/stable/Release.gpg" "$out/apt/dists/stable/Release"
gpg --batch --dearmor < "$work/public.asc" > "$out/apt/farol-guard.gpg"

for p in "${archpkgs[@]}"; do
  case "$p" in
    *-x86_64.pkg.tar.zst) a=x86_64 ;;
    *-aarch64.pkg.tar.zst) a=aarch64 ;;
    *) continue ;;
  esac
  cp "$p" "$out/arch/$a/"
  sign_detached --output "$p.sig" "$p"
  cp "$p.sig" "$out/arch/$a/"
done
run docker.io/library/archlinux:latest "
  set -e
  for a in x86_64 aarch64; do
    cd /site/arch/\$a
    repo-add -q farol-guard.db.tar.gz ./*.pkg.tar.zst
    rm -f farol-guard.db farol-guard.files
    cp farol-guard.db.tar.gz farol-guard.db
    cp farol-guard.files.tar.gz farol-guard.files
  done
  chown -R $uid /site
"
for a in x86_64 aarch64; do
  for f in farol-guard.db farol-guard.db.tar.gz farol-guard.files farol-guard.files.tar.gz; do
    sign_detached --output "$out/arch/$a/$f.sig" "$out/arch/$a/$f"
  done
done

fpr="$(gpg --batch --with-colons --fingerprint "$key" | awk -F: '/^fpr/ {print $10; exit}')"
sed -e "s|@BASE_URL@|$base_url|g" -e "s|@FINGERPRINT@|$fpr|g" "$root_dir/packaging/repo/index.html" > "$out/index.html"
touch "$out/.nojekyll"
echo "$out"
