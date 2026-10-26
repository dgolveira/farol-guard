#!/bin/bash
# -----------------------------------------------------------------------------
# Script Name: run.sh
# Description: Boots throwaway KVM virtual machines from official cloud images
#              (one per supported family) to test farol-guard against real
#              systemd, kernels and reboots. Uses QEMU user-mode networking
#              with SSH forwarded to 127.0.0.1:2301-2305, a cloud-init seed
#              that authorizes the lab key for root, and copy-on-write disks
#              in .cache/vm. Each VM also gets a vsock device (CID 3 to 7,
#              "ssh root@vsock/<cid>" on hosts with systemd-ssh-proxy) for
#              debugging without network. Writes test/vm/inventory.yaml.
# Author:      Douglas Oliveira <contato@dgoliveira.com.br>
# Role:        Infrastructure Analyst
# Created:     2026-10-26
#
# Usage:       test/vm/run.sh up [name...]     download images and boot VMs
#              test/vm/run.sh down [name...]   power off VMs (disks are kept)
#              test/vm/run.sh reset [name...]  power off and delete the disks
#              test/vm/run.sh status
#   --dry-run  print the actions without running them
#
# Requires:    qemu-system-x86_64, qemu-img, xorriso, curl, /dev/kvm access,
#              and the lab key from test/lab/setup.sh.
# -----------------------------------------------------------------------------
set -e

root_dir="$(cd "$(dirname "$0")/../.." && pwd)"
vm_dir="$root_dir/.cache/vm"
key="$root_dir/.cache/lab/id_ed25519.pub"
dry_run=0

declare -A url port
names=(debian13 rocky9 fedora leap16 arch)
url[debian13]="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2"
url[rocky9]="https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2"
url[fedora]="https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2"
url[leap16]="https://download.opensuse.org/distribution/leap/16.0/appliances/Leap-16.0-Minimal-VM.x86_64-Cloud.qcow2"
url[arch]="https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2"
port[debian13]=2301
port[rocky9]=2302
port[fedora]=2303
port[leap16]=2304
port[arch]=2305

args=()
for a in "$@"; do
  if [[ "$a" == "--dry-run" ]]; then dry_run=1; else args+=("$a"); fi
done
set -- "${args[@]}"
cmd="${1:-status}"
shift || true
selected=("$@")
[[ ${#selected[@]} -eq 0 ]] && selected=("${names[@]}")

do_run() {
  if [[ "$dry_run" == "1" ]]; then
    echo "[DRY-RUN] $*"
  else
    "$@"
  fi
}

running() {
  local pidfile="$vm_dir/$1/qemu.pid"
  [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null
}

seed() {
  local name="$1" dir="$vm_dir/$1"
  cat > "$dir/user-data" <<DATA
#cloud-config
hostname: lab-$name
disable_root: false
ssh_pwauth: false
ssh_authorized_keys:
  - $(cat "$key")
bootcmd:
  - [sh, -c, "systemctl enable sshd.service 2>/dev/null; systemctl start --no-block sshd.service 2>/dev/null; true"]
DATA
  printf 'instance-id: farol-%s\nlocal-hostname: lab-%s\n' "$name" "$name" > "$dir/meta-data"
  xorriso -as mkisofs -quiet -output "$dir/seed.iso" -volid cidata -joliet -rock "$dir/user-data" "$dir/meta-data" 2>/dev/null
}

up() {
  local name="$1" dir="$vm_dir/$1" base
  base="$vm_dir/images/$(basename "${url[$name]}")"
  if running "$name"; then
    echo "$name already running on 127.0.0.1:${port[$name]}"
    return
  fi
  do_run mkdir -p "$dir" "$vm_dir/images"
  if [[ ! -f "$base" ]]; then
    do_run curl -fL --retry 3 -o "$base.part" "${url[$name]}"
    do_run mv "$base.part" "$base"
  fi
  if [[ ! -f "$dir/disk.qcow2" ]]; then
    do_run qemu-img create -q -f qcow2 -b "$base" -F qcow2 "$dir/disk.qcow2" 20G
  fi
  if [[ "$dry_run" == "1" ]]; then
    echo "[DRY-RUN] write cloud-init seed $dir/seed.iso"
  else
    seed "$name"
  fi
  do_run qemu-system-x86_64 -name "farol-$name" -enable-kvm -cpu host -m 2048 -smp 2 \
    -drive "file=$dir/disk.qcow2,if=virtio" -drive "file=$dir/seed.iso,media=cdrom" \
    -nic "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:${port[$name]}-:22" \
    -device "vhost-vsock-pci,guest-cid=$((port[$name] - 2298))" \
    -display none -daemonize -pidfile "$dir/qemu.pid" -serial "file:$dir/console.log"
  echo "$name booting on 127.0.0.1:${port[$name]}"
}

down() {
  local name="$1"
  if running "$name"; then
    do_run kill "$(cat "$vm_dir/$name/qemu.pid")"
    echo "$name stopped"
  fi
}

inventory() {
  {
    printf 'defaults:\n  user: root\n  identity: .cache/lab/id_ed25519\n\ngroups:\n  vm:\n    hosts:\n'
    for n in "${names[@]}"; do
      printf '      - name: vm-%s\n        address: 127.0.0.1\n        port: %s\n' "$n" "${port[$n]}"
    done
  } > "$root_dir/test/vm/inventory.yaml"
}

if [[ ! -f "$key" && "$cmd" == "up" ]]; then
  echo "lab key not found: run test/lab/setup.sh first" >&2
  exit 1
fi

case "$cmd" in
  up)
    for n in "${selected[@]}"; do up "$n"; done
    [[ "$dry_run" == "1" ]] || inventory
    ;;
  down)
    for n in "${selected[@]}"; do down "$n"; done
    ;;
  reset)
    for n in "${selected[@]}"; do
      down "$n"
      do_run rm -f "$vm_dir/$n/disk.qcow2" "$vm_dir/$n/seed.iso"
    done
    ;;
  status)
    for n in "${names[@]}"; do
      if running "$n"; then echo "$n running 127.0.0.1:${port[$n]}"; else echo "$n stopped"; fi
    done
    ;;
  *) echo "unknown command: $cmd" >&2; exit 2 ;;
esac
