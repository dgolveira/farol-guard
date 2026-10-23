#!/bin/bash
# -----------------------------------------------------------------------------
# Script Name: setup.sh
# Description: Creates the farol-guard development lab: a throwaway SSH key in
#              .cache/lab, a lab inventory (test/lab/inventory.yaml) and the
#              Debian/Ubuntu sshd containers from docker-compose.yml.
# Author:      Douglas Oliveira <contato@dgoliveira.com.br>
# Role:        Infrastructure Analyst
# Created:     2026-10-23
#
# Usage:       test/lab/setup.sh [--down]
#   --down     Stop and remove the lab containers
# -----------------------------------------------------------------------------
set -e

lab_dir="$(cd "$(dirname "$0")" && pwd)"
cache_dir="$lab_dir/../../.cache/lab"

if [[ "${1:-}" == "--down" ]]; then
  docker compose -f "$lab_dir/docker-compose.yml" down
  exit 0
fi

mkdir -p "$cache_dir"
if [[ ! -f "$cache_dir/id_ed25519" ]]; then
  ssh-keygen -q -t ed25519 -N '' -C farol-lab -f "$cache_dir/id_ed25519"
fi
cp "$cache_dir/id_ed25519.pub" "$cache_dir/authorized_keys"
fingerprint="$(ssh-keygen -lf "$cache_dir/id_ed25519.pub" | awk '{print $2}')"

cat > "$lab_dir/inventory.yaml" <<YAML
defaults:
  user: root
  identity: .cache/lab/id_ed25519

known_keys:
  - name: farol-lab
    fingerprint: $fingerprint

groups:
  lab-debian:
    hosts:
      - name: debian12
        address: 127.0.0.1
        port: 2201
  lab-ubuntu:
    hosts:
      - name: ubuntu2404
        address: 127.0.0.1
        port: 2202
      - name: ubuntu2204
        address: 127.0.0.1
        port: 2203
        user: deploy
      - name: offline01
        address: 127.0.0.1
        port: 2299
YAML

docker compose -f "$lab_dir/docker-compose.yml" up -d --build
