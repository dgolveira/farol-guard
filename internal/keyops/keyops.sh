#!/bin/bash
# -----------------------------------------------------------------------------
# Script Name: keyops.sh
# Description: Remote helper used by farol-guard key management through SSH
#              (bash -s -- <action> <user>). All key logic runs locally in Go;
#              this script only reads or atomically replaces a user's
#              ~/.ssh/authorized_keys, keeping a timestamped backup.
# Author:      Douglas Oliveira <contato@dgoliveira.com.br>
# Role:        Infrastructure Analyst
# Created:     2026-10-23
#
# Actions:
#   read  <user>   Print "@@path <file>" followed by the file contents
#   write <user>   Replace the file with base64 content from FAROL_CONTENT_B64
# -----------------------------------------------------------------------------
set -e
export LC_ALL=C

action="$1"
target_user="$2"

home="$(getent passwd "$target_user" | cut -d: -f6)"
if [[ -z "$home" ]]; then
  echo "@@error user $target_user not found"
  exit 3
fi
file="$home/.ssh/authorized_keys"

case "$action" in
  read)
    echo "@@path $file"
    if [[ -f "$file" ]]; then
      cat "$file"
    fi
    ;;
  write)
    group="$(id -gn "$target_user")"
    install -d -m 700 -o "$target_user" -g "$group" "$home/.ssh"
    if [[ -f "$file" ]]; then
      backup="$file.farol-$(date +%Y%m%d%H%M%S%N)"
      cp -p "$file" "$backup"
      echo "@@backup $backup"
    fi
    tmp="$(mktemp "$home/.ssh/.authorized_keys.XXXXXX")"
    printf '%s' "${FAROL_CONTENT_B64:-}" | base64 -d > "$tmp"
    chown "$target_user:$group" "$tmp"
    chmod 600 "$tmp"
    mv -f "$tmp" "$file"
    echo "@@written $file"
    ;;
  *)
    echo "@@error unknown action $action"
    exit 2
    ;;
esac
