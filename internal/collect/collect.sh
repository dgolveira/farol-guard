#!/bin/bash
# -----------------------------------------------------------------------------
# Script Name: collect.sh
# Description: Read-only collector executed by farol-guard on each audited host
#              through SSH (bash -s). Prints sections delimited by
#              "@@farol:<name>" markers that the Go side parses.
#              Never modifies the host, except "apt-get update" when
#              FAROL_APT_UPDATE=1 is prepended by "farol check --refresh".
# Author:      Douglas Oliveira <contato@dgoliveira.com.br>
# Role:        Infrastructure Analyst
# Created:     2026-10-23
# -----------------------------------------------------------------------------

export LC_ALL=C
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

section() { printf '\n@@farol:%s\n' "$1"; }
has() { command -v "$1" >/dev/null 2>&1; }

section meta
echo "uid=$(id -u)"
echo "hostname=$(hostname -f 2>/dev/null || hostname)"

section os_release
cat /etc/os-release 2>/dev/null

section kernel
uname -r

section uptime
cut -d' ' -f1 /proc/uptime

section passwd
getent passwd

section group
getent group

section shadow
if [[ -r /etc/shadow ]]; then
  awk -F: '{s="password"; if ($2 == "") s="empty"; else if ($2 ~ /^[!*]/) s="locked"; print $1 ":" s}' /etc/shadow
fi

section sudoers
if [[ -r /etc/sudoers ]]; then
  grep -hE '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d/* 2>/dev/null
fi

section authorized_keys
declare -A seen_files
while IFS=: read -r user _ _ _ _ home _; do
  for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
    [[ -r "$f" ]] || continue
    real="$(readlink -f "$f")"
    [[ -n "${seen_files[$real]:-}" ]] && continue
    seen_files[$real]=1
    while IFS= read -r line || [[ -n "$line" ]]; do
      [[ -z "${line// /}" || "$line" == \#* ]] && continue
      printf '%s\t%s\t%s\n' "$user" "$f" "$line"
    done < "$f"
  done
done < <(getent passwd)

section sshd_effective
if has sshd; then
  sshd -T 2>/dev/null
fi

section sshd_file
cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null

section ssh_version
ssh -V 2>&1 | head -1

if [[ "${FAROL_APT_UPDATE:-0}" == "1" && "$(id -u)" == "0" ]]; then
  section apt_update
  timeout 180 apt-get update -qq >/dev/null 2>&1
fi

section packages
dpkg-query -W -f='${db:Status-Abbrev}\t${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n' 2>/dev/null

section apt_lists_mtime
find /var/lib/apt/lists -maxdepth 1 -type f -name '*Release' -printf '%T@\n' 2>/dev/null | sort -n | tail -1
date +%s

section upgradable
apt list --upgradable 2>/dev/null | grep -v '^Listing'

section reboot_required
if [[ -f /var/run/reboot-required ]]; then
  echo "yes"
  cat /var/run/reboot-required.pkgs 2>/dev/null
fi

section unattended
dpkg-query -W -f='${db:Status-Abbrev}\n' unattended-upgrades 2>/dev/null
apt-config dump APT::Periodic::Unattended-Upgrade 2>/dev/null

section snaps
if has snap; then
  snap list 2>/dev/null | tail -n +2
fi

section containers
if has docker; then
  timeout 15 docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.Status}}' 2>/dev/null
fi

section services
systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print $1}'

section failed_units
systemctl list-units --state=failed --no-legend --plain 2>/dev/null | awk '{print $1}'

section listening
ss -H -tulpn 2>/dev/null

section sshd_log
out=""
if has journalctl; then
  out="$(journalctl -q --no-pager -o short-iso --since '-14 days' -t sshd -t sshd-session 2>/dev/null \
    | grep -E 'Accepted |Failed |Invalid user ' | tail -n 5000)"
fi
if [[ -n "$out" ]]; then
  printf '%s\n' "$out"
else
  for f in /var/log/auth.log.1 /var/log/auth.log; do
    [[ -r "$f" ]] && grep -hE '(Accepted (publickey|password|keyboard-interactive)|Failed (password|publickey|none)|Invalid user ) ' "$f"
  done | tail -n 5000
fi

section last
last -i -w -n 50 2>/dev/null | grep -vE '^(wtmp|$)'

section fail2ban
if has fail2ban-client; then
  fail2ban-client status 2>/dev/null
fi

section firewall
if has ufw; then
  ufw status 2>/dev/null | head -1
fi
if has nft; then
  echo "nft_rules=$(nft list ruleset 2>/dev/null | grep -cE '^\s+(ip|ip6|tcp|udp|iif|oif|ct|meta|counter|accept|drop|reject|jump)')"
fi
if has iptables; then
  echo "iptables_rules=$(iptables -S 2>/dev/null | grep -vc '^-P')"
fi

section time_sync
timedatectl show -p NTPSynchronized --value 2>/dev/null

section kernel_errors
if has journalctl; then
  journalctl -q --no-pager -k -p err --since '-24 hours' -o short-iso 2>/dev/null | tail -n 200
else
  dmesg -T --level=emerg,alert,crit,err 2>/dev/null | tail -n 200
fi

section ip_addr
ip -br addr 2>/dev/null

section net_dev
cat /proc/net/dev

section df
df -P -B1 -T -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs 2>/dev/null

section df_inodes
df -P -i -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs 2>/dev/null

section meminfo
cat /proc/meminfo

section loadavg
cat /proc/loadavg
nproc

section cpu_stat
head -1 /proc/stat
sleep 1
head -1 /proc/stat

section end
