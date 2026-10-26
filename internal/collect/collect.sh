#!/bin/bash
# -----------------------------------------------------------------------------
# Script Name: collect.sh
# Description: Read-only collector executed by farol-guard on each audited host
#              through SSH (bash -s). Prints sections delimited by
#              "@@farol:<name>" markers that the Go side parses.
#              Supports dpkg (Debian/Ubuntu and derivatives), rpm with
#              dnf/yum (RHEL family, Fedora, Amazon Linux) and pacman (Arch
#              family). Never modifies the host, except refreshing package
#              metadata (apt-get update / dnf makecache) when FAROL_REFRESH=1
#              is prepended by "farol check --refresh".
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

refresh="${FAROL_REFRESH:-${FAROL_APT_UPDATE:-0}}"

if has dpkg-query; then
  pkg_family=deb
elif has zypper; then
  pkg_family=suse
elif has rpm && { has dnf || has yum; }; then
  pkg_family=rpm
elif has pacman; then
  pkg_family=arch
else
  pkg_family=unknown
fi
dnf_bin=dnf
has dnf || dnf_bin=yum

section pkg_family
echo "$pkg_family"
case "$pkg_family" in
  rpm) echo "$dnf_bin" ;;
  suse) echo zypper ;;
esac

if [[ "$refresh" == "1" && "$(id -u)" == "0" ]]; then
  section refresh
  case "$pkg_family" in
    deb) timeout 180 apt-get update -qq >/dev/null 2>&1 ;;
    rpm) timeout 300 "$dnf_bin" -q makecache >/dev/null 2>&1 ;;
    suse) timeout 300 zypper -n -q refresh >/dev/null 2>&1 ;;
  esac
fi

case "$pkg_family" in
deb)
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
  ;;
rpm)
  section packages_rpm
  rpm -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{SOURCERPM}\t%{ARCH}\n' 2>/dev/null

  section apt_lists_mtime
  find /var/cache/dnf /var/cache/libdnf5 /var/cache/yum \( -name repomd.xml -o -name cachecookie \) -printf '%T@\n' 2>/dev/null | sort -n | tail -1
  date +%s

  section upgradable_rpm
  timeout 120 "$dnf_bin" -q -C check-update 2>/dev/null

  section security_rpm
  if [[ "$dnf_bin" == "yum" ]]; then
    timeout 120 yum -q -C updateinfo list cves 2>/dev/null
    echo "@@advisories"
    timeout 120 yum -q -C updateinfo list security 2>/dev/null
  elif "$dnf_bin" --version 2>/dev/null | grep -q '^dnf5'; then
    timeout 120 "$dnf_bin" -q -C advisory list --security --with-cve 2>/dev/null
    echo "@@advisories"
    timeout 120 "$dnf_bin" -q -C advisory list --security 2>/dev/null
  else
    timeout 120 "$dnf_bin" -q -C updateinfo list --security --with-cve 2>/dev/null
    echo "@@advisories"
    timeout 120 "$dnf_bin" -q -C updateinfo list --security 2>/dev/null
  fi

  section reboot_required
  if has needs-restarting; then
    needs-restarting -r >/dev/null 2>&1
    [[ $? -eq 1 ]] && echo "yes"
  elif [[ -d /lib/modules && ! -d "/lib/modules/$(uname -r)" ]] && ls /lib/modules/*/vmlinuz >/dev/null 2>&1; then
    echo "yes"
  fi

  section unattended_rpm
  for t in dnf-automatic.timer dnf-automatic-install.timer dnf5-automatic.timer; do
    systemctl is-enabled "$t" 2>/dev/null | grep -qx enabled && echo "$t"
  done
  ;;
suse)
  section packages_rpm
  rpm -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{SOURCERPM}\t%{ARCH}\n' 2>/dev/null

  section apt_lists_mtime
  find /var/cache/zypp/raw -name repomd.xml -printf '%T@\n' 2>/dev/null | sort -n | tail -1
  date +%s

  section upgradable_suse
  timeout 120 zypper -n --no-refresh --xmlout list-updates -t package 2>/dev/null | grep -o '<update kind="package"[^>]*>'

  section patches_suse
  timeout 120 zypper -n --no-refresh --xmlout list-patches 2>/dev/null | grep -o '<update kind="patch"[^>]*>\(<summary>[^<]*</summary>\)\?'

  section reboot_required
  zypper -n needs-rebooting >/dev/null 2>&1
  [[ $? -eq 102 ]] && echo "yes"

  section unattended_rpm
  for t in transactional-update.timer os-update.timer; do
    systemctl is-enabled "$t" 2>/dev/null | grep -qx enabled && echo "$t"
  done
  ;;
arch)
  section packages_arch
  pacman -Q 2>/dev/null

  section apt_lists_mtime
  find /var/lib/pacman/sync -maxdepth 1 -name '*.db' -printf '%T@\n' 2>/dev/null | sort -n | tail -1
  date +%s

  section upgradable_arch
  if [[ "$refresh" == "1" ]] && has checkupdates; then
    timeout 180 checkupdates 2>/dev/null
  else
    pacman -Qu 2>/dev/null
  fi

  section reboot_required
  if [[ -d /usr/lib/modules ]] && ls /usr/lib/modules/*/vmlinuz >/dev/null 2>&1 && [[ ! -d "/usr/lib/modules/$(uname -r)" ]]; then
    echo "yes"
  fi
  ;;
esac

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
  for f in /var/log/auth.log.1 /var/log/auth.log /var/log/secure-* /var/log/secure; do
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
if has firewall-cmd; then
  echo "firewalld=$(firewall-cmd --state 2>/dev/null || echo 'not running')"
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
