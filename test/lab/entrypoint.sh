#!/bin/bash
# -----------------------------------------------------------------------------
# Script Name: entrypoint.sh
# Description: Lab container entrypoint. Installs /lab/authorized_keys for root
#              and the "deploy" user, then runs sshd in the foreground logging
#              to /var/log/auth.log so farol-guard can parse SSH access.
# Author:      Douglas Oliveira <contato@dgoliveira.com.br>
# Role:        Infrastructure Analyst
# Created:     2026-10-23
# -----------------------------------------------------------------------------
set -e

for home in /root /home/deploy; do
  mkdir -p "$home/.ssh"
  cp /lab/authorized_keys "$home/.ssh/authorized_keys"
  chmod 700 "$home/.ssh"
  chmod 600 "$home/.ssh/authorized_keys"
done
chown -R deploy:deploy /home/deploy/.ssh

if [[ "${LAB_WEAK_SSHD:-0}" == "1" ]]; then
  printf 'PermitRootLogin yes\nPasswordAuthentication yes\nX11Forwarding yes\n' > /etc/ssh/sshd_config.d/00-lab-weak.conf
fi

ssh-keygen -A >/dev/null
exec /usr/sbin/sshd -D -E /var/log/auth.log
