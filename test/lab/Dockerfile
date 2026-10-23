ARG BASE=docker.io/library/debian:12
FROM ${BASE}
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server sudo iproute2 procps \
 && mkdir -p /run/sshd \
 && useradd -m -s /bin/bash deploy \
 && echo 'deploy ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/deploy \
 && chmod 0440 /etc/sudoers.d/deploy
COPY entrypoint.sh /entrypoint.sh
CMD ["/entrypoint.sh"]
