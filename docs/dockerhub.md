# farol-guard

Agentless SSH auditor for Debian and Ubuntu server fleets: users, keys, sshd,
updates, CVEs and resources, with a local dashboard and safe SSH key rotation.

- Source, documentation and issues: <https://github.com/dgolveira/farol-guard>
- License: MIT
- Platforms: `linux/amd64`, `linux/arm64`
- Base image: `gcr.io/distroless/static-debian12:nonroot` (single static binary, no shell)

## Tags

| Tag | Content |
| --- | --- |
| `0.2.1`, `latest` | current release |

Use the version tag in production. `0.2.0` is not published here; it was built
with vulnerable Go and `x/crypto` versions.

## Quick start

```bash
docker run --rm docker.io/dgzin01/farol-guard:0.2.1 version
```

Run the dashboard with your inventory, state and SSH key mounted:

```bash
mkdir -p config/farol-guard data
cp inventory.yaml config/farol-guard/inventory.yaml

docker run -d --name farol-guard \
  --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:7380:7380 \
  -e FAROL_GUARD_TOKEN="$(openssl rand -hex 24)" \
  -e FAROL_GUARD_APP_PASSPHRASE="$(openssl rand -base64 32)" \
  -v "$PWD/config:/config" \
  -v "$PWD/data:/data" \
  -v "$HOME/.ssh:/home/farol/.ssh:ro" \
  docker.io/dgzin01/farol-guard:0.2.1 ui --no-open --listen 0.0.0.0:7380

docker logs farol-guard    # prints the URL with the session token
```

One-off audit that writes a report:

```bash
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/config:/config" -v "$PWD/data:/data" \
  -v "$HOME/.ssh:/home/farol/.ssh:ro" \
  docker.io/dgzin01/farol-guard:0.2.1 check -o /data/report.html
```

## Volumes and paths

| Path | Content |
| --- | --- |
| `/config` | `farol-guard/inventory.yaml`, generated keys, `known_hosts` |
| `/data` | report history, CVE cache |
| `/home/farol/.ssh` | private key used to log in to the hosts (read-only) |

## Environment

| Variable | Purpose |
| --- | --- |
| `FAROL_GUARD_TOKEN` | fixed dashboard session token (otherwise random on every start) |
| `FAROL_GUARD_APP_PASSPHRASE` | passphrase that protects the app key (no system keyring in containers) |
| `FAROL_GUARD_ALLOWED_HOSTS` | extra `Host` headers accepted, e.g. the domain of a reverse proxy |
| `FAROL_GUARD_KNOWN_HOSTS` | known_hosts file (default `/config/known_hosts`) |

## Security notes

- farol-guard only uses SSH public keys; the login user must be root or have
  passwordless sudo for a complete audit.
- The dashboard controls SSH keys on every host in the inventory. Publish it
  only on `127.0.0.1` or behind an authenticating proxy; see the hosting guide:
  <https://github.com/dgolveira/farol-guard/blob/main/docs/hosting.md>
- Report vulnerabilities privately:
  <https://github.com/dgolveira/farol-guard/security/advisories/new>
