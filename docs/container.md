# Container image

The image is published on GitHub Container Registry:
`ghcr.io/dgolveira/farol-guard` (public, no login needed to pull).

- Platforms: `linux/amd64`, `linux/arm64`
- Base image: `gcr.io/distroless/static-debian12:nonroot` (single static binary, no shell)

## Tags

| Tag | Content |
| --- | --- |
| `<version>` (e.g. `1.0.0`) | a release |
| `latest` | the most recent release |

Use the version tag in production. Images up to `0.2.1` were also pushed to
Docker Hub (`dgzin01/farol-guard`); that location is no longer updated.

## Quick start

```bash
docker run --rm ghcr.io/dgolveira/farol-guard:1.1.0 version
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
  ghcr.io/dgolveira/farol-guard:1.1.0 ui --no-open --listen 0.0.0.0:7380

docker logs farol-guard    # prints the URL with the session token
```

One-off audit that writes a report:

```bash
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/config:/config" -v "$PWD/data:/data" \
  -v "$HOME/.ssh:/home/farol/.ssh:ro" \
  ghcr.io/dgolveira/farol-guard:1.1.0 check -o /data/report.html
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
