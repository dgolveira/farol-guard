# Hosting farol-guard

`farol ui` is built to run on your workstation and listen on `127.0.0.1`. This
guide covers what changes when you run it somewhere else (a server, Docker,
Kubernetes) and how to put real authentication in front of it.

farol-guard does **not** ship a login screen. Access control is delegated to a
reverse proxy you already trust. A built-in login is welcome as a contribution,
see [Contributing a built-in login](#contributing-a-built-in-login).

## Read this first

The dashboard can run checks and **write SSH keys to every host in the
inventory**, usually as root. Whoever reaches the dashboard effectively holds
that power. Treat it like the console of a bastion host.

What farol-guard enforces on its own:

| Control | Behavior |
| --- | --- |
| Session token | The first request must carry `?token=...`; it becomes an `HttpOnly`, `SameSite=Strict` cookie. Without it every request gets `401`. |
| Host header check | Only `localhost`, IP literals and hosts passed with `--allowed-host` are accepted (blocks DNS rebinding). |
| CSRF | Every state-changing request needs the `X-Farol-Request: 1` header and a same-origin `Origin`. |
| Security headers | `Content-Security-Policy` without inline scripts, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`. |

What it does **not** do: user accounts, passwords, MFA, TLS, audit of who
clicked what. That is the job of the proxy in front of it.

## Option 1: SSH tunnel (simplest, nothing exposed)

Run farol-guard on the server bound to loopback and reach it through SSH:

```bash
# on the server
FAROL_GUARD_TOKEN="$(openssl rand -hex 24)" farol ui --no-open

# on your workstation
ssh -N -L 7380:127.0.0.1:7380 you@server
# open http://127.0.0.1:7380/?token=<token printed on the server>
```

Authentication is your SSH login. No port is opened, no proxy is needed.

## Option 2: Docker Compose with Caddy (TLS + basic auth)

`deploy/docker/` contains a compose file with an optional `proxy` profile that
puts [Caddy](https://caddyserver.com) in front of farol-guard. Caddy gets a TLS
certificate automatically and asks for a username and password.

```bash
cd deploy/docker
cp .env.example .env
# edit .env: FAROL_GUARD_TOKEN, FAROL_GUARD_DOMAIN, FAROL_GUARD_APP_PASSPHRASE
docker run --rm docker.io/library/caddy:2.8.4 caddy hash-password --plaintext 'a-long-password'
# put the hash and the user name in .env (FAROL_GUARD_BASIC_USER / FAROL_GUARD_BASIC_HASH)
docker compose --profile proxy up -d
```

Then open `https://<domain>/?token=<FAROL_GUARD_TOKEN>` once; the browser keeps
the session cookie. Notes:

- The farol-guard container only publishes `127.0.0.1:7380`; Caddy is the only
  public entry point (ports 80/443).
- `FAROL_GUARD_ALLOWED_HOSTS` must contain the public domain, otherwise
  farol-guard rejects the requests with `403 forbidden host`.
- Basic auth is a single shared credential. For per-person accounts and MFA,
  use Option 3 or Caddy with an identity provider plugin.

## Option 3: Kubernetes with ingress-nginx and oauth2-proxy

`deploy/kubernetes/` contains example manifests:

- `farol-guard.yaml`: Namespace, Secret, PersistentVolumeClaim, Deployment,
  Service and Ingress.
- `oauth2-proxy.yaml`: oauth2-proxy configured for an OpenID Connect provider
  (Google, GitHub, Keycloak, Entra ID...).

The Ingress uses the ingress-nginx external auth annotations, so every request
is authenticated by oauth2-proxy before it reaches farol-guard:

```yaml
nginx.ingress.kubernetes.io/auth-url: "https://$host/oauth2/auth"
nginx.ingress.kubernetes.io/auth-signin: "https://$host/oauth2/start?rd=$escaped_request_uri"
```

Steps:

1. Create an OAuth application in your provider with the callback
   `https://<domain>/oauth2/callback`.
2. Fill the placeholders in both files (domain, client id/secret, cookie secret,
   allowed e-mail domain or GitHub org).
3. Put the SSH material in the `farol-guard-ssh` Secret (see below).
4. `kubectl apply -f deploy/kubernetes/`
5. Log in through the provider, then open `https://<domain>/?token=<token>` once.

Restrict who can log in (`--email-domain`, `--github-org`, or an allow list).
Anyone who passes oauth2-proxy and knows the token controls the fleet.

## SSH material outside a desktop

There is no system keyring in a container or on a headless server. Provide the
pieces explicitly:

| What | How |
| --- | --- |
| Private key used to log in | Mount it read-only (`~/.ssh` in Docker, a Secret in Kubernetes) and point `identity:` in the inventory to it. |
| App key passphrase | `FAROL_GUARD_APP_PASSPHRASE` environment variable, or a systemd credential named `farol-app-passphrase` (`$CREDENTIALS_DIRECTORY`). |
| Known hosts | `FAROL_GUARD_KNOWN_HOSTS=/config/known_hosts`, kept on a persistent volume. Pre-populate it with `ssh-keyscan` and review the fingerprints. |
| Inventory and history | Persistent volumes for `/config` and `/data`. |

If no passphrase source exists, a new app key is created **without** a
passphrase and the dashboard says so. Do not run it like that on a shared host.

### Scheduled checks with systemd

The user timer shipped in the `.deb` (`farol-guard-check.timer`) unlocks the app
key through the desktop keyring, which is only available while you are logged
in. On a server, store the passphrase as an encrypted credential instead:

```bash
systemd-ask-password -n | systemd-creds encrypt --user --name=farol-app-passphrase - ~/.config/farol-guard/app-passphrase.cred
systemctl --user edit farol-guard-check.service
# [Service]
# LoadCredentialEncrypted=farol-app-passphrase:%h/.config/farol-guard/app-passphrase.cred
```

## Hardening checklist

- Restrict the app key on the servers with `from="<address of the farol host>"`
  (field "Restrict to source IPs/CIDRs" when installing it).
- Keep `FAROL_GUARD_TOKEN` long and random (`openssl rand -hex 24`) and store it
  as a secret, not in the compose file or the image.
- Never publish port 7380 directly; expose only the proxy.
- Limit the proxy to known users (e-mail domain, organization, allow list) and
  enable MFA in the identity provider.
- Use the dry-run option before key operations, and keep the activity log.
- Back up `/config` (inventory, keys) and protect the backup like a password
  vault.

## Contributing a built-in login

Pull requests that add an optional built-in login are welcome. Expected shape:

- Off by default; local use keeps the current token flow.
- Passwords hashed with bcrypt or argon2id, never stored or logged in clear.
- Server-side sessions with expiry and logout, cookie `HttpOnly`,
  `SameSite=Strict`, `Secure` when served over TLS.
- Progressive delay or lockout after failed attempts, per user and per source
  address.
- A CLI command to create and reset users without editing files by hand.
- Tests for the authentication middleware and the rate limiting.
