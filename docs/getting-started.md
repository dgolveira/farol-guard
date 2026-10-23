# Getting started

## How farol-guard reaches your servers

farol-guard is **agentless** and **public-key only**:

- Nothing is installed on the servers. Every check opens an SSH session, runs a
  read-only collector through `bash -s` and disconnects.
- Authentication is always an SSH key: a key loaded in your `ssh-agent`, a key
  file referenced in the inventory, or the dedicated app key. **Password login
  is not supported** and farol-guard never stores SSH passwords.
- For a complete audit the login user must be `root` or have passwordless
  `sudo` (`sudo -n`). Without it the check still runs, but users of other
  accounts, `/etc/shadow`, the effective `sshd` configuration and
  `apt-get update` are skipped and the report marks the collection as limited.
- Host keys are verified against `known_hosts`. Unknown hosts must be trusted
  explicitly (dashboard, interactive prompt or `--accept-new`).

This means **someone has to grant the first access**: a public key must already
be authorized on each server, for a user that is root or can use `sudo` without
a password. There are two ways to do that.

## Path A: use the key you already have

If your personal key already logs in as `root` (or as a sudoer) on the servers,
you are done:

```bash
farol init                      # creates ~/.config/farol-guard/inventory.yaml
$EDITOR ~/.config/farol-guard/inventory.yaml
farol check                     # or: farol open
```

`farol open` (also the **farol-guard** icon in the applications menu when the
`.deb` is installed) starts the dashboard in the background if needed and opens
it: as an app window when the default browser is Chromium based (Edge, Chrome,
Chromium, Brave...), otherwise in a normal tab. Closing the window, or closing
every dashboard tab for about 20 seconds, stops the dashboard. `farol stop` stops it; `farol ui` runs it in the foreground. The
session token is kept in `~/.config/farol-guard/ui-token`, so the address does
not change between restarts.

`defaults.identity` points to the private key to use (`~/.ssh/id_ed25519` by
default). If the key has a passphrase, load it in `ssh-agent` first
(`ssh-add`); farol-guard asks for it only when it is not in the agent.

From there you can let farol-guard install its own key (Keys, "Install app
key", or `farol keys app-init -g <group>`), verify it and make it the default
identity, so scheduled checks do not depend on your personal key.

## Path B: prepare the access manually

Use this when you do not want your personal key involved, when the servers are
managed by someone else, or when policy requires a dedicated, restricted user.

**1. Create the app key locally** (no server is contacted):

```bash
farol keys app-init --create-only --from 203.0.113.10
```

It prints the exact line to add to `authorized_keys`, already restricted:

```text
restrict,from="203.0.113.10" ssh-ed25519 AAAA... farol-guard:app:<installation-id>@<host> <date>
```

- `restrict` disables port, agent and X11 forwarding, PTY allocation and
  `~/.ssh/rc`. farol-guard needs none of them.
- `from=` limits the key to the address farol-guard runs from. Omit `--from` if
  that address is not fixed.
- Print the line again at any time with `farol keys pub farol-app --from <ip>`.

**2. On each server, as root, create a dedicated user** and authorize the key:

```bash
useradd --create-home --shell /bin/bash farol
install -d -m 700 -o farol -g farol /home/farol/.ssh
printf '%s\n' 'restrict,from="203.0.113.10" ssh-ed25519 AAAA... farol-guard:app:...' > /home/farol/.ssh/authorized_keys
chown farol:farol /home/farol/.ssh/authorized_keys
chmod 600 /home/farol/.ssh/authorized_keys
```

**3. Give it passwordless sudo** (needed for a complete audit and for key
management on other accounts):

```bash
printf 'farol ALL=(root) NOPASSWD: ALL\n' > /etc/sudoers.d/farol
chmod 440 /etc/sudoers.d/farol
visudo -cf /etc/sudoers.d/farol
```

Skip this step for a read-only, limited audit.

**4. Point the inventory to the user and the app key:**

```yaml
defaults:
  user: farol
  port: 22
  identity: ~/.config/farol-guard/keys/farol-app
```

**5. Trust the host keys and run the first check:**

```bash
farol check            # interactive: confirms each unknown host key
# or open farol ui and use "Review and trust"
```

## Inventory

```yaml
defaults:
  user: root
  port: 22
  identity: ~/.ssh/id_ed25519

known_keys:                 # fingerprints you recognize; others are reported
  - name: ops-laptop
    fingerprint: SHA256:...

groups:
  production:
    hosts:
      - name: web01
        address: 203.0.113.10
      - name: db01
        address: 203.0.113.20
        port: 2222
        tags: [database]
  lab:
    user: ubuntu            # group-level override
    hosts:
      - name: lab01
        address: 192.0.2.50
```

Settings cascade `defaults -> group -> host`. The dashboard edits the same file
(a backup is kept as `inventory.yaml.bak`).

## Supported systems

| Target | Status |
| --- | --- |
| Debian 10 to 13 | supported |
| Ubuntu 18.04 to 26.04 (LTS and interim) | supported |
| Other Linux distributions | collection works partially; updates and CVEs are not evaluated |

The machine running farol-guard can be any Linux (amd64 or arm64). The `.deb`
targets Debian and Ubuntu; a container image is also available.
