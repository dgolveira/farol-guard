# Security policy

## Supported versions

Security fixes are released for the latest minor version.

| Version | Supported |
| --- | --- |
| 0.2.1 and later | yes |
| 0.2.0 | no (built with vulnerable Go and x/crypto versions, upgrade) |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

- Preferred: open a private report with GitHub
  [security advisories](https://github.com/dgolveira/farol-guard/security/advisories/new).
- Or e-mail **contato@dgoliveira.com.br** with the subject `farol-guard security`.

Include the version (`farol version`), how to reproduce, and the impact you
expect. You should receive an answer within 5 business days. Please give a
reasonable time for a fix before public disclosure; credit is given in the
release notes unless you prefer otherwise.

## Scope

In scope:

- Key generation, storage and handling (`internal/keys`, `internal/keyops`).
- The remote collector and helper scripts executed on the servers.
- The dashboard HTTP API: authentication token, Host header check, CSRF
  protection, path handling.
- Anything that could let a third party reach a server through farol-guard.

Out of scope: vulnerabilities in the audited servers themselves, findings that
require an attacker already running code as the farol-guard user, and missing
hardening of deployments that ignore [docs/hosting.md](docs/hosting.md).

## Design notes

The security model is documented in [docs/keys.md](docs/keys.md). In short:
keys and secrets come only from `crypto/rand` (enforced by a test), there are
no default or embedded credentials, the app key is encrypted with a passphrase
kept in the system keyring, and the dashboard is meant to listen on loopback
or behind an authenticating proxy.
