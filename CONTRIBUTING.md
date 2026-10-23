# Contributing to farol-guard

Thank you for helping. Bug reports, documentation fixes and pull requests are
all welcome.

## Before you start

- Search the existing issues first. For larger changes, open an issue to agree
  on the approach before writing code.
- Security problems go through [SECURITY.md](SECURITY.md), never public issues.
- By contributing you agree that your work is licensed under the
  [MIT License](LICENSE).

## Development setup

See [docs/development.md](docs/development.md). In short:

```bash
make test
make vet
test/lab/setup.sh        # local Debian/Ubuntu sshd containers
```

Never test key operations against servers you do not own; use the lab.

## Pull requests

- One topic per pull request, with a clear description of what and why.
- Add or update tests for behavior changes; `make test` and `make vet` must pass.
- Keep user-facing strings in `internal/i18n` with both English and Brazilian
  Portuguese entries.
- Code, comments, commits and docs in English. No emojis.
- Do not add dependencies without discussing them first.
- Update `CHANGELOG.md` under `Unreleased`.

## Commit messages

Use the imperative mood and explain the reason when it is not obvious:

```text
Skip hosts with pending host keys on scheduled checks

Aborted handshakes are counted as attacks by sshguard and fail2ban.
```

## Ideas that would be welcome

- An optional built-in login for hosted deployments (see [docs/hosting.md](docs/hosting.md#contributing-a-built-in-login)).
- Support for RPM based distributions (dnf/yum updates and OSV ecosystems).
- More languages in `internal/i18n`.
