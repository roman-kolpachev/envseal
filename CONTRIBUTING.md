# Contributing to envseal

## Prerequisites

- Go 1.25.8+ (earlier 1.25.x releases are affected by [GO-2026-4602](https://pkg.go.dev/vuln/GO-2026-4602), fixed in 1.25.8)
- Git
- (Optional) `sops` binary — only needed to test `import --from-sops`

## Setup

```bash
git clone https://github.com/roman-kolpachev/envseal.git
cd envseal
go mod download
```

## Build

```bash
go build -o envseal .
```

## Test

```bash
go test ./...
```

## Install (development binary)

```bash
go install .
```

## Project Structure

```
cmd/              CLI commands (thin wrappers, no business logic)
internal/
  audit/          Append-only JSON Lines audit log
  config/         TOML config management (.envseal/config.toml), path constants
  crypto/         age encryption/decryption (key-name binding lives inside the ciphertext, see docs/vault-format.md)
  discovery/      .env file discovery (scans project root for .env* files)
  dotenv/         .env file parser (multiline, quoted, escape sequences)
  keyring/        age key generation and discovery (ENVSEAL_KEY env var + file)
  runner/         Cross-platform process runner (normal + sealed mode)
  ui/             Terminal output formatting
  vault/          Core vault service (encrypt, decrypt, sync, import, export)
main.go           Composition root
scripts/
  install.sh      curl-pipe-sh installer
```

## Key Design Decisions

- **Multiline values**: The .env parser supports double-quoted multiline values with escape sequences (`\n`, `\"`, `\\`). Single-quoted multiline values are literal (no escape processing). `pull` uses `dotenv.MarshalFile` to correctly quote multiline values on output.
- **Sealed mode**: `run --sealed` writes secrets to a temp file (0600) instead of env vars. Only `ENVSEAL_SECRETS` is set. Temp file is deleted after the child process exits.
- **SOPS import**: `import --from-sops` shells out to the `sops` binary for decryption — we don't reimplement SOPS crypto.
- **Run flag parsing**: `run` uses `DisableFlagParsing` so arbitrary child commands work, but manually parses `-e`/`--env` and `--sealed` before `--`.
- **JSON output**: Commands that display data (`list`, `diff`, `audit`, `version`) support `--json` for machine-readable output. Use `encoding/json` and write to `cmd.OutOrStdout()` — no custom serialization.

## Layer Rules

- A layer may only import from layers below it
- Layers communicate through interfaces, not concrete types
- `cmd/` contains no business logic — it delegates to services

## Commit Messages

Prefix the summary line with the type of change, followed by a colon:

```
fix: refuse symlinked lock paths on Unix
feat: add --format=json to envseal export
docs: document core.hooksPath in the git hook section
chore: bump golangci-lint to v2
refactor: extract saveAllVaults for grant/revoke/rotate
test: add concurrent grant stress test
```

Common types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`. Pick the one that describes what the commit *does*, not the area it touches — a bug fix in `vault/` is `fix:`, not `vault:`.

## Pull Requests

1. Fork the repo and create a branch from `main`
2. Write failing tests first (TDD encouraged)
3. Add tests for new functionality
4. Ensure `go test ./...` passes
5. Ensure `go vet ./...` reports no issues
6. Title the PR the same way as a commit summary line (`fix: ...`, `feat: ...`) and open it with a clear description of the change
