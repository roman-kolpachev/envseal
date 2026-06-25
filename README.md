<p align="center">
  <img src="brand/logo.svg" alt="envseal — secrets sealed in git" width="400">
</p>

<p align="center">
  <a href="https://github.com/roman-kolpachev/envseal/actions/workflows/ci.yml"><img src="https://github.com/roman-kolpachev/envseal/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://goreportcard.com/report/github.com/roman-kolpachev/envseal"><img src="https://goreportcard.com/badge/github.com/roman-kolpachev/envseal" alt="Go Report Card"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://pkg.go.dev/github.com/roman-kolpachev/envseal"><img src="https://pkg.go.dev/badge/github.com/roman-kolpachev/envseal.svg" alt="Go Reference"></a>
</p>

**Secrets sealed in git.** Encrypt `.env` secrets per-key, store them safely in git, inject at runtime. Zero cloud, zero config, one binary.

## Table of contents

- [Why](#why)
- [How it works](#how-it-works)
- [Install](#install)
- [Quick start](#quick-start)
- [Commands](#commands) — secrets, sync, run, sealed mode, export, environments, teams, rotation, audit, JSON output, verbose output
- [Migrating from other tools](#migrating-from-other-tools) — SOPS, dotenvx, plain .env
- [CI/CD](#cicd) — GitHub Actions, GitLab, CircleCI, Bitbucket, Jenkins, Azure DevOps, AWS CodeBuild, Docker, TeamCity, Fly.io, Railway
- [Git hook](#git-hook)
- [Architecture](#architecture)
- [No lock-in](#no-lock-in)
- [vs. alternatives](#vs-alternatives)
- [Shell completion](#shell-completion)

## Why

Your team shares secrets over Slack. Someone copies `.env` from a colleague. A contractor leaves — nobody rotates the keys. Sound familiar?

envseal encrypts each secret individually using [age](https://age-encryption.org/) cryptography. The encrypted vault lives in your git repo. Each team member has their own keypair — grant and revoke access per person, not per shared password.

**vs. dotenvx / SOPS / Doppler, in short:** one ~10 MB binary, no bundled Node.js runtime (dotenvx), no KMS/IAM setup (SOPS), no cloud account (Doppler). `envseal grant`/`revoke` replace manually rotating a shared key or editing an IAM policy. Full comparison table: [vs. alternatives](#vs-alternatives).

## How it works

Each secret is encrypted individually with [age](https://age-encryption.org/) (X25519 + ChaCha20-Poly1305). The vault is a JSON file — human-readable, git-friendly, one key per line in diffs.

```
.env (plaintext, gitignored)            .envseal/vault/development.vault (encrypted, committed)
┌──────────────────────────┐            ┌───────────────────────────────────────────┐
│ DB_HOST=localhost        │    ──►     │ {                                         │
│ DB_PASS=secret123        │            │   "environment": "development",           │
│ STRIPE_KEY=sk_live_abc   │            │   "entries": {                            │
└──────────────────────────┘            │     "DB_HOST": {                          │
                                        │       "encrypted": "YWdlLWVuY3J5cH..."    │
                                        │     },                                    │
                                        │     "DB_PASS": {                          │
                                        │       "encrypted": "YWdlLWVuY3J5cH..."    │
                                        │     }                                     │
                                        │   }                                       │
                                        │ }                                         │
                                        └───────────────────────────────────────────┘
```

There is deliberately **no plaintext hash** next to the ciphertext: a hash would let anyone holding the vault file (e.g. from a public repo) test guesses against low-entropy secrets offline. Integrity is enforced *inside* the ciphertext instead — each entry seals `environment\0key\0value`, so swapped entries and cross-environment copies are detected at decrypt time. See [docs/vault-format.md](docs/vault-format.md).

When a single key changes, `git diff` shows only that key:

```diff
  "DB_HOST": {
-   "encrypted": "YWdlLWVuY3J5cH..."
+   "encrypted": "UmFuZG9tIGVuY3..."
  },
```

- **Encrypt** secrets with `set`, `sync`, or `import`
- **Decrypt** at runtime with `run` or `pull`
- **Grant/revoke** access per person — no shared passwords
- **Rotate** keys without downtime

## Install

```bash
# One-line installer (macOS, Linux)
curl -fsSL https://raw.githubusercontent.com/roman-kolpachev/envseal/main/scripts/install.sh | sh

# macOS (Apple Silicon)
curl -fsSL https://github.com/roman-kolpachev/envseal/releases/latest/download/envseal-darwin-arm64.tar.gz | tar xz
sudo mv envseal /usr/local/bin/

# macOS (Intel)
curl -fsSL https://github.com/roman-kolpachev/envseal/releases/latest/download/envseal-darwin-amd64.tar.gz | tar xz
sudo mv envseal /usr/local/bin/

# Linux
curl -fsSL https://github.com/roman-kolpachev/envseal/releases/latest/download/envseal-linux-amd64.tar.gz | tar xz
sudo mv envseal /usr/local/bin/

# Windows (PowerShell)
Invoke-WebRequest -Uri https://github.com/roman-kolpachev/envseal/releases/latest/download/envseal-windows-amd64.zip -OutFile envseal.zip
Expand-Archive envseal.zip -DestinationPath "$env:LOCALAPPDATA\envseal"
# Add to PATH: $env:LOCALAPPDATA\envseal

# With Go
go install github.com/roman-kolpachev/envseal@latest
```

Custom install location: `ENVSEAL_INSTALL_DIR=/opt/bin curl -fsSL ... | sh`

## Quick start

### You (project owner)

```bash
# 1. Initialize
envseal init
# ✓ Generated age keypair
#   Public key: age1yourkeyhere...

# 2. Import your existing .env
envseal import
# Select source file:
#   [1] .env
#   [2] .env.local
#   [3] .env.staging
# Enter number or path: 1
# ℹ Importing into development vault (.envseal/vault/development.vault)
# ✓ Imported 14 secrets from .env

# Or specify the file directly
envseal import .env.production -e production

# Or add secrets one by one (value never in shell history)
envseal set STRIPE_KEY
# Enter value for STRIPE_KEY: ████████████

# 3. Commit the encrypted vault
git add .envseal/
git commit -m "Add encrypted secrets"
git push
```

### Day-to-day: sync & pull

```bash
# Pull secrets from vault into a .env file (for local dev)
envseal pull
# ✓ Pulled 14 secrets to .env.development

# Sync updated .env back into vault
envseal sync
# ✓ Synced 14 keys
#   + Added: NEW_KEY
#   ~ Changed: DB_PASS
#   = Unchanged: 12 keys

# Compare without changing anything
envseal diff
```

### Adding a teammate

```bash
# Alice installs envseal and generates her keypair
envseal keygen
# ✓ Generated age keypair
#   Public key: age1alicekeyhere...

# Alice sends you her public key (over Slack, email — it's not secret)

# You grant her access
envseal grant alice --key age1alicekeyhere...
# ✓ Re-encrypted 2 secrets for 2 recipients

git add .envseal/
git commit -m "Grant access to Alice"
git push
```

### Alice (teammate)

```bash
# Alice pulls the repo and runs
git pull
envseal run -- npm start
# ✓ Secrets decrypted and injected — app starts

# Or generates a .env file
envseal pull
```

### When Alice leaves

```bash
envseal revoke alice
# ✓ Re-encrypted 2 secrets for 1 recipient
# ⚠ Remember to rotate all secrets — alice had access
```

## Commands

### Secrets

| Command | Description |
|---------|-------------|
| `set KEY=VALUE` | Encrypt and store a secret |
| `set KEY` | Encrypt a secret (prompts for value with hidden input) |
| `get KEY` | Decrypt and print a secret |
| `rm KEY` | Remove a secret |
| `list` | List all secret keys (no values). `--json` for machine-readable output |

### Sync and diff

| Command | Description |
|---------|-------------|
| `import [PATH]` | Import from `.env` file — discovers `.env*` files interactively, or pass path directly. Prompts per key if exists (`--force` to overwrite all) |
| `import --from-sops FILE` | Import from a SOPS-encrypted file (requires `sops` binary installed) |
| `sync` | Sync from `.env` to vault using source path from config — prompts per key if exists |
| `diff` | Show differences between `.env` and vault. `--json` for machine-readable output |
| `pull` | Decrypt vault and write a `.env` file using output path from config |

When `import` or `sync` encounter a key that already exists in the vault, you get an interactive prompt:

```
Key "DB_PASS" already exists. Overwrite? [y]es / [N]o / [a]ll:
```

- **y** — overwrite this key
- **N** — skip this key (default)
- **a** — overwrite this and all remaining keys

Use `import --force` to skip all prompts and overwrite everything.

### Run

```bash
envseal run -- npm start
envseal run -- docker compose up
envseal run -- python manage.py runserver

# Use a specific environment
envseal run -e production -- npm run deploy
envseal run --env staging -- python manage.py migrate
```

Decrypts all secrets and injects them as environment variables into the child process.

### Sealed mode

```bash
envseal run --sealed -- npm start
envseal run -e production --sealed -- npm run deploy
```

By default, `envseal run` injects secrets as environment variables. Every library, crash reporter, and debugging tool that reads `process.env` or `os.environ` gets the full set — including secrets.

`--sealed` keeps secrets out of the process environment. Instead:

1. Secrets are written to a temporary file with 0600 permissions
2. One env var is set: `ENVSEAL_SECRETS=/tmp/envseal-secrets-xxxx.env`
3. The temp file is deleted when the child process exits

**What this protects against:** tools and libraries that passively collect environment variables — crash reporters sending `process.env` to Sentry, telemetry packages harvesting env vars, `printenv` in logs, `/proc/*/environ` on Linux.

**What this does not protect against:** code that deliberately reads the file at `$ENVSEAL_SECRETS`. Any code running inside your process can still open that file and read the secrets. Sealed mode reduces the exposure surface — it is not a sandbox.

Your application reads secrets from the file instead of env vars:

```bash
# Shell: source the file
source "$ENVSEAL_SECRETS"

# Node.js: parse as .env
require('dotenv').config({ path: process.env.ENVSEAL_SECRETS })

# Python: load with dotenv
from dotenv import load_dotenv
load_dotenv(os.environ['ENVSEAL_SECRETS'])
```

### Export

```bash
envseal export --format=docker    # KEY=VALUE
envseal export --format=shell     # export KEY=VALUE
envseal export --format=json      # {"KEY": "VALUE"}
envseal export --format=k8s       # Kubernetes Secret YAML
```

### Environments

Each environment has its own vault and source `.env` file. All commands respect the `-e` flag for per-command environment override:

```bash
envseal env list                  # List environments (* = active)
envseal env use staging           # Switch active environment
envseal env add testing           # Add a new environment
envseal -e production pull        # One-off environment override
envseal -e staging import .env    # Import into a specific vault
envseal -e production sync        # Sync production .env to its vault
```

### Team access

```bash
# Alice generates her keypair
envseal keygen
# Alice sends her public key (age1abc...) to you

# You grant access
envseal grant alice --key age1abc...

# Vault is re-encrypted for all recipients
# Alice can now decrypt with her private key

# When Alice leaves the team
envseal revoke alice
```

`grant` refuses to replace an existing recipient's key unless you pass `--force`:

```bash
envseal grant alice --key age1newkey...
# Error: recipient "alice" already exists with a different key — use --force to replace it
#   (this revokes decrypt access for whoever holds the current private key)

envseal grant alice --key age1newkey... --force
```

This also protects you from yourself: `grant`-ing your own name by mistake (e.g. `default`, the name `init` registers your own key under) can't silently replace your own key and lock you out.

### Key rotation

```bash
envseal rotate
# Generates new keypair, re-encrypts all secrets
```

### Audit log

Every operation is logged to `.envseal/audit.log` — an append-only JSON Lines file committed alongside the vault.

```bash
envseal audit              # Show recent events
envseal audit --last 50    # Show last 50 events
envseal audit --json       # Machine-readable JSON output
```

```
Timestamp             Action   Actor         Keys        Message
──────────────────────────────────────────────────────────────────
2026-06-26 10:00:00   set      age1abc...    DB_HOST     Set DB_HOST
2026-06-26 10:01:00   import   age1abc...    A, B, C     Imported 3 secrets
2026-06-26 10:05:00   grant    age1abc...                Granted access to alice
```

Tracked actions: `set`, `get`, `rm`, `import`, `sync`, `pull`, `export`, `grant`, `revoke`, `rotate`.

### JSON output

Commands that display data support `--json` for CI/CD scripting and automation:

```bash
envseal list --json            # ["API_KEY","DB_HOST","DB_PASS"]
envseal diff --json            # [{"key":"DB_HOST","status":"unchanged"},...]
envseal audit --json           # [{...event...},...]
envseal version --json         # {"version":"v0.1.0"}
```

### Verbose output

`--verbose` (`-v`) prints which project directory and vault file a command actually resolved to, to stderr, on any command:

```bash
envseal get DB_HOST --verbose
# ℹ using project directory /home/alice/myapp, vault /home/alice/myapp/.envseal/vault/development.vault
# hunter2
```

Useful when running from a subdirectory — it tells you exactly which project you're operating against instead of leaving you to assume.

## Migrating from other tools

### From SOPS

```bash
# One command: decrypt with sops, import into envseal
envseal import --from-sops .env.sops

# Or for a specific environment
envseal import --from-sops -e production secrets.env.enc
```

Requires the `sops` binary to be installed. envseal runs `sops -d <file>` under the hood, then imports the decrypted entries. See [docs/migration-from-sops.md](docs/migration-from-sops.md) for the full guide.

### From dotenvx

```bash
# One command: decrypt with dotenvx, import into envseal
envseal import --from-dotenvx .env

# Or for a specific environment
envseal import --from-dotenvx -e production .env.production
```

Requires the `dotenvx` binary to be installed and able to decrypt the file. envseal runs `dotenvx decrypt --stdout` under the hood, then imports the decrypted entries. See [docs/migration-from-dotenvx.md](docs/migration-from-dotenvx.md) for the full guide.

### From plain .env files

```bash
envseal init
envseal import        # auto-discovers .env files
git add .envseal/
git commit -m "Encrypt secrets with envseal"
```

## CI/CD

The encrypted vault is in git — CI just needs the private key and the binary.

### Key setup

Store your private key as a CI secret named `ENVSEAL_KEY`. envseal discovers it automatically.

```bash
export ENVSEAL_KEY="AGE-SECRET-KEY-1..."
envseal run -e production -- npm run deploy
```

Alternatively, write the key to a file:

```bash
mkdir -p .envseal
echo "$ENVSEAL_PRIVATE_KEY" > .envseal/keys
envseal run -e production -- npm run deploy
```

**Note on `ENVSEAL_KEY` exposure:** envseal unsets `ENVSEAL_KEY` from its own process environment as soon as it reads it, but on Linux that only affects envseal's in-memory view — the kernel-backed `/proc/<pid>/environ` for that process still contains the literal key for as long as the process runs, and any core dump captures it too. This is the same exposure class documented above for `--sealed`, applied to the master private key itself rather than an individual secret. If your CI system supports mounting a secret as a file, prefer writing the key to `.envseal/keys` (0600, gitignored) over passing it via the `ENVSEAL_KEY` environment variable.

### Installing in CI

The install script downloads the latest version and verifies the SHA-256 checksum automatically:

```bash
curl -fsSL https://raw.githubusercontent.com/roman-kolpachev/envseal/main/scripts/install.sh | sh
```

Pin a specific version with `ENVSEAL_VERSION`:

```bash
ENVSEAL_VERSION=v0.1.0 curl -fsSL https://raw.githubusercontent.com/roman-kolpachev/envseal/main/scripts/install.sh | sh
```

If you prefer not to use the install script, you can install manually:

| Method | Version pinned | Checksum verified | Requires |
|--------|:-:|:-:|----------|
| Direct download | Yes | Manual | curl + sha256sum |
| `go install` | Yes | Yes (Go module hash) | Go toolchain |

<details>
<summary>Direct download + manual checksum</summary>

```bash
ENVSEAL_VERSION="v0.1.0"
curl -fsSL "https://github.com/roman-kolpachev/envseal/releases/download/${ENVSEAL_VERSION}/envseal-linux-amd64.tar.gz" -o envseal.tar.gz
curl -fsSL "https://github.com/roman-kolpachev/envseal/releases/download/${ENVSEAL_VERSION}/checksums.txt" -o checksums.txt
sha256sum --check --ignore-missing checksums.txt
tar xzf envseal.tar.gz
sudo mv envseal /usr/local/bin/
```

On macOS, replace `sha256sum` with `shasum -a 256`.

</details>

<details>
<summary>go install</summary>

```bash
go install github.com/roman-kolpachev/envseal@v0.1.0
```

</details>

### GitHub Actions

```yaml
steps:
  - uses: actions/checkout@v4
  - run: curl -fsSL https://raw.githubusercontent.com/roman-kolpachev/envseal/main/scripts/install.sh | sh
  - run: envseal run -e production -- npm run deploy
    env:
      ENVSEAL_KEY: ${{ secrets.ENVSEAL_KEY }}
```

### GitLab CI

```yaml
deploy:
  variables:
    ENVSEAL_KEY: $ENVSEAL_KEY  # Set in Settings → CI/CD → Variables (masked)
  before_script:
    - curl -fsSL https://raw.githubusercontent.com/roman-kolpachev/envseal/main/scripts/install.sh | sh
  script:
    - envseal run -e production -- npm run deploy
```

### CircleCI

```yaml
jobs:
  deploy:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
      - run: curl -fsSL https://raw.githubusercontent.com/roman-kolpachev/envseal/main/scripts/install.sh | sh
      - run: envseal run -e production -- npm run deploy
# Set ENVSEAL_KEY in Project Settings → Environment Variables
```

### Bitbucket Pipelines

```yaml
pipelines:
  branches:
    main:
      - step:
          name: Deploy
          script:
            - curl -fsSL https://raw.githubusercontent.com/roman-kolpachev/envseal/main/scripts/install.sh | sh
            - envseal run -e production -- npm run deploy
# Set ENVSEAL_KEY in Repository settings → Repository variables (secured)
```

### Jenkins

```groovy
pipeline {
    agent any
    environment {
        ENVSEAL_KEY = credentials('envseal-key')  // Add in Jenkins → Credentials
    }
    stages {
        stage('Deploy') {
            steps {
                sh 'curl -fsSL https://raw.githubusercontent.com/roman-kolpachev/envseal/main/scripts/install.sh | sh'
                sh 'envseal run -e production -- npm run deploy'
            }
        }
    }
}
```

### Azure DevOps

```yaml
steps:
  - script: curl -fsSL https://raw.githubusercontent.com/roman-kolpachev/envseal/main/scripts/install.sh | sh
    displayName: Install envseal
  - script: envseal run -e production -- npm run deploy
    displayName: Deploy
    env:
      ENVSEAL_KEY: $(ENVSEAL_KEY)  # Set in Pipelines → Library → Variable groups
```

### AWS CodeBuild

```yaml
version: 0.2
env:
  secrets-manager:
    ENVSEAL_KEY: envseal:ENVSEAL_KEY  # Store in AWS Secrets Manager
phases:
  install:
    commands:
      - curl -fsSL https://raw.githubusercontent.com/roman-kolpachev/envseal/main/scripts/install.sh | sh
  build:
    commands:
      - envseal run -e production -- npm run deploy
```

### Docker

Use a BuildKit secret mount — never `ARG`/`ENV`, and never `COPY` decrypted
secrets between stages. An `ARG` value survives in `docker history`, and a
`COPY`'d file remains extractable from the final image's layer history even
if a later `RUN rm` deletes it.

```dockerfile
# syntax=docker/dockerfile:1
FROM node:22-slim AS build
COPY --from=golang:1.25.8-alpine /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:/root/go/bin:$PATH"
RUN go install github.com/roman-kolpachev/envseal@latest
WORKDIR /app
COPY . .
# The key is mounted for this single RUN only — it never enters a layer,
# the build cache, or the image history. Secrets exist only in the build
# step's process environment.
RUN --mount=type=secret,id=envseal_key,env=ENVSEAL_KEY \
    envseal run -e production -- npm run build

FROM node:22-slim
COPY --from=build /app/dist /app/dist
```

```bash
# Pass the key from the host without writing it to disk
docker build --secret id=envseal_key,env=ENVSEAL_KEY .
```

### Fly.io

```bash
# Set the secret once
fly secrets set ENVSEAL_KEY="AGE-SECRET-KEY-1..."

# In your Dockerfile or fly.toml start command
envseal run -e production -- npm start
```

### Railway / Render / Vercel

Set `ENVSEAL_KEY` as an environment variable in the platform's dashboard, then use envseal in your build command:

```bash
# Build command
curl -fsSL https://raw.githubusercontent.com/roman-kolpachev/envseal/main/scripts/install.sh | sh && envseal run -e production -- npm run build
```

### TeamCity

Add `ENVSEAL_KEY` as a password parameter in Build Configuration → Parameters:

```
Parameter name: env.ENVSEAL_KEY
Kind: Environment variable
Type: Password
```

Build step (Command Line runner):

```bash
curl -fsSL https://raw.githubusercontent.com/roman-kolpachev/envseal/main/scripts/install.sh | sh
envseal run -e production -- npm run deploy
```

The same pattern works with any CI: Drone, Buildkite, Woodpecker. Store the private key as a CI secret named `ENVSEAL_KEY`, and `envseal run` picks it up automatically.

## Git hook

envseal can install a pre-commit hook that prevents accidentally committing `.envseal/keys` (your private key):

```bash
envseal hook install
# ✓ Installed pre-commit hook

envseal hook uninstall
# ✓ Removed pre-commit hook
```

If `.envseal/keys` is staged, the commit is blocked:

```
✗ .envseal/keys is staged for commit.
  This file contains your private key and must NEVER be committed.

  To unstage:  git reset HEAD .envseal/keys
```

`hook install` resolves the hooks directory through `git` itself (`git rev-parse --git-path hooks`), so it installs to the right place even if you use Husky, the `pre-commit` framework, lefthook, or any other tool that sets `core.hooksPath` — not just the default `.git/hooks/`.

**`git clone` does not carry hooks over.** Hooks live in `.git/hooks/` (or wherever `core.hooksPath` points), which is local, untracked repository state — cloning, pulling, or fetching never installs them on the other end. Each teammate who clones the repo starts with no pre-commit protection until they run `envseal hook install` themselves. Put it in your onboarding checklist next to `envseal keygen`; a repo where only the person who ran `init` has the hook gives everyone else a false sense of safety.

## Architecture

```
.envseal/
  config.toml          ← Config: environments, recipients (committed)
  keys                 ← Private key (gitignored, never committed)
  audit.log            ← Audit trail (committed)
  vault/
    development.vault  ← Encrypted secrets (committed)
    staging.vault
    production.vault
```

Every command works from any subdirectory of your project — not just the directory containing `.envseal/` — the same way `git` and `npm` do. `envseal init` and `envseal keygen` are the two exceptions: both always target the exact directory you run them from, since redirecting either one to an unrelated ancestor project would be a good way to overwrite someone else's key or lock yourself out of your own vault.

Concurrent invocations are safe: a project-wide lock serializes reads and writes, and `grant`/`revoke`/`rotate` commit every affected environment's vault as a single all-or-nothing unit. This matters more than it sounds like it should — envseal ends up called from places that parallelize by default: a docker-compose stack where every service's entrypoint is `envseal run -- start`, a `make -j` or `npm-run-all --parallel` target, an onboarding script that `xargs -P4`s a list of `envseal grant` calls. Without the lock, those race a plain read-modify-write cycle and silently drop each other's changes while every invocation still reports success.

Built with:
- [age](https://age-encryption.org/) — modern encryption (X25519 + ChaCha20-Poly1305)
- [cobra](https://github.com/spf13/cobra) — CLI framework
- Go — single binary, no runtime dependencies

## No lock-in

envseal uses [age](https://age-encryption.org/), an open encryption standard. Your vault is a documented JSON file. Even if envseal disappears, you can decrypt everything with the standalone `age` CLI:

```bash
# Install age (https://github.com/FiloSottile/age)
brew install age  # or: apt install age / scoop install age

# Each vault entry's "encrypted" field is base64-encoded age ciphertext.
# Decrypt any value with your private key:
echo "YWdlLWVuY3J5cHRpb24..." | base64 -d | age -d -i .envseal/keys
```

No proprietary format, no account, no server. Your secrets are always yours.

## vs. alternatives

| | envseal | dotenvx | SOPS | Doppler |
|---|---|---|---|---|
| Setup time | `curl \| sh` + `envseal init` | npm install + setup | Binary + GPG/KMS setup | Account + dashboard + CLI |
| Add a teammate | `envseal grant alice` | Share the key with everyone | Configure KMS IAM policy | Invite via web UI |
| Remove a teammate | `envseal revoke alice` | Rotate the shared key manually | Update KMS IAM policy | Remove via web UI |
| Runtime: Node.js? | No — single binary (~10 MB) | Yes — bundled Node.js (~60 MB) | No | No |
| Encryption | age (X25519, post-quantum path) | secp256k1 (Bitcoin curve) | age/KMS/PGP | Proprietary |
| Sealed mode | `--sealed` (secrets out of env vars) | No | No | No |
| SOPS migration | `import --from-sops` | No | — | No |
| dotenvx migration | `import --from-dotenvx` | — | No | No |
| JSON output (`--json`) | `list`, `diff`, `audit`, `version` | No | `--output-type json` | API-based |
| Multiline .env | Yes (quoted + escape sequences) | Yes | Partial (.env is secondary format) | N/A |
| Cloud account needed? | No | No | Optional (AWS/GCP KMS) | Yes (required) |
| Works offline? | Yes | Yes | Only with GPG | No |
| Lock-in risk | None — age is an open standard | Low — custom format | Low — standard KMS | High — proprietary API |

## Shell completion

```bash
# Bash
source <(envseal completion bash)

# Zsh
envseal completion zsh > "${fpath[1]}/_envseal"

# Fish
envseal completion fish > ~/.config/fish/completions/envseal.fish

# PowerShell
envseal completion powershell | Out-String | Invoke-Expression
```

## License

MIT
