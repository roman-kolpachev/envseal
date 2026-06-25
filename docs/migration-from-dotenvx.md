# Migrating from dotenvx to envseal

## Overview

Both tools encrypt `.env` secrets per-key for git storage — dotenvx is not
"whole-file" encryption, it already encrypts each value individually, same
as envseal. The real differences are elsewhere:

| | dotenvx | envseal |
|---|---|---|
| Encryption | secp256k1 (ECIES, a Bitcoin curve) | age (X25519 + ChaCha20-Poly1305, post-quantum path) |
| Binary | Bundled Node.js runtime (~60 MB) | Native Go binary (~10 MB) |
| Key management | `.env.keys` (symmetric) | `.envseal/keys` (age keypair) |
| Vault format | Values encrypted in place inside the `.env` file | Separate JSON per-key vault |
| Team sharing | Share the key manually, or pay for Dotenvx Ops | `grant` / `revoke` with public keys, built into the core CLI |
| Runtime | `dotenvx run --` | `envseal run --` |

## Step-by-Step Migration

### Quick path: one command

```bash
envseal import --from-dotenvx .env
```

This shells out to `dotenvx decrypt --stdout` to decrypt the file, then
imports the plaintext entries directly — no intermediate decrypted file
touches disk. Requires the `dotenvx` binary to be installed and able to
decrypt the file (`DOTENV_PRIVATE_KEY` set, or a `.env.keys` file present).

For multiple environments:

```bash
envseal init --name my-project
envseal import --from-dotenvx .env
envseal import --from-dotenvx .env.staging --env staging
envseal import --from-dotenvx .env.production --env production
```

## Step-by-Step Migration (manual)

### 1. Decrypt your dotenvx secrets

```bash
# Decrypt all environments to plain .env files
dotenvx decrypt
# or for a specific environment:
dotenvx decrypt -f .env.production
```

### 2. Initialize envseal

```bash
envseal init --name my-project
```

This creates `.envseal/config.toml`, `.envseal/keys`, and an empty vault under `.envseal/vault/`.

### 3. Import your decrypted .env files

```bash
# Import each environment
envseal import .env
envseal import .env.staging --env staging
envseal import .env.production --env production
```

### 4. Verify the import

```bash
envseal list
envseal get DATABASE_URL
```

### 5. Update your runtime commands

```diff
# Before (dotenvx)
- dotenvx run -- node server.js

# After (envseal)
+ envseal run -- node server.js
```

### 6. Update CI/CD

Replace `DOTENV_PRIVATE_KEY` with `ENVSEAL_KEY` in your CI secrets. See the README for CI/CD examples.

### 7. Clean up

```bash
# Remove dotenvx artifacts
rm .env.vault .env.keys  # dotenvx files
# Commit the new envseal vault
git add .envseal/
git commit -m "chore: migrate from dotenvx to envseal"
```

### 8. Add teammates

```bash
# Each teammate generates a keypair
envseal keygen

# Project owner grants access
envseal grant alice --key age1...
```
