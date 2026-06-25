# Migrating from SOPS to envseal

## Overview

| | SOPS | envseal |
|---|---|---|
| Encryption | AES-256-GCM, age, PGP, KMS | age only |
| Config | `.sops.yaml` | `.envseal/config.toml` |
| File format | Encrypted YAML/JSON/ENV/INI | JSON vault (per-key) |
| Key management | KMS, PGP keyring, age | age keypairs |
| Cloud dependency | Optional (KMS, GCP KMS) | None |
| Runtime injection | External (e.g., `sops exec-env`) | Built-in (`envseal run --`) |

## Step-by-Step Migration

### 1. Decrypt your SOPS secrets to .env format

```bash
# If your secrets are in YAML:
sops -d secrets.yaml | yq -o=props > .env.plain

# If your secrets are already in .env format:
sops -d .env.enc > .env.plain

# If your secrets are in JSON:
sops -d secrets.json | jq -r 'to_entries[] | "\(.key)=\(.value)"' > .env.plain
```

### 2. Initialize envseal

```bash
envseal init --name my-project
```

### 3. Import secrets

```bash
envseal import .env.plain
```

### 4. Verify

```bash
envseal list
envseal diff .env.plain  # should show all unchanged
```

### 5. Update runtime commands

```diff
# Before (SOPS)
- sops exec-env secrets.yaml 'node server.js'

# After (envseal)
+ envseal run -- node server.js
```

### 6. Update CI/CD

Replace SOPS key setup (KMS role, PGP import, age key file) with a single `ENVSEAL_KEY` secret containing your age private key. See the README for CI/CD examples.

### 7. Clean up

```bash
rm .env.plain  # remove decrypted file
rm .sops.yaml  # remove SOPS config
git add .envseal/
git commit -m "chore: migrate from SOPS to envseal"
```

## Notes

- If you used SOPS with AWS KMS or GCP KMS, envseal eliminates that cloud dependency entirely
- If you used SOPS with age keys, you need to generate new envseal-managed age keys (`envseal keygen`) — SOPS age keys are not directly reusable because envseal manages its own keyring format
