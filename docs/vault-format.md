# Vault Format Specification

envseal stores encrypted secrets in JSON vault files (`.env.vault`, `.env.staging.vault`, etc.). This document describes the format.

## File Structure

```json
{
  "version": 4,
  "environment": "development",
  "created_at": "2025-01-15T10:30:00Z",
  "updated_at": "2025-01-15T14:22:00Z",
  "entries": {
    "DATABASE_URL": {
      "encrypted": "<base64-encoded age ciphertext>"
    },
    "API_KEY": {
      "encrypted": "<base64-encoded age ciphertext>"
    }
  }
}
```

## Fields

| Field | Type | Description |
|-------|------|-------------|
| `version` | integer | Format version. Always `4` — the only supported version. Files with any other version are rejected at load time. |
| `environment` | string | Environment name (e.g., `development`, `staging`, `production`). Required — a v4 vault without it is rejected as tampered. Checked against the requested environment on load as a fast pre-decryption hint; the authoritative copy of this name lives *inside* every entry's ciphertext (see Entry Binding). |
| `created_at` | string | RFC 3339 timestamp of vault creation. |
| `updated_at` | string | RFC 3339 timestamp of last modification. |
| `entries` | object | Map of secret key names to entry objects. |

### Entry Object

| Field | Type | Description |
|-------|------|-------------|
| `encrypted` | string | Base64-encoded [age](https://age-encryption.org/) ciphertext. Encrypted to all configured recipients. The plaintext sealed inside is `<environment> || 0x00 || <key name> || 0x00 || <value>`, not the bare value (see Entry Binding). |

## Encryption Details

- **Algorithm:** age (X25519 + ChaCha20-Poly1305)
- **Library:** [filippo.io/age](https://pkg.go.dev/filippo.io/age) v1.3.1
- **Per-key encryption:** Each secret is encrypted independently, enabling per-key git diffs
- **Multi-recipient:** Each ciphertext is encrypted to all configured recipients simultaneously
- **Encoding:** Raw age ciphertext → base64 (standard encoding, with padding)

## Entry Binding

- **Framing:** before encryption, the plaintext is `<environment> || 0x00 || <key name> || 0x00 || <value>`. The `0x00` separators are unambiguous because environment names are restricted to `[a-zA-Z0-9_-]`, key names to `[A-Za-z0-9_]`, and values are rejected outright if they contain a null byte.
- **Purpose:** binds both the environment and the key name to the value, so an attacker with write access to the vault file can neither move an encrypted payload from one key to another nor copy it (or the whole file) from one environment's vault into another's. Unlike the v2 format's plaintext HMAC, the binding lives entirely inside the age ciphertext.
- **Verified:** on every decryption (`get`, `run`, `export`, `pull`, rotation, `sync`/`diff` change detection), by decrypting and checking the embedded environment and key name match the environment in use and the map key the entry was stored under. A mismatch or malformed plaintext is treated as tampering.

### Threat-model notes

- Swapping two entries inside a vault file is detected (embedded key name mismatch on decryption).
- Copying a whole vault file — or a single ciphertext — between environments is detected cryptographically: the environment name embedded inside each ciphertext no longer matches. The plaintext `environment` field additionally fails fast on load, but it is not the security boundary (it is attacker-editable; the ciphertext binding is not).
- Not protected: rolling the entire file back to an older valid version of the *same* environment's vault, or deleting entries. Both remain visible in `git diff` — review changes to vault files like any other code.
- **No offline verification oracle:** because the binding only exists inside the age ciphertext, checking it requires the recipient's private key. Unlike the v2 format (which stored an HMAC + cleartext salt next to each entry), holding the vault file alone — e.g. from a public git repository — gives an attacker no way to test guesses against low-entropy values without first breaking age's encryption.

## Older versions

Version 4 is the only supported format. Older versions are rejected at load time with "unsupported vault version":

- **v2** carried a plaintext `hash` + `salt` per entry (an offline verification oracle) — superseded by in-ciphertext binding.
- **v3** (pre-release) bound only the key name, not the environment, so a whole-file swap between environments was detectable only via the forgeable plaintext `environment` field.

There is no automatic migration (no v3 files exist outside pre-release development). To move an old vault forward, decrypt each value with the build that wrote it and re-`set` it with a current build, or restore secrets from your original source (password manager, provider console, etc.) into a fresh vault.

## File Naming Convention

Vault files live inside the `.envseal/vault/` directory:

| Environment | Vault File | Source File |
|-------------|-----------|-------------|
| development | `.envseal/vault/development.vault` | `.env.development` |
| staging | `.envseal/vault/staging.vault` | `.env.staging` |
| production | `.envseal/vault/production.vault` | `.env.production` |

## Decryption Without envseal

Vault files can be decrypted using the standard `age` CLI. The decrypted plaintext is `<environment>\x00<key name>\x00<value>` — strip everything up to and including the second null byte to get the value:

```bash
# Extract, decode, and decrypt a single entry (prints "development\x00DATABASE_URL\x00<value>")
cat .envseal/vault/development.vault | jq -r '.entries.DATABASE_URL.encrypted' | base64 -d | age -d -i .envseal/keys
```

This ensures zero lock-in — you never depend on envseal to access your secrets.
