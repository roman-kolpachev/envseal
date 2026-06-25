package cmd

import (
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"

	"github.com/roman-kolpachev/envseal/internal/config"
	"github.com/roman-kolpachev/envseal/internal/crypto"
	"github.com/roman-kolpachev/envseal/internal/keyring"
	"github.com/roman-kolpachev/envseal/internal/ui"
	"github.com/roman-kolpachev/envseal/internal/vault"
)

func (a *App) newRotateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate",
		Short: "Rotate the current user's keypair and re-encrypt all secrets",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.requireDeps(cmd, true); err != nil {
				return err
			}
			if a.deps.Keyring == nil {
				return fmt.Errorf("no private key found — cannot rotate")
			}

			dir, err := a.workDir()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}

			oldPubKey := a.deps.Keyring.PublicKey

			newID, err := keyring.Generate()
			if err != nil {
				return fmt.Errorf("generate new keypair: %w", err)
			}

			// Collect ALL recipient names that carry the old public key. The same
			// key may be registered under several names; replacing only the first
			// match would silently leave the old (rotated-away) key as a valid
			// recipient under the remaining names, defeating the rotation.
			var namesWithOldKey []string
			for name, key := range a.deps.Config.Recipients {
				if key == oldPubKey {
					namesWithOldKey = append(namesWithOldKey, name)
				}
			}
			if len(namesWithOldKey) == 0 {
				return fmt.Errorf("current public key not found in recipients — cannot rotate")
			}
			sort.Strings(namesWithOldKey)

			oldEnc := crypto.NewAgeEncryptor(a.deps.Keyring)
			for _, recipientName := range namesWithOldKey {
				if err := a.deps.Config.RemoveRecipient(recipientName); err != nil {
					return fmt.Errorf("remove old recipient %q: %w", recipientName, err)
				}
				if err := a.deps.Config.AddRecipient(recipientName, newID.PublicKey, false); err != nil {
					return fmt.Errorf("add new recipient %q: %w", recipientName, err)
				}
			}
			newEnc := crypto.NewAgeEncryptor(newID)

			totalSecrets := 0
			envVaults := make(map[string]*vault.Service)

			for envName, envCfg := range a.deps.Config.Environments {
				vaultPath, pathErr := safePath(dir, envCfg.VaultPath)
				if pathErr != nil {
					return fmt.Errorf("invalid vault path for %q: %w", envName, pathErr)
				}
				oldSvc := vault.NewService(oldEnc, a.deps.Config)
				// Bind before Load: Load verifies the file's recorded
				// environment, and DecryptAll verifies the environment
				// embedded in every entry's ciphertext.
				if err := oldSvc.SetEnvironment(envName); err != nil {
					return fmt.Errorf("invalid environment name %q: %w", envName, err)
				}
				if loadErr := oldSvc.Load(vaultPath); loadErr != nil {
					if errors.Is(loadErr, vault.ErrVaultNotFound) {
						continue
					}
					return fmt.Errorf("load vault for %q: %w", envName, loadErr)
				}

				all, err := oldSvc.DecryptAll(cmd.Context())
				if err != nil {
					return fmt.Errorf("decrypt %q secrets: %w", envName, err)
				}

				newSvc := vault.NewService(newEnc, a.deps.Config)
				if err := newSvc.SetEnvironment(envName); err != nil {
					vault.ClearSecretMap(all)
					return fmt.Errorf("invalid environment name %q: %w", envName, err)
				}
				for key, val := range all {
					if err := newSvc.Set(cmd.Context(), key, val); err != nil {
						vault.ClearSecretMap(all)
						return fmt.Errorf("re-encrypt %q in %q: %w", key, envName, err)
					}
				}
				totalSecrets += len(all)
				vault.ClearSecretMap(all)
				envVaults[envName] = newSvc
			}

			tmpKeyPath := config.KeysPath(dir) + ".new"
			if err := keyring.SaveToFile(newID, tmpKeyPath); err != nil {
				return fmt.Errorf("save new private key: %w", err)
			}

			// Save vaults BEFORE saving config, as a single all-or-nothing
			// staged commit (saveAllVaults): a per-vault save loop here used
			// to mean a failure partway left some environments re-encrypted
			// for the new key and the rest still on the old one. With staging,
			// a failure before the commit phase modifies nothing on disk, so
			// the config (still unchanged) and every vault stay consistent
			// with the old key. The new key at tmpKeyPath is kept — do NOT
			// delete it — because any vault that was already committed needs
			// it for recovery.
			if err := a.saveAllVaults(dir, envVaults); err != nil {
				return fmt.Errorf(
					"%w\nnote: new private key saved to %s — keep this file to recover any already-rotated vaults",
					err, tmpKeyPath,
				)
			}

			// All vaults committed with new encryption; now persist the config change.
			// If this fails, manually rename tmpKeyPath to the keys file to recover.
			if err := a.saveConfig(); err != nil {
				return fmt.Errorf(
					"%w\nnote: vaults already re-encrypted; new private key at %s — rename it to %s to complete recovery",
					err, tmpKeyPath, config.KeysPath(dir),
				)
			}

			if err := os.Rename(tmpKeyPath, config.KeysPath(dir)); err != nil {
				return fmt.Errorf(
					"finalize key rotation: %w\nnote: manually rename %s to %s to complete the rotation",
					err, tmpKeyPath, config.KeysPath(dir),
				)
			}

			a.deps.Keyring = newID
			if currentSvc, ok := envVaults[a.resolveEnvironmentName(cmd)]; ok {
				a.deps.Vault = currentSvc
			}

			w := cmd.OutOrStdout()
			recipients := a.deps.Config.RecipientKeys()
			if err := ui.Success(w, "Generated new keypair"); err != nil {
				return err
			}
			if err := ui.Success(w, fmt.Sprintf(
				"Re-encrypted %d %s across %d %s for %d %s",
				totalSecrets, ui.Plural(totalSecrets, "secret", "secrets"),
				len(envVaults), ui.Plural(len(envVaults), "environment", "environments"),
				len(recipients), ui.Plural(len(recipients), "recipient", "recipients"),
			)); err != nil {
				return err
			}
			if err := ui.KeyValue(w, "New public key", newID.PublicKey); err != nil {
				return err
			}
			a.auditLog("rotate", fmt.Sprintf("Rotated keypair, re-encrypted %d secrets across %d environments", totalSecrets, len(envVaults)))
			return nil
		},
	}
}
