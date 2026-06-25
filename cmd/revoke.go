package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/roman-kolpachev/envseal/internal/ui"
)

func (a *App) newRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke NAME",
		Short: "Revoke vault access from a recipient",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.requireDeps(cmd, true); err != nil {
				return err
			}

			name := args[0]
			uniqueKeys := make(map[string]bool)
			for n, key := range a.deps.Config.Recipients {
				if n != name {
					uniqueKeys[key] = true
				}
			}
			if len(uniqueKeys) == 0 {
				return fmt.Errorf("cannot revoke the last recipient — vault would become unrecoverable")
			}

			if err := a.deps.Config.RemoveRecipient(name); err != nil {
				return err
			}

			dir, err := a.workDir()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}

			newRecipients := a.deps.Config.RecipientKeys()
			envVaults, totalSecrets, err := a.reEncryptAllVaults(cmd.Context(), dir, newRecipients)
			if err != nil {
				return err
			}

			// Save vaults BEFORE updating the config so that a partial save failure
			// does not leave any vault accessible to the revoked recipient via stale
			// on-disk encryption while the config already reflects their removal.
			if err := a.saveAllVaults(dir, envVaults); err != nil {
				return err
			}
			if err := a.saveConfig(); err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			recipients := a.deps.Config.RecipientKeys()
			if err := ui.Success(w, fmt.Sprintf("Revoked access for %s", name)); err != nil {
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
			if err := ui.Warn(w, fmt.Sprintf("Remember to rotate all secrets — %s had access to decrypted values", name)); err != nil {
				return err
			}
			a.auditLogWithTarget("revoke", name, fmt.Sprintf("Revoked access for %s", name))
			return nil
		},
	}
}
