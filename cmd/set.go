package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/roman-kolpachev/envseal/internal/ui"
)

func (a *App) newSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set KEY[=VALUE]",
		Short: "Set an encrypted secret",
		Long:  "Set an encrypted secret. If VALUE is omitted, prompts for it interactively with hidden input.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.requireDeps(cmd, true); err != nil {
				return err
			}

			key, valueStr, ok := strings.Cut(args[0], "=")
			var value []byte
			if !ok {
				if a.deps.ReadSecret == nil {
					return fmt.Errorf("expected KEY=VALUE format, got %q (interactive input not available)", args[0])
				}
				// Sanitize: the key has not passed ValidateKeyName yet (that
				// happens inside Vault.Set, after this prompt), so control
				// characters in it would otherwise reach the terminal raw —
				// matching the SanitizeForTerminal call on the warning path below.
				b, err := a.deps.ReadSecret(fmt.Sprintf("Enter value for %s: ", ui.SanitizeForTerminal(key)))
				if err != nil {
					return fmt.Errorf("read secret: %w", err)
				}
				if len(b) == 0 {
					return fmt.Errorf("value cannot be empty")
				}
				value = b
			} else {
				if a.deps.ReadSecret != nil {
					if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "⚠ Value passed via command-line arguments — visible in process listings. Use `envseal set %s` (without =VALUE) for hidden input.\n", ui.SanitizeForTerminal(key)); err != nil {
						return err
					}
				}
				value = []byte(valueStr)
			}

			if err := a.deps.Vault.Set(cmd.Context(), key, value); err != nil {
				clear(value)
				return err
			}
			clear(value)

			if err := a.saveVault(cmd); err != nil {
				return err
			}

			recipients := a.deps.Config.RecipientKeys()
			if err := ui.Success(cmd.OutOrStdout(), fmt.Sprintf("Encrypted %s for %d %s", key, len(recipients), ui.Plural(len(recipients), "recipient", "recipients"))); err != nil {
				return err
			}
			a.auditLog("set", fmt.Sprintf("Set %s", key), key)
			return nil
		},
	}
}
