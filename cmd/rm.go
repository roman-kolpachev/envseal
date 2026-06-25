package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/roman-kolpachev/envseal/internal/ui"
)

func (a *App) newRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm KEY",
		Short: "Remove a secret from the vault",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.requireDeps(cmd, true); err != nil {
				return err
			}

			if err := a.deps.Vault.Remove(args[0]); err != nil {
				return err
			}

			if err := a.saveVault(cmd); err != nil {
				return err
			}

			if err := ui.Success(cmd.OutOrStdout(), fmt.Sprintf("Removed %s", args[0])); err != nil {
				return err
			}
			a.auditLog("rm", fmt.Sprintf("Removed %s", args[0]), args[0])
			return nil
		},
	}
}
