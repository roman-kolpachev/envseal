package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func (a *App) newGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get KEY",
		Short: "Get a decrypted secret value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.requireDeps(cmd, false); err != nil {
				return err
			}

			value, err := a.deps.Vault.Get(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			defer clear(value)

			w := cmd.OutOrStdout()
			if _, err := w.Write(value); err != nil {
				return err
			}
			if _, err := w.Write([]byte("\n")); err != nil {
				return err
			}
			a.auditLog("get", fmt.Sprintf("Get %s", args[0]), args[0])
			return nil
		},
	}
}
