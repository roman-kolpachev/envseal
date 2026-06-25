package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func (a *App) newExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export secrets in various formats",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.requireDeps(cmd, false); err != nil {
				return err
			}

			format, err := cmd.Flags().GetString("format")
			if err != nil {
				return err
			}

			if err := a.deps.Vault.Export(cmd.Context(), format, cmd.OutOrStdout()); err != nil {
				return err
			}

			a.auditLog("export", fmt.Sprintf("Exported secrets as %s", format))
			return nil
		},
	}

	cmd.Flags().String("format", "shell", "output format: shell, json, docker, k8s")
	return cmd
}
