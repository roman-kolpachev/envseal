package cmd

import (
	"encoding/json"

	"github.com/spf13/cobra"

	"github.com/roman-kolpachev/envseal/internal/ui"
)

func (a *App) newDiffCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Show differences between .env file and vault",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.requireDeps(cmd, false); err != nil {
				return err
			}

			source, err := a.resolveSourcePath(cmd)
			if err != nil {
				return err
			}

			diffs, err := a.deps.Vault.Diff(source)
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()

			if jsonOut, _ := cmd.Flags().GetBool("json"); jsonOut {
				return json.NewEncoder(w).Encode(diffs)
			}

			headers := []string{"Key", "Status"}
			rows := make([][]string, len(diffs))
			for i, d := range diffs {
				rows[i] = []string{ui.SanitizeForTerminal(d.Key), d.Status}
			}
			return ui.Table(w, headers, rows)
		},
	}

	cmd.Flags().String("source", "", "source .env file (default from config)")
	cmd.Flags().Bool("json", false, "output as JSON")
	return cmd
}
