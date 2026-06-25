package cmd

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/spf13/cobra"
)

func (a *App) newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all secret keys",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.requireDeps(cmd, false); err != nil {
				return err
			}

			keys, err := a.deps.Vault.List()
			if err != nil {
				return err
			}

			sort.Strings(keys)

			if jsonOut, _ := cmd.Flags().GetBool("json"); jsonOut {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(keys)
			}

			for _, k := range keys {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), k); err != nil {
					return err
				}
			}
			return nil
		},
	}

	cmd.Flags().Bool("json", false, "output as JSON")
	return cmd
}
