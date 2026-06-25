package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

func (a *App) newVersionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			v := a.deps.Version
			if v == "" {
				v = "dev"
			}

			if jsonOut, _ := cmd.Flags().GetBool("json"); jsonOut {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]string{"version": v})
			}

			_, err := fmt.Fprintf(cmd.OutOrStdout(), "envseal %s\n", v)
			return err
		},
	}

	cmd.Flags().Bool("json", false, "output as JSON")
	return cmd
}
