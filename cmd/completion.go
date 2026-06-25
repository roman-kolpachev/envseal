package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func (a *App) newCompletionCmd() *cobra.Command {
	return &cobra.Command{
		Use:       "completion [bash|zsh|fish|powershell]",
		Short:     "Generate shell completion script",
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return a.root.GenBashCompletion(cmd.OutOrStdout())
			case "zsh":
				return a.root.GenZshCompletion(cmd.OutOrStdout())
			case "fish":
				return a.root.GenFishCompletion(cmd.OutOrStdout(), true)
			case "powershell":
				return a.root.GenPowerShellCompletionWithDesc(cmd.OutOrStdout())
			default:
				return fmt.Errorf("unsupported shell: %s (use bash, zsh, fish, or powershell)", args[0])
			}
		},
	}
}
