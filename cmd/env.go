package cmd

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/roman-kolpachev/envseal/internal/ui"
)

func (a *App) newEnvCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "env",
		Short: "Manage environments",
	}

	cmd.AddCommand(
		a.newEnvListCmd(),
		a.newEnvUseCmd(),
		a.newEnvAddCmd(),
	)

	return cmd
}

func (a *App) newEnvListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List available environments",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// mutate=false: this command only reads the config — passing true
			// here kept the project-wide vault lock held for the remainder of
			// the process (see requireDeps), needlessly blocking every
			// concurrent envseal invocation for a purely read-only listing.
			if err := a.requireDeps(cmd, false); err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			names := a.deps.Config.EnvironmentNames()
			sort.Strings(names)

			for _, name := range names {
				if name == a.deps.Config.Default {
					if _, err := fmt.Fprintf(w, "* %s\n", name); err != nil {
						return err
					}
				} else {
					if _, err := fmt.Fprintf(w, "  %s\n", name); err != nil {
						return err
					}
				}
			}
			return nil
		},
	}
}

func (a *App) newEnvAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add NAME",
		Short: "Add a new environment",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.requireDeps(cmd, true); err != nil {
				return err
			}

			name := args[0]
			if err := a.deps.Config.AddEnvironment(name); err != nil {
				return err
			}

			if err := a.saveConfig(); err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			env, _ := a.deps.Config.GetEnvironment(name)
			if err := ui.Success(w, fmt.Sprintf("Added environment %s", name)); err != nil {
				return err
			}
			if err := ui.KeyValue(w, "Vault", ui.SanitizeForTerminal(env.VaultPath)); err != nil {
				return err
			}
			return ui.KeyValue(w, "Source", ui.SanitizeForTerminal(env.SourcePath))
		},
	}
}

func (a *App) newEnvUseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "use ENVIRONMENT",
		Short: "Switch the active environment",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.requireDeps(cmd, true); err != nil {
				return err
			}

			env := args[0]
			if err := a.deps.Config.SetDefault(env); err != nil {
				return err
			}

			if err := a.saveConfig(); err != nil {
				return err
			}

			return ui.Success(cmd.OutOrStdout(), fmt.Sprintf("Switched to %s", env))
		},
	}
}
