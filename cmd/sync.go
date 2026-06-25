package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/roman-kolpachev/envseal/internal/ui"
)

func (a *App) newSyncCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Sync secrets from a .env file to the vault",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.requireDeps(cmd, true); err != nil {
				return err
			}

			source, err := a.resolveSourcePath(cmd)
			if err != nil {
				return err
			}

			if _, err := os.Lstat(source); os.IsNotExist(err) {
				w := cmd.OutOrStdout()
				if err := ui.Warn(w, fmt.Sprintf("Source file not found: %s", ui.SanitizeForTerminal(source))); err != nil {
					return err
				}
				if a.deps.Confirm != nil {
					if yes, confirmErr := a.deps.Confirm(fmt.Sprintf("Create empty %s? [Y/n] ", ui.SanitizeForTerminal(filepath.Base(source)))); confirmErr != nil {
						return confirmErr
					} else if yes {
						//nolint:gosec // G304: source was already resolved and containment-checked via safeUserPath/safePath above; O_EXCL additionally blocks symlink-follow TOCTOU on creation.
						f, createErr := os.OpenFile(source, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
						if createErr != nil {
							return fmt.Errorf("create source file: %w", createErr)
						}
						if closeErr := f.Close(); closeErr != nil {
							return fmt.Errorf("close source file: %w", closeErr)
						}
						if err := ui.Success(w, fmt.Sprintf("Created %s", filepath.Base(source))); err != nil {
							return err
						}
					} else {
						return nil
					}
				} else {
					return nil
				}
			}

			prune, _ := cmd.Flags().GetBool("prune")
			result, err := a.deps.Vault.Sync(cmd.Context(), source, prune, a.deps.ConfirmOverwrite)
			if err != nil {
				return err
			}

			if err := a.saveVault(cmd); err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			total := len(result.Added) + len(result.Changed) + len(result.Removed) + len(result.Kept) + len(result.Unchanged)
			if err := ui.Success(w, fmt.Sprintf("Synced %d keys", total)); err != nil {
				return err
			}
			for _, k := range result.Added {
				if _, err := fmt.Fprintf(w, "  + Added: %s\n", k); err != nil {
					return err
				}
			}
			for _, k := range result.Changed {
				if _, err := fmt.Fprintf(w, "  ~ Changed: %s\n", k); err != nil {
					return err
				}
			}
			for _, k := range result.Removed {
				if _, err := fmt.Fprintf(w, "  - Removed: %s\n", k); err != nil {
					return err
				}
			}
			if len(result.Kept) > 0 {
				if _, err := fmt.Fprintf(w, "  ! Kept %d vault-only keys (use --prune to remove)\n", len(result.Kept)); err != nil {
					return err
				}
			}
			if len(result.Unchanged) > 0 {
				if _, err := fmt.Fprintf(w, "  Unchanged: %d %s\n", len(result.Unchanged), ui.Plural(len(result.Unchanged), "key", "keys")); err != nil {
					return err
				}
			}
			allKeys := make([]string, 0, total)
			allKeys = append(allKeys, result.Added...)
			allKeys = append(allKeys, result.Changed...)
			allKeys = append(allKeys, result.Removed...)
			allKeys = append(allKeys, result.Kept...)
			allKeys = append(allKeys, result.Unchanged...)
			a.auditLog("sync", fmt.Sprintf("Synced %d keys", total), allKeys...)
			return nil
		},
	}

	cmd.Flags().String("source", "", "source .env file (default from config)")
	cmd.Flags().Bool("prune", false, "remove vault keys not present in the source .env file")
	return cmd
}
