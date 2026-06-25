package cmd

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"

	"github.com/roman-kolpachev/envseal/internal/dotenv"
	"github.com/roman-kolpachev/envseal/internal/envcheck"
	"github.com/roman-kolpachev/envseal/internal/ui"
	"github.com/roman-kolpachev/envseal/internal/vault"
)

func (a *App) newPullCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pull",
		Short: "Decrypt vault and write a .env file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.requireDeps(cmd, false); err != nil {
				return err
			}

			env, err := a.resolveEnvironment(cmd)
			if err != nil {
				return err
			}

			// Check for dangerous variable names from the key list alone, before
			// decrypting anything. Key names don't require decryption to inspect,
			// and checking first means a tampered vault (which fails the
			// decrypt-time integrity check) doesn't mask this guard — pull must
			// refuse a vault containing a dangerous var regardless of whether its
			// ciphertext also happens to be malformed.
			keys, err := a.deps.Vault.List()
			if err != nil {
				return err
			}
			sort.Strings(keys)

			for _, k := range keys {
				if envcheck.IsDangerous(k) {
					return fmt.Errorf(
						"vault contains dangerous environment variable %q — remove it with `envseal rm %s` before pulling",
						k, k,
					)
				}
			}

			all, err := a.deps.Vault.DecryptAll(cmd.Context())
			if err != nil {
				return err
			}
			defer vault.ClearSecretMap(all)

			dir, err := a.workDir()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}

			outputFlag, _ := cmd.Flags().GetString("output")
			var output string
			if outputFlag != "" {
				var pathErr error
				output, pathErr = safeUserPath(dir, outputFlag)
				if pathErr != nil {
					return pathErr
				}
			} else {
				var pathErr error
				output, pathErr = safePath(dir, env.SourcePath)
				if pathErr != nil {
					return pathErr
				}
			}

			entries := make([]dotenv.Entry, len(keys))
			for i, k := range keys {
				entries[i] = dotenv.Entry{Key: k, Value: all[k]}
			}

			if err := dotenv.MarshalFile(output, entries); err != nil {
				return fmt.Errorf("write %s: %w", output, err)
			}

			if err := ui.Success(cmd.OutOrStdout(), fmt.Sprintf("Pulled %d %s to %s", len(all), ui.Plural(len(all), "secret", "secrets"), ui.SanitizeForTerminal(filepath.Base(output)))); err != nil {
				return err
			}
			a.auditLog("pull", fmt.Sprintf("Pulled %d secrets to %s", len(all), filepath.Base(output)), keys...)
			return nil
		},
	}

	cmd.Flags().StringP("output", "o", "", "output file path (default: environment source path)")
	return cmd
}
