package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/roman-kolpachev/envseal/internal/ui"
)

func (a *App) newGrantCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "grant NAME",
		Short: "Grant vault access to a new recipient",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.requireDeps(cmd, true); err != nil {
				return err
			}

			name := args[0]
			pubkey, _ := cmd.Flags().GetString("key")
			keyFile, _ := cmd.Flags().GetString("key-file")

			if pubkey == "" && keyFile == "" {
				return fmt.Errorf("provide --key or --key-file")
			}
			if keyFile != "" {
				if len(keyFile) > maxUserPathLength {
					return fmt.Errorf("--key-file path too long (%d bytes, maximum %d)", len(keyFile), maxUserPathLength)
				}
				const maxKeyFileSize = 4096
				lstatInfo, err := os.Lstat(keyFile)
				if err != nil {
					return fmt.Errorf("stat key file: %w", err)
				}
				if !lstatInfo.Mode().IsRegular() {
					return fmt.Errorf("key file %q is not a regular file", keyFile)
				}
				if lstatInfo.Size() > maxKeyFileSize {
					return fmt.Errorf("key file too large (max %d bytes)", maxKeyFileSize)
				}
				//nolint:gosec // G304: keyFile was just Lstat-verified above (regular file, size limit); this is a user-supplied --key-file flag, not attacker-controlled traversal.
				f, err := os.Open(keyFile)
				if err != nil {
					return fmt.Errorf("open key file: %w", err)
				}
				fdInfo, fErr := f.Stat()
				if fErr != nil {
					return errors.Join(
						fmt.Errorf("stat open key file: %w", fErr),
						f.Close(),
					)
				}
				if !os.SameFile(lstatInfo, fdInfo) {
					return errors.Join(
						fmt.Errorf("key file %q changed between stat and open", keyFile),
						f.Close(),
					)
				}
				data, readErr := io.ReadAll(io.LimitReader(f, maxKeyFileSize+1))
				closeErr := f.Close()
				if readErr != nil {
					return errors.Join(fmt.Errorf("read key file: %w", readErr), closeErr)
				}
				if closeErr != nil {
					return fmt.Errorf("close key file: %w", closeErr)
				}
				if int64(len(data)) > maxKeyFileSize {
					return fmt.Errorf("key file too large (max %d bytes)", maxKeyFileSize)
				}
				pubkey = strings.TrimSpace(string(data))
			}

			if _, err := age.ParseX25519Recipient(pubkey); err != nil {
				return fmt.Errorf("invalid age public key: %w", err)
			}

			force, _ := cmd.Flags().GetBool("force")
			if err := a.deps.Config.AddRecipient(name, pubkey, force); err != nil {
				return err
			}

			dir, err := a.workDir()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}

			newRecipients := a.deps.Config.RecipientKeys()
			envVaults, totalSecrets, err := a.reEncryptAllVaults(cmd.Context(), dir, newRecipients)
			if err != nil {
				return err
			}

			// Save vaults before config so that a partial failure does not leave the
			// config updated (new recipient listed) while some vaults still lack the
			// new recipient's wrapped key.
			if err := a.saveAllVaults(dir, envVaults); err != nil {
				return err
			}
			if err := a.saveConfig(); err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			recipients := a.deps.Config.RecipientKeys()
			if err := ui.Success(w, fmt.Sprintf("Granted access to %s", name)); err != nil {
				return err
			}
			if err := ui.Success(w, fmt.Sprintf(
				"Re-encrypted %d %s across %d %s for %d %s",
				totalSecrets, ui.Plural(totalSecrets, "secret", "secrets"),
				len(envVaults), ui.Plural(len(envVaults), "environment", "environments"),
				len(recipients), ui.Plural(len(recipients), "recipient", "recipients"),
			)); err != nil {
				return err
			}
			a.auditLogWithTarget("grant", name, fmt.Sprintf("Granted access to %s", name))
			return nil
		},
	}

	cmd.Flags().String("key", "", "recipient's public key")
	cmd.Flags().String("key-file", "", "path to recipient's public key file")
	cmd.Flags().Bool("force", false, "replace an existing recipient's key (revokes decrypt access for the old key)")
	return cmd
}
