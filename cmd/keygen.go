package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/roman-kolpachev/envseal/internal/config"
	"github.com/roman-kolpachev/envseal/internal/keyring"
	"github.com/roman-kolpachev/envseal/internal/ui"
)

func (a *App) generateAndSaveKey(dir string, force bool) (*keyring.Identity, error) {
	keyPath := config.KeysPath(dir)
	keysRel := filepath.Join(config.DirName, config.KeysFile)
	if !force {
		if _, err := os.Lstat(keyPath); err == nil {
			return nil, fmt.Errorf("private key already exists at %s — overwriting would make existing vault secrets unrecoverable. Delete the file manually if you are sure: rm %s", keysRel, keysRel)
		}
	}

	id, err := keyring.Generate()
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}

	if err := keyring.SaveToFile(id, keyPath); err != nil {
		return nil, fmt.Errorf("save private key: %w", err)
	}

	return id, nil
}

func (a *App) newKeygenCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "keygen",
		Short: "Generate a new age keypair",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// invocationDir, not workDir: keygen must always target the
			// exact directory it was run from, never get silently
			// redirected to an ancestor project's root the way every other
			// command now is (see Deps.InvocationDir on cmd.Deps, and
			// init.go's identical reasoning). Without this, a new teammate
			// running `keygen` from what they believe is an independent
			// scratch directory — exactly the standalone, pre-project use
			// case this command exists for — could be silently redirected
			// to an unrelated ancestor project higher up the tree. Worse,
			// the resulting "private key already exists — delete it if
			// you're sure: rm .envseal/keys" refusal would then point at
			// that ancestor project's real master key with no indication
			// it belongs to someone else's project, not their own
			// nonexistent one — a confused rm of that file destroys the
			// whole team's only way to decrypt every secret in the vault.
			dir, err := a.invocationDir()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			if verbose, _ := cmd.Flags().GetBool("verbose"); verbose {
				_ = ui.Info(cmd.ErrOrStderr(), fmt.Sprintf("using invocation directory %s (not an ancestor project — see keygen's own doc comment)", dir))
			}

			// keygen is documented to work standalone (e.g. a new teammate
			// generating a keypair before the project has been `init`-ed in
			// their checkout), so the .envseal directory may not exist yet.
			if err := os.MkdirAll(config.DirPath(dir), 0700); err != nil {
				return fmt.Errorf("create %s directory: %w", config.DirName, err)
			}

			id, err := a.generateAndSaveKey(dir, false)
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			if err := ui.Success(w, "Generated age keypair"); err != nil {
				return err
			}
			if err := ui.KeyValue(w, "Public key", id.PublicKey); err != nil {
				return err
			}
			return ui.KeyValue(w, "Private key", "saved to "+filepath.Join(config.DirName, config.KeysFile))
		},
	}
}
