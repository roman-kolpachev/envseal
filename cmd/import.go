package cmd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/roman-kolpachev/envseal/internal/discovery"
	"github.com/roman-kolpachev/envseal/internal/dotenv"
	"github.com/roman-kolpachev/envseal/internal/ui"
	"github.com/roman-kolpachev/envseal/internal/vault"
)

func (a *App) newImportCmd() *cobra.Command {
	var force bool
	var fromSops bool
	var fromDotenvx bool

	cmd := &cobra.Command{
		Use:   "import [PATH]",
		Short: "Import secrets from a .env file",
		Long: `Bulk-import all keys from an existing .env file into the vault.
Safe to re-run — skips existing keys unless --force is used.

Use --from-sops to import from a SOPS-encrypted file. Requires the sops
binary to be installed. envseal will run "sops -d <file>" to decrypt,
then import the plaintext entries.

Use --from-dotenvx to import from a dotenvx-encrypted file. Requires the
dotenvx binary to be installed and able to decrypt the file (via
DOTENV_PRIVATE_KEY or a .env.keys file). envseal will run
"dotenvx decrypt --stdout --env-file=<file>" to decrypt, then import the
plaintext entries (the DOTENV_PUBLIC_KEY metadata line is skipped).`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.requireDeps(cmd, true); err != nil {
				return err
			}

			if fromSops && fromDotenvx {
				return fmt.Errorf("--from-sops and --from-dotenvx are mutually exclusive")
			}

			dir, err := a.workDir()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}

			envName, _ := cmd.Flags().GetString("env")
			if envName == "" {
				envName = a.deps.Config.Default
			}
			env, err := a.deps.Config.GetEnvironment(envName)
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			if err := ui.Info(w, fmt.Sprintf("Importing into %s vault (%s)", envName, ui.SanitizeForTerminal(env.VaultPath))); err != nil {
				return err
			}

			var onConflict vault.OnConflict
			if force {
				onConflict = func(key string) vault.ConflictChoice { return vault.ConflictAll }
			} else if a.deps.ConfirmOverwrite != nil {
				onConflict = a.deps.ConfirmOverwrite
			}

			if fromSops {
				return a.importFromSops(cmd, args, dir, onConflict)
			}

			if fromDotenvx {
				return a.importFromDotenvx(cmd, args, dir, onConflict)
			}

			path, err := a.resolveImportPath(args, dir)
			if err != nil {
				return err
			}

			fullPath, err := safeUserPath(dir, path)
			if err != nil {
				return err
			}

			result, err := a.deps.Vault.Import(cmd.Context(), fullPath, onConflict)
			if err != nil {
				return err
			}

			if err := a.saveVault(cmd); err != nil {
				return err
			}

			return a.printImportResult(cmd, result, path)
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "overwrite all existing keys without asking")
	cmd.Flags().BoolVar(&fromSops, "from-sops", false, "decrypt with sops before importing")
	cmd.Flags().BoolVar(&fromDotenvx, "from-dotenvx", false, "decrypt with dotenvx before importing")
	return cmd
}

func (a *App) importFromSops(cmd *cobra.Command, args []string, dir string, onConflict vault.OnConflict) error {
	if len(args) == 0 {
		return fmt.Errorf("--from-sops requires a file path argument")
	}

	sopsPath, err := exec.LookPath("sops")
	if err != nil {
		return fmt.Errorf("sops binary not found in PATH — install it from https://github.com/getsops/sops")
	}

	filePath, err := safeUserPath(dir, args[0])
	if err != nil {
		return err
	}

	var stdout, stderr bytes.Buffer
	// sops infers format from the file extension when --input-type/
	// --output-type are omitted, and only recognizes a bare ".env" suffix as
	// dotenv — every name this command's own docs use as an example
	// (".env.sops", "secrets.env.enc") falls through to sops's default (JSON)
	// and fails to parse. Passing the types explicitly makes decryption
	// independent of the source filename.
	//nolint:gosec // G204: sopsPath is resolved via exec.LookPath (not a shell), and filePath was already containment-checked by safeUserPath above; "--" prevents flag injection from a filename.
	sopsCmd := exec.CommandContext(cmd.Context(), sopsPath, "-d", "--input-type", "dotenv", "--output-type", "dotenv", "--", filePath)
	sopsCmd.Env = filterSensitiveEnv(os.Environ())
	sopsCmd.Stdout = &stdout
	sopsCmd.Stderr = &stderr
	defer func() { clear(stdout.Bytes()) }()
	defer func() { clear(stderr.Bytes()) }()

	if err := sopsCmd.Run(); err != nil {
		verbose, _ := cmd.Flags().GetBool("verbose")
		if verbose {
			stderrStr := strings.TrimSpace(stderr.String())
			const maxSopsStderr = 256
			if len(stderrStr) > maxSopsStderr {
				stderrStr = stderrStr[:maxSopsStderr] + "... (truncated)"
			}
			return fmt.Errorf("sops decrypt failed: %s: %w", stderrStr, err)
		}
		return fmt.Errorf("sops decrypt failed (re-run with --verbose for details): %w", err)
	}

	entries, err := dotenv.Parse(bytes.NewReader(stdout.Bytes()))
	if err != nil {
		return fmt.Errorf("parse sops output: %w", err)
	}
	defer func() {
		for i := range entries {
			clear(entries[i].Value)
		}
		clear(entries)
	}()
	

	result, err := a.deps.Vault.ImportEntries(cmd.Context(), entries, onConflict)
	if err != nil {
		return err
	}

	if err := a.saveVault(cmd); err != nil {
		return err
	}

	return a.printImportResult(cmd, result, args[0])
}

func (a *App) importFromDotenvx(cmd *cobra.Command, args []string, dir string, onConflict vault.OnConflict) error {
	if len(args) == 0 {
		return fmt.Errorf("--from-dotenvx requires a file path argument")
	}

	dotenvxPath, err := exec.LookPath("dotenvx")
	if err != nil {
		return fmt.Errorf("dotenvx binary not found in PATH — install it from https://dotenvx.com")
	}

	filePath, err := safeUserPath(dir, args[0])
	if err != nil {
		return err
	}

	var stdout, stderr bytes.Buffer
	//nolint:gosec // G204: dotenvxPath is resolved via exec.LookPath (not a shell); filePath was already containment-checked by safeUserPath above, and the "--env-file=" joined form prevents it from being reinterpreted as a flag.
	dotenvxCmd := exec.CommandContext(cmd.Context(), dotenvxPath, "decrypt", "--stdout", "--env-file="+filePath)
	dotenvxCmd.Env = filterSensitiveEnv(os.Environ())
	dotenvxCmd.Stdout = &stdout
	dotenvxCmd.Stderr = &stderr
	defer func() { clear(stdout.Bytes()) }()
	defer func() { clear(stderr.Bytes()) }()

	if err := dotenvxCmd.Run(); err != nil {
		verbose, _ := cmd.Flags().GetBool("verbose")
		if verbose {
			stderrStr := strings.TrimSpace(stderr.String())
			const maxDotenvxStderr = 256
			if len(stderrStr) > maxDotenvxStderr {
				stderrStr = stderrStr[:maxDotenvxStderr] + "... (truncated)"
			}
			return fmt.Errorf("dotenvx decrypt failed: %s: %w", stderrStr, err)
		}
		return fmt.Errorf("dotenvx decrypt failed (re-run with --verbose for details): %w", err)
	}

	parsed, err := dotenv.Parse(bytes.NewReader(stdout.Bytes()))
	if err != nil {
		return fmt.Errorf("parse dotenvx output: %w", err)
	}
	defer func() {
		for i := range parsed {
			clear(parsed[i].Value)
		}
		clear(parsed)
	}()

	// dotenvx embeds its own public key as a plaintext DOTENV_PUBLIC_KEY
	// (or DOTENV_PUBLIC_KEY_<ENVIRONMENT>) entry in decrypted output —
	// that's metadata, not a secret, so it's excluded from the import.
	entries := make([]dotenv.Entry, 0, len(parsed))
	for _, e := range parsed {
		if strings.HasPrefix(e.Key, "DOTENV_PUBLIC_KEY") {
			clear(e.Value)
			continue
		}
		entries = append(entries, e)
	}

	result, err := a.deps.Vault.ImportEntries(cmd.Context(), entries, onConflict)
	if err != nil {
		return err
	}

	if err := a.saveVault(cmd); err != nil {
		return err
	}

	return a.printImportResult(cmd, result, args[0])
}

func (a *App) printImportResult(cmd *cobra.Command, result *vault.ImportResult, source string) error {
	w := cmd.OutOrStdout()
	if len(result.Imported) == 0 {
		return ui.Info(w, fmt.Sprintf("Nothing to import — all %d keys already in vault", result.Total))
	}

	if err := ui.Success(w, fmt.Sprintf("Imported %d %s from %s", len(result.Imported), ui.Plural(len(result.Imported), "secret", "secrets"), ui.SanitizeForTerminal(source))); err != nil {
		return err
	}
	for _, k := range result.Imported {
		if _, err := fmt.Fprintf(w, "  + %s\n", k); err != nil {
			return err
		}
	}
	if len(result.Skipped) > 0 {
		if _, err := fmt.Fprintf(w, "  Skipped: %d %s (already in vault)\n", len(result.Skipped), ui.Plural(len(result.Skipped), "key", "keys")); err != nil {
			return err
		}
	}
	a.auditLog("import", fmt.Sprintf("Imported %d secrets from %s", len(result.Imported), source), result.Imported...)
	return nil
}

func filterSensitiveEnv(env []string) []string {
	filtered := make([]string, 0, len(env))
	for _, e := range env {
		k, _, _ := strings.Cut(e, "=")
		if strings.EqualFold(k, "ENVSEAL_KEY") || strings.EqualFold(k, "ENVSEAL_SECRETS") {
			continue
		}
		filtered = append(filtered, e)
	}
	return filtered
}

func (a *App) resolveImportPath(args []string, dir string) (string, error) {
	if len(args) > 0 {
		return args[0], nil
	}

	if a.deps.SelectOption == nil {
		return ".env", nil
	}

	envFiles, err := discovery.FindEnvFiles(dir)
	if err != nil {
		return "", fmt.Errorf("scan for .env files: %w", err)
	}

	if len(envFiles) == 0 {
		selected, err := a.deps.SelectOption("No .env files found — enter path", nil)
		if err != nil {
			return "", fmt.Errorf("select source file: %w", err)
		}
		return selected, nil
	}

	selected, err := a.deps.SelectOption("Select source file", envFiles)
	if err != nil {
		return "", fmt.Errorf("select source file: %w", err)
	}
	return selected, nil
}

