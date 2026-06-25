package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/term"

	"github.com/roman-kolpachev/envseal/cmd"
	"github.com/roman-kolpachev/envseal/internal/audit"
	"github.com/roman-kolpachev/envseal/internal/config"
	"github.com/roman-kolpachev/envseal/internal/crypto"
	"github.com/roman-kolpachev/envseal/internal/keyring"
	"github.com/roman-kolpachev/envseal/internal/runner"
	"github.com/roman-kolpachev/envseal/internal/ui"
	"github.com/roman-kolpachev/envseal/internal/vault"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		// A direct (unwrapped) *exec.ExitError means `envseal run`'s child
		// process already wrote its own diagnostics to the inherited
		// stdout/stderr (runner.RunSealed and the Windows execProcess both
		// return cmd.Run()'s result as-is) — mirror its exit code silently
		// rather than double-print. errors.As would also match this against
		// e.g. `import --from-sops`/`--from-dotenvx` failures, whose
		// sops/dotenvx subprocess output is captured (not inherited) and
		// wrapped in a descriptive error — those must still be printed, so
		// the check is a plain type assertion, not an unwrap-through-chain.
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		// Sanitize before echoing: error text can embed untrusted input
		// (unknown flag names from cobra, TOML parse context, file paths)
		// which could carry terminal escape sequences.
		fmt.Fprintf(os.Stderr, "Error: %s\n", ui.SanitizeMultiline(err.Error()))
		os.Exit(1)
	}
}

func run() error {
	invocationDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	// Walk upward for an initialized project the same way `git`, `npm`, and
	// `cargo` do, so commands work from any subdirectory (e.g. a monorepo's
	// apps/backend/ when .envseal/ lives at the repo root) rather than only
	// the exact directory containing .envseal/. `init` is exempted via
	// InvocationDir — see its doc comment on cmd.Deps.
	dir := invocationDir
	if projectDir, err := config.FindProjectDir(invocationDir); err == nil {
		dir = projectDir
	}

	deps := cmd.Deps{Dir: dir, InvocationDir: invocationDir, Version: version}
	deps.ReadSecret = func(prompt string) ([]byte, error) {
		fmt.Fprint(os.Stderr, prompt)

		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}

		return password, nil
	}
	deps.Confirm = func(prompt string) (bool, error) {
		fmt.Fprint(os.Stderr, prompt)
		reader := bufio.NewReader(os.Stdin)
		input, err := reader.ReadString('\n')
		if err != nil {
			return false, err
		}
		input = strings.ToLower(strings.TrimSpace(input))
		return input == "" || input == "y" || input == "yes", nil
	}
	deps.ConfirmOverwrite = func(key string) vault.ConflictChoice {
		fmt.Fprintf(os.Stderr, "Key %q already exists. Overwrite? [y]es / [N]o / [a]ll: ", key)
		reader := bufio.NewReader(os.Stdin)
		input, err := reader.ReadString('\n')
		if err != nil {
			return vault.ConflictNo
		}
		switch strings.ToLower(strings.TrimSpace(input)) {
		case "y", "yes":
			return vault.ConflictYes
		case "a", "all":
			return vault.ConflictAll
		default:
			return vault.ConflictNo
		}
	}
	deps.SelectOption = func(prompt string, options []string) (string, error) {
		reader := bufio.NewReader(os.Stdin)
		fmt.Fprintln(os.Stderr, prompt+":")
		for i, opt := range options {
			// Filenames come from directory listings and may contain terminal
			// escape sequences — sanitize before echoing to the user's terminal.
			fmt.Fprintf(os.Stderr, "  [%d] %s\n", i+1, ui.SanitizeForTerminal(opt))
		}
		fmt.Fprint(os.Stderr, "Enter number or path: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		input = strings.TrimSpace(input)
		if input == "" {
			return "", fmt.Errorf("no file selected")
		}

		if idx, ok := parseIndex(input, len(options)); ok {
			return options[idx], nil
		}
		return input, nil
	}
	deps.Audit = audit.NewLogger(config.AuditPath(dir))

	configPath := config.ConfigPath(dir)
	if cfg, err := config.Load(configPath); err == nil {
		deps.Config = cfg

		if id, err := keyring.Discover(dir); err == nil {
			deps.Keyring = id
			enc := crypto.NewAgeEncryptor(id)
			deps.Vault = vault.NewService(enc, cfg)
			deps.Runner = runner.New(deps.Vault)
		} else {
			fmt.Fprintf(os.Stderr, "Warning: config loaded but private key not found: %s\n", ui.SanitizeMultiline(err.Error()))
		}
	} else if _, statErr := os.Stat(configPath); statErr == nil {
		fmt.Fprintf(os.Stderr, "Warning: config file exists but could not be loaded: %s\n", ui.SanitizeMultiline(err.Error()))
	}

	app := cmd.NewApp(deps)
	return app.Execute()
}

func parseIndex(input string, max int) (int, bool) {
	n, err := strconv.Atoi(input)
	if err != nil || n < 1 || n > max {
		return 0, false
	}
	return n - 1, true
}
