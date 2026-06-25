package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func (a *App) newRunCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "run [-e ENV] [--sealed] -- COMMAND [ARGS...]",
		Short:              "Run a command with decrypted secrets",
		Long: `Run a command with decrypted secrets injected as environment variables.

Use --sealed to keep secrets out of the process environment. In sealed mode,
secrets are written to a temporary file (0600 permissions, deleted on exit)
and only ENVSEAL_SECRETS env var is set, pointing to that file. This reduces
exposure to tools that passively collect environment variables (crash reporters,
telemetry, printenv). It is not a sandbox — code that reads the file directly
can still access the secrets.`,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// DisableFlagParsing means cobra's usual automatic -h/--help
			// interception (which runs before RunE for every other command)
			// never happens here — without this check, `envseal run --help`
			// falls straight through to parseRunArgs, which treats "--help"
			// as the command to execute, producing a "command not found"
			// exec error instead of usage text.
			if helpRequested(args) {
				return cmd.Help()
			}

			envName, sealed, cmdArgs := parseRunArgs(args)

			if envName != "" {
				if err := cmd.Flags().Set("env", envName); err != nil {
					return err
				}
			}

			if err := a.requireDeps(cmd, false); err != nil {
				return err
			}
			// requireDeps(cmd, false) already released the vault lock before
			// returning above — see its doc comment for why that matters
			// specifically for --sealed's real, potentially long-lived child
			// process.
			if a.deps.Runner == nil {
				return fmt.Errorf("not initialized — run `envseal init` first")
			}

			if len(cmdArgs) == 0 {
				return fmt.Errorf("no command specified")
			}

			a.auditLog("run", fmt.Sprintf("running: %s (sealed=%v, args=%d)", cmdArgs[0], sealed, len(cmdArgs)-1))

			if sealed {
				return a.deps.Runner.RunSealed(cmd.Context(), cmdArgs)
			}
			return a.deps.Runner.Run(cmd.Context(), cmdArgs)
		},
	}
}

// helpRequested reports whether -h/--help appears among envseal's own flags
// — i.e. before a -- delimiter, if any — rather than as part of the child
// command's own arguments (e.g. `envseal run -- mycommand --help`, where
// --help must reach mycommand untouched, not be intercepted by envseal).
func helpRequested(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == "-h" || a == "--help" {
			return true
		}
	}
	return false
}

func parseRunArgs(args []string) (envName string, sealed bool, cmdArgs []string) {
	i := 0
	for i < len(args) {
		if args[i] == "--" {
			cmdArgs = args[i+1:]
			return
		}
		if (args[i] == "-e" || args[i] == "--env") && i+1 < len(args) {
			envName = args[i+1]
			i += 2
			continue
		}
		if strings.HasPrefix(args[i], "--env=") {
			envName = strings.TrimPrefix(args[i], "--env=")
			i++
			continue
		}
		if strings.HasPrefix(args[i], "-e=") {
			envName = strings.TrimPrefix(args[i], "-e=")
			i++
			continue
		}
		if args[i] == "--sealed" {
			sealed = true
			i++
			continue
		}
		cmdArgs = args[i:]
		return
	}
	return
}
