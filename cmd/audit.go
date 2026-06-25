package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/roman-kolpachev/envseal/internal/audit"
	"github.com/roman-kolpachev/envseal/internal/config"
	"github.com/roman-kolpachev/envseal/internal/ui"
)

func (a *App) newAuditCmd() *cobra.Command {
	var last int

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Show recent audit log entries",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := a.workDir()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}

			logPath := config.AuditPath(dir)
			events, loadErr := a.loadAuditEvents(logPath, last)
			if loadErr != nil && len(events) == 0 {
				return loadErr
			}

			w := cmd.OutOrStdout()
			if loadErr != nil {
				// Defence in depth: never echo error text to the terminal without
				// stripping control characters, matching main.go's error path.
				if err := ui.Warn(w, ui.SanitizeMultiline(loadErr.Error())); err != nil {
					return err
				}
			}
			if len(events) == 0 {
				if jsonOut, _ := cmd.Flags().GetBool("json"); jsonOut {
					return json.NewEncoder(w).Encode([]audit.Event{})
				}
				return ui.Info(w, "No audit events recorded yet")
			}

			if jsonOut, _ := cmd.Flags().GetBool("json"); jsonOut {
				return json.NewEncoder(w).Encode(events)
			}

			headers := []string{"Timestamp", "Action", "Actor", "Keys", "Message"}
			var rows [][]string
			for _, e := range events {
				actor := e.Actor
				if len(actor) > 12 {
					actor = actor[:12] + "..."
				}
				keys := strings.Join(e.Keys, ", ")
				ts := e.Timestamp
				if len(ts) > 19 {
					ts = ts[:19]
					ts = strings.Replace(ts, "T", " ", 1)
				}
				rows = append(rows, []string{
					ui.SanitizeForTerminal(ts),
					ui.SanitizeForTerminal(e.Action),
					ui.SanitizeForTerminal(actor),
					ui.SanitizeForTerminal(keys),
					ui.SanitizeForTerminal(e.Message),
				})
			}
			return ui.Table(w, headers, rows)
		},
	}

	cmd.Flags().IntVar(&last, "last", 20, "number of recent events to show")
	cmd.Flags().Bool("json", false, "output as JSON")
	return cmd
}

func (a *App) loadAuditEvents(path string, n int) ([]audit.Event, error) {
	l := audit.NewLogger(path)
	return l.Recent(n)
}
