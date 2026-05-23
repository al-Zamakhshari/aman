package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/al-Zamakhshari/aman/internal/audit"
	"github.com/spf13/cobra"
)

var logCmd = &cobra.Command{
	Use:   "log",
	Short: "Show the vault audit log",
	Long: `Displays the hash-chained audit log for the vault.

Every vault operation is recorded with a timestamp, actor, and chain hash.
Use --verify to check the integrity of the log.

Examples:
  aman log
  aman log --verify
  aman log --action get`,
	RunE: runLog,
}

func init() {
	rootCmd.AddCommand(logCmd)
	logCmd.Flags().Bool("verify", false, "verify the hash chain integrity")
	logCmd.Flags().String("action", "", "filter by action (add, get, grant, revoke, delete)")
	logCmd.Flags().Int("tail", 0, "show last N entries")
}

func runLog(cmd *cobra.Command, _ []string) error {
	verify, _ := cmd.Flags().GetBool("verify")
	actionFilter, _ := cmd.Flags().GetString("action")
	tail, _ := cmd.Flags().GetInt("tail")

	logPath := filepath.Join(vaultDir(), "audit.log")

	if verify {
		if err := audit.Verify(logPath); err != nil {
			return fmt.Errorf("audit log integrity check FAILED: %w", err)
		}
		fmt.Println("✓ Audit log integrity verified — chain is intact")
		return nil
	}

	entries, err := audit.ReadAll(logPath)
	if err != nil {
		return err
	}

	if actionFilter != "" {
		var filtered []audit.LogEntry
		for _, e := range entries {
			if e.Event.Action == actionFilter {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}

	if tail > 0 && len(entries) > tail {
		entries = entries[len(entries)-tail:]
	}

	if len(entries) == 0 {
		fmt.Println("No audit log entries found.")
		return nil
	}

	fmt.Printf("%-4s  %-20s  %-10s  %-15s  %s\n", "#", "TIME", "ACTION", "ACTOR", "ENTRY / DETAIL")
	fmt.Println("────  ────────────────────  ──────────  ───────────────  ──────────────────────")
	for _, e := range entries {
		detail := e.Event.Entry
		if len(e.Event.Recipients) > 0 {
			for _, r := range e.Event.Recipients {
				detail += " → " + r
			}
		}
		fmt.Printf("%-4d  %-20s  %-10s  %-15s  %s\n",
			e.Seq,
			e.Time.Format("2006-01-02 15:04:05"),
			e.Event.Action,
			e.Event.Actor,
			detail,
		)
	}

	return nil
}
