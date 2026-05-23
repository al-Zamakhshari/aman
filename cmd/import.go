package cmd

import (
	"fmt"
	"strings"

	"github.com/al-Zamakhshari/aman/internal/importer"
	"github.com/spf13/cobra"
)

var importCmd = &cobra.Command{
	Use:   "import <file>",
	Short: "Import credentials from another password manager",
	Long: `Imports credentials from an exported file and encrypts them into the vault.

Supported formats:
  --from bitwarden    Bitwarden JSON export
  --from 1password    1Password JSON export
  --from lastpass     LastPass CSV export
  --from csv          Generic CSV (columns: name,username,password,url,notes)

The format is auto-detected from the file if --from is omitted.

All imported entries are encrypted to the recipients you specify with --to.

Examples:
  aman import bitwarden_export.json --to alice,bob
  aman import lastpass_export.csv --from lastpass --to alice
  aman import --from 1password 1p_export.json --to alice,bob,carol --dry-run`,
	Args: cobra.ExactArgs(1),
	RunE: runImport,
}

func init() {
	rootCmd.AddCommand(importCmd)
	importCmd.Flags().String("from", "", "source format: bitwarden, 1password, lastpass, csv (auto-detected if omitted)")
	importCmd.Flags().String("to", "", "comma-separated recipients (required)")
	importCmd.Flags().Bool("dry-run", false, "parse and show what would be imported without writing")
	importCmd.Flags().Bool("skip-existing", true, "skip entries that already exist in the vault")
	importCmd.MarkFlagRequired("to") //nolint:errcheck
}

func runImport(cmd *cobra.Command, args []string) error {
	file := args[0]
	fromFlag, _ := cmd.Flags().GetString("from")
	toFlag, _ := cmd.Flags().GetString("to")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	skipExisting, _ := cmd.Flags().GetBool("skip-existing")

	recipients := splitCSV(toFlag)
	if len(recipients) == 0 {
		return fmt.Errorf("--to requires at least one recipient")
	}

	// Detect or parse format.
	var format importer.Format
	switch strings.ToLower(fromFlag) {
	case "bitwarden":
		format = importer.FormatBitwarden
	case "1password", "onepassword":
		format = importer.FormatOnePassword
	case "lastpass":
		format = importer.FormatLastPass
	case "csv", "":
		if fromFlag == "" {
			format = importer.DetectFormat(file)
			fmt.Printf("Auto-detected format: %s\n", format)
		} else {
			format = importer.FormatCSV
		}
	default:
		return fmt.Errorf("unknown format %q — use: bitwarden, 1password, lastpass, csv", fromFlag)
	}

	records, err := importer.Import(file, format)
	if err != nil {
		return fmt.Errorf("import: %w", err)
	}

	if len(records) == 0 {
		fmt.Println("No importable records found in the file.")
		return nil
	}

	fmt.Printf("Found %d records to import → recipients: %s\n\n", len(records), strings.Join(recipients, ", "))

	if dryRun {
		for i, r := range records {
			fmt.Printf("  [%d] %-35s  user=%-25s  url=%s\n",
				i+1, r.Name, r.Payload.Username, r.Payload.URL)
		}
		fmt.Printf("\nDry run — nothing written. Remove --dry-run to import.\n")
		return nil
	}

	// Load vault and keys.
	identity, err := identityName()
	if err != nil {
		return err
	}
	kp, err := loadKeyPair(identity)
	if err != nil {
		return err
	}
	v, err := openVault()
	if err != nil {
		return err
	}

	var imported, skipped, failed int
	for _, r := range records {
		if r.Name == "" {
			skipped++
			continue
		}

		err := v.Add(r.Name, identity, r.Payload, recipients, kp, r.Tags)
		if err != nil {
			if skipExisting && isAlreadyExists(err) {
				fmt.Printf("  skip  %s (already exists)\n", r.Name)
				skipped++
				continue
			}
			fmt.Printf("  FAIL  %s: %v\n", r.Name, err)
			failed++
			continue
		}

		fmt.Printf("  ✓     %s\n", r.Name)
		imported++
	}

	fmt.Printf("\nImport complete: %d imported, %d skipped, %d failed\n", imported, skipped, failed)
	if failed > 0 {
		return fmt.Errorf("%d entries failed to import", failed)
	}
	return nil
}

func isAlreadyExists(err error) bool {
	return err != nil && strings.Contains(err.Error(), "already exists")
}
