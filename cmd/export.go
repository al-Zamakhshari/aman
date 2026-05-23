package cmd

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/al-Zamakhshari/aman/internal/entry"
	"github.com/spf13/cobra"
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export accessible secrets to a file",
	Long: `Decrypts all secrets you have access to and writes them to a file.

Supported formats:
  --format bitwarden   Bitwarden-compatible JSON (default)
  --format csv         Generic CSV: name,username,password,url,notes,tags,totp

WARNING: The output file contains plaintext credentials.
Delete it immediately after use.

Examples:
  aman export --out export.json
  aman export --format csv --out export.csv`,
	RunE: runExport,
}

func init() {
	rootCmd.AddCommand(exportCmd)
	exportCmd.Flags().String("format", "bitwarden", "output format: bitwarden, csv")
	exportCmd.Flags().String("out", "", "output file path (required)")
	exportCmd.MarkFlagRequired("out") //nolint:errcheck
}

type exportRecord struct {
	name    string
	payload *entry.Payload
	tags    []string
}

func runExport(cmd *cobra.Command, _ []string) error {
	format, _ := cmd.Flags().GetString("format")
	outPath, _ := cmd.Flags().GetString("out")

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

	items, err := v.List(identity)
	if err != nil {
		return err
	}

	var records []exportRecord
	var skipped int
	for _, item := range items {
		if !item.CanDecrypt {
			skipped++
			continue
		}
		p, err := v.Get(item.Name, identity, kp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  skip %s: %v\n", item.Name, err)
			skipped++
			continue
		}
		records = append(records, exportRecord{name: item.Name, payload: p, tags: item.Tags})
	}

	switch strings.ToLower(format) {
	case "bitwarden":
		if err := exportBitwarden(outPath, records); err != nil {
			return err
		}
	case "csv":
		if err := exportCSV(outPath, records); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown format %q — use: bitwarden, csv", format)
	}

	fmt.Printf("✓ Exported %d entries → %s", len(records), outPath)
	if skipped > 0 {
		fmt.Printf(" (%d skipped — not a recipient or error)", skipped)
	}
	fmt.Println()
	fmt.Println("⚠  Delete this file immediately after use — it contains plaintext credentials.")
	return nil
}

// ── Bitwarden format ─────────────────────────────────────────────────────────

type bitwardenExport struct {
	Encrypted bool            `json:"encrypted"`
	Items     []bitwardenItem `json:"items"`
}

type bitwardenItem struct {
	ID    string          `json:"id"`
	Type  int             `json:"type"` // 1 = login
	Name  string          `json:"name"`
	Notes string          `json:"notes,omitempty"`
	Login *bitwardenLogin `json:"login,omitempty"`
}

type bitwardenLogin struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	URIs     []struct {
		URI string `json:"uri"`
	} `json:"uris,omitempty"`
	TOTP string `json:"totp,omitempty"`
}

func exportBitwarden(path string, records []exportRecord) error {
	items := make([]bitwardenItem, 0, len(records))
	for _, r := range records {
		login := &bitwardenLogin{
			Username: r.payload.Username,
			Password: r.payload.Password,
			TOTP:     r.payload.TOTPSecret,
		}
		if r.payload.URL != "" {
			login.URIs = []struct {
				URI string `json:"uri"`
			}{{URI: r.payload.URL}}
		}
		items = append(items, bitwardenItem{
			ID:    fmt.Sprintf("%x", []byte(r.name+"-aman"))[:8],
			Type:  1,
			Name:  r.name,
			Notes: r.payload.Notes,
			Login: login,
		})
	}
	data, err := json.MarshalIndent(bitwardenExport{Encrypted: false, Items: items}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func exportCSV(path string, records []exportRecord) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	if err := w.Write([]string{"name", "username", "password", "url", "notes", "tags", "totp"}); err != nil {
		return err
	}
	for _, r := range records {
		row := []string{
			r.name,
			r.payload.Username,
			r.payload.Password,
			r.payload.URL,
			r.payload.Notes,
			strings.Join(r.tags, ";"),
			r.payload.TOTPSecret,
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}
