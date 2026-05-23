package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/al-Zamakhshari/aman/internal/crypto"
	"github.com/al-Zamakhshari/aman/internal/entry"
	"github.com/spf13/cobra"
)

var collectCmd = &cobra.Command{
	Use:   "collect <name>",
	Short: "Unwrap your Shamir share for a threshold entry",
	Long: `For entries protected by M-of-N threshold encryption, each recipient
holds one Shamir share of the FEK — not the whole key. Use 'collect' to
unwrap your share and save it to a .share file that an authorized combiner
can use with 'aman get --shares'.

Examples:
  aman collect prod-db-password --out /tmp/alice.share
  aman collect prod-db-password   # saved to <name>-<identity>.share`,
	Args: cobra.ExactArgs(1),
	RunE: runCollect,
}

func init() {
	rootCmd.AddCommand(collectCmd)
	collectCmd.Flags().String("out", "", "output path for the .share file (default: <name>-<identity>.share)")
}

func runCollect(cmd *cobra.Command, args []string) error {
	name := args[0]

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

	// Load the raw entry.
	e, err := entry.Load(entry.EntryPath(v.Dir, name))
	if err != nil {
		return err
	}

	if e.Threshold <= 1 {
		return fmt.Errorf("%q uses threshold=1 — use 'aman get' directly (no share collection needed)", name)
	}

	share, err := entry.CollectShare(e, identity, kp, v.Cfg.Name)
	if err != nil {
		return fmt.Errorf("collect share: %w", err)
	}

	data, err := crypto.MarshalShare(share)
	if err != nil {
		return fmt.Errorf("marshal share: %w", err)
	}

	// Wrap with metadata so the combiner knows which entry/vault this belongs to.
	type shareFile struct {
		Vault  string          `json:"vault"`
		Entry  string          `json:"entry"`
		Member string          `json:"member"`
		Share  json.RawMessage `json:"share"`
	}
	wrapper := shareFile{
		Vault:  v.Cfg.Name,
		Entry:  name,
		Member: identity,
		Share:  data,
	}
	out, err := json.MarshalIndent(wrapper, "", "  ")
	if err != nil {
		return err
	}

	outPath, _ := cmd.Flags().GetString("out")
	if outPath == "" {
		outPath = filepath.Join(".", fmt.Sprintf("%s-%s.share", sanitize(name), sanitize(identity)))
	}

	if err := os.WriteFile(outPath, out, 0600); err != nil {
		return fmt.Errorf("write share file: %w", err)
	}

	fmt.Printf("✓ Share for %q saved → %s\n", name, outPath)
	fmt.Printf("  Send this file to the person running 'aman get --shares ...' to reconstruct the secret.\n")
	fmt.Printf("  Required: %d of %d shares\n", e.Threshold, len(e.Recipients))
	return nil
}

// sanitize replaces characters unsafe for filenames.
func sanitize(s string) string {
	return strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "-").Replace(s)
}
