package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

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
  aman collect prod-db-password --ttl 4h
  aman collect prod-db-password   # saved to <name>-<identity>.share, expires in 24h`,
	Args: cobra.ExactArgs(1),
	RunE: runCollect,
}

func init() {
	rootCmd.AddCommand(collectCmd)
	collectCmd.Flags().String("out", "", "output path for the .share file (default: <name>-<identity>.share)")
	collectCmd.Flags().Duration("ttl", 24*time.Hour, "share file validity window (default: 24h)")
}

// ShareFile is the JSON wrapper written by 'aman collect'.
type ShareFile struct {
	Vault     string          `json:"vault"`
	Entry     string          `json:"entry"`
	Member    string          `json:"member"`
	ExpiresAt time.Time       `json:"expires_at"`
	Share     json.RawMessage `json:"share"`
}

func runCollect(cmd *cobra.Command, args []string) error {
	name := args[0]
	ttl, _ := cmd.Flags().GetDuration("ttl")

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
	entryPath, err := entry.EntryPath(v.Dir, name)
	if err != nil {
		return err
	}
	e, err := entry.Load(entryPath)
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

	shareData, err := crypto.MarshalShare(share)
	if err != nil {
		return fmt.Errorf("marshal share: %w", err)
	}

	wrapper := ShareFile{
		Vault:     v.Cfg.Name,
		Entry:     name,
		Member:    identity,
		ExpiresAt: time.Now().UTC().Add(ttl),
		Share:     shareData,
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
	fmt.Printf("  Expires : %s\n", wrapper.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("  Required: %d of %d shares\n", e.Threshold, len(e.Recipients))
	fmt.Printf("  Send this file to the person running 'aman get --shares ...'\n")
	return nil
}

// sanitize replaces characters unsafe for filenames.
func sanitize(s string) string {
	return strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "-").Replace(s)
}
