package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/al-Zamakhshari/aman/internal/clipboard"
	"github.com/al-Zamakhshari/aman/internal/crypto"
	"github.com/al-Zamakhshari/aman/internal/entry"
	"github.com/al-Zamakhshari/aman/internal/totp"
	"github.com/spf13/cobra"
)

var getCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Decrypt a secret and copy it to clipboard",
	Long: `Decrypts a secret using your private key and copies it to clipboard.
The clipboard is automatically cleared after 30 seconds.

Examples:
  aman get github                       copy password to clipboard
  aman get github --field totp          copy current TOTP code
  aman get github --field user          copy username
  aman get github --field url           copy URL
  aman get github --no-clipboard        print to stdout (use with care)
  aman get prod-db --shares alice.share,bob.share   combine shares for threshold entry`,
	Args: cobra.ExactArgs(1),
	RunE: runGet,
}

func init() {
	rootCmd.AddCommand(getCmd)
	getCmd.Flags().String("field", "password", "field to retrieve: password, user, url, totp, notes")
	getCmd.Flags().Bool("no-clipboard", false, "print to stdout instead of clipboard")
	getCmd.Flags().StringSlice("shares", nil, "share files for threshold entries (comma-separated paths)")
}

func runGet(cmd *cobra.Command, args []string) error {
	name := args[0]
	field, _ := cmd.Flags().GetString("field")
	noClip, _ := cmd.Flags().GetBool("no-clipboard")
	sharePaths, _ := cmd.Flags().GetStringSlice("shares")

	v, err := openVault()
	if err != nil {
		return err
	}

	// Threshold path: combine shares without our private key.
	if len(sharePaths) > 0 {
		entryPath, err := entry.EntryPath(v.Dir, name)
		if err != nil {
			return err
		}
		e, err := entry.Load(entryPath)
		if err != nil {
			return err
		}
		shares, err := loadShareFiles(sharePaths, v.Cfg.Name, name)
		if err != nil {
			return err
		}
		p, err := entry.OpenWithShares(e, shares)
		if err != nil {
			return fmt.Errorf("combine shares: %w", err)
		}
		return printOrCopy(p, name, field, noClip)
	}

	// Normal single-recipient path.
	identity, err := identityName()
	if err != nil {
		return err
	}
	kp, err := loadKeyPair(identity)
	if err != nil {
		return err
	}

	p, err := v.Get(name, identity, kp)
	if err != nil {
		return err
	}
	return printOrCopy(p, name, field, noClip)
}

// loadShareFiles reads and validates .share files produced by 'aman collect'.
func loadShareFiles(paths []string, vaultName, entryName string) ([]*crypto.ShamirShare, error) {
	var shares []*crypto.ShamirShare
	now := time.Now().UTC()

	for _, p := range paths {
		data, err := os.ReadFile(p) //nolint:gosec
		if err != nil {
			return nil, fmt.Errorf("read share file %s: %w", p, err)
		}
		var sf ShareFile
		if err := json.Unmarshal(data, &sf); err != nil {
			return nil, fmt.Errorf("parse share file %s: %w", p, err)
		}

		// Check expiry.
		if !sf.ExpiresAt.IsZero() && now.After(sf.ExpiresAt) {
			return nil, fmt.Errorf("share file %s expired at %s — ask %s to re-collect",
				p, sf.ExpiresAt.Format(time.RFC3339), sf.Member)
		}

		// Validate vault and entry binding.
		if sf.Vault != "" && sf.Vault != vaultName {
			return nil, fmt.Errorf("share file %s is for vault %q, not %q", p, sf.Vault, vaultName)
		}
		if sf.Entry != "" && sf.Entry != entryName {
			return nil, fmt.Errorf("share file %s is for entry %q, not %q", p, sf.Entry, entryName)
		}

		s, err := crypto.UnmarshalShare(sf.Share)
		if err != nil {
			return nil, fmt.Errorf("unmarshal share from %s: %w", p, err)
		}
		shares = append(shares, s)
	}
	return shares, nil
}

func printOrCopy(payload *entry.Payload, name, field string, noClip bool) error {
	var value string
	var fieldName string
	switch field {
	case "password", "pass", "p":
		value = payload.Password
		fieldName = "password"
	case "user", "username", "u":
		value = payload.Username
		fieldName = "username"
	case "url":
		value = payload.URL
		fieldName = "URL"
	case "totp", "otp":
		if payload.TOTPSecret == "" {
			return fmt.Errorf("%q has no TOTP secret", name)
		}
		code, err := totp.Code(payload.TOTPSecret)
		if err != nil {
			return err
		}
		value = code
		fieldName = fmt.Sprintf("TOTP (%ds remaining)", totp.TimeRemaining())
	case "notes":
		value = payload.Notes
		fieldName = "notes"
	default:
		if cv, ok := payload.Fields[field]; ok {
			value = cv
			fieldName = field
		} else {
			return fmt.Errorf("unknown field %q — valid: password, user, url, totp, notes", field)
		}
	}

	if value == "" {
		return fmt.Errorf("%q field is empty for %q", field, name)
	}

	if noClip {
		fmt.Println(value)
		return nil
	}

	return clipboard.CopyWithNotice(value, clipboard.DefaultTTL, fieldName)
}
