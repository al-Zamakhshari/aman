package cmd

import (
	"encoding/json"
	"fmt"
	"os"

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

	identity, err := identityName()
	if err != nil {
		return err
	}

	v, err := openVault()
	if err != nil {
		return err
	}

	var payload interface{ GetPassword() string }
	_ = payload

	// Threshold path: combine shares without our private key.
	if len(sharePaths) > 0 {
		e, err := entry.Load(entry.EntryPath(v.Dir, name))
		if err != nil {
			return err
		}
		shares, err := loadShareFiles(sharePaths)
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

// loadShareFiles reads .share files produced by 'aman collect'.
func loadShareFiles(paths []string) ([]*crypto.ShamirShare, error) {
	type shareFile struct {
		Share json.RawMessage `json:"share"`
	}
	var shares []*crypto.ShamirShare
	for _, p := range paths {
		data, err := os.ReadFile(p) //nolint:gosec
		if err != nil {
			return nil, fmt.Errorf("read share file %s: %w", p, err)
		}
		var sf shareFile
		if err := json.Unmarshal(data, &sf); err != nil {
			return nil, fmt.Errorf("parse share file %s: %w", p, err)
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
		// Check custom fields.
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
