package cmd

import (
	"fmt"

	"github.com/al-Zamakhshari/aman/internal/clipboard"
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
  aman get github --no-clipboard        print to stdout (use with care)`,
	Args: cobra.ExactArgs(1),
	RunE: runGet,
}

func init() {
	rootCmd.AddCommand(getCmd)
	getCmd.Flags().String("field", "password", "field to retrieve: password, user, url, totp, notes")
	getCmd.Flags().Bool("no-clipboard", false, "print to stdout instead of clipboard")
}

func runGet(cmd *cobra.Command, args []string) error {
	name := args[0]
	field, _ := cmd.Flags().GetString("field")
	noClip, _ := cmd.Flags().GetBool("no-clipboard")

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

	payload, err := v.Get(name, identity, kp)
	if err != nil {
		return err
	}

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
		if v, ok := payload.Fields[field]; ok {
			value = v
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
