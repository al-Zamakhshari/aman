package cmd

import (
	"fmt"
	"strings"

	"github.com/al-Zamakhshari/aman/internal/entry"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"os"
)

var addCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Add a new secret to the vault",
	Long: `Encrypts a new secret and adds it to the vault.

The secret is encrypted separately for each recipient using their
individual PQC public key — no shared password is involved.

Examples:
  aman add github --to alice,bob --user deploy@company.com --url https://github.com
  aman add stripe-live --to alice,bob,carol --threshold 2 --tag prod,payments`,
	Args: cobra.ExactArgs(1),
	RunE: runAdd,
}

func init() {
	rootCmd.AddCommand(addCmd)
	addCmd.Flags().String("to", "", "comma-separated list of recipients (required)")
	addCmd.Flags().String("user", "", "username or email")
	addCmd.Flags().String("url", "", "associated URL")
	addCmd.Flags().String("notes", "", "free-form notes")
	addCmd.Flags().String("totp", "", "TOTP secret (base32)")
	addCmd.Flags().StringSlice("tag", nil, "tags (repeatable: --tag prod --tag aws)")
	addCmd.Flags().Int("threshold", 1, "require K-of-N recipients to cooperate (default: 1 = any recipient)")
	addCmd.MarkFlagRequired("to") //nolint:errcheck
}

func runAdd(cmd *cobra.Command, args []string) error {
	name := args[0]

	identity, err := identityName()
	if err != nil {
		return err
	}

	toFlag, _ := cmd.Flags().GetString("to")
	recipients := splitCSV(toFlag)
	if len(recipients) == 0 {
		return fmt.Errorf("--to requires at least one recipient")
	}

	user, _ := cmd.Flags().GetString("user")
	url, _ := cmd.Flags().GetString("url")
	notes, _ := cmd.Flags().GetString("notes")
	totpSecret, _ := cmd.Flags().GetString("totp")
	tags, _ := cmd.Flags().GetStringSlice("tag")
	threshold, _ := cmd.Flags().GetInt("threshold")

	// Prompt for password.
	fmt.Printf("Password for %q (leave blank to skip): ", name)
	passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return err
	}

	payload := &entry.Payload{
		Username:   user,
		Password:   string(passBytes),
		URL:        url,
		TOTPSecret: totpSecret,
		Notes:      notes,
	}

	kp, err := loadKeyPair(identity)
	if err != nil {
		return err
	}

	v, err := openVault()
	if err != nil {
		return err
	}

	if err := v.Add(name, identity, payload, recipients, kp, tags, threshold); err != nil {
		return err
	}

	fmt.Printf("✓ Secret %q added → recipients: %s\n", name, strings.Join(recipients, ", "))
	return nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
