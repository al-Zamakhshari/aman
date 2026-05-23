package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/al-Zamakhshari/aman/internal/audit"
	"github.com/al-Zamakhshari/aman/internal/entry"
	"github.com/al-Zamakhshari/aman/internal/vault"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var editCmd = &cobra.Command{
	Use:   "edit <name>",
	Short: "Update fields of an existing secret",
	Long: `Decrypts an entry, applies field updates, and re-encrypts it.
Only the fields you explicitly set are changed; others are preserved.

The entry is re-encrypted with a fresh FEK for all existing recipients.

Examples:
  aman edit github --password            prompt for new password
  aman edit github --user new@email.com
  aman edit github --url https://github.com/new
  aman edit github --totp JBSWY3DPEHPK3PXP
  aman edit github --notes "Updated 2026-05"`,
	Args: cobra.ExactArgs(1),
	RunE: runEdit,
}

func init() {
	rootCmd.AddCommand(editCmd)
	editCmd.Flags().Bool("password", false, "prompt for new password")
	editCmd.Flags().String("user", "", "new username")
	editCmd.Flags().String("url", "", "new URL")
	editCmd.Flags().String("notes", "", "new notes")
	editCmd.Flags().String("totp", "", "new TOTP secret (base32)")
}

func runEdit(cmd *cobra.Command, args []string) error {
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

	// Decrypt current payload.
	payload, err := v.Get(name, identity, kp)
	if err != nil {
		return err
	}

	// Apply updates.
	changed := false

	if cmd.Flags().Changed("password") {
		fmt.Printf("New password for %q: ", name)
		passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return err
		}
		payload.Password = string(passBytes)
		changed = true
	}
	if u, _ := cmd.Flags().GetString("user"); cmd.Flags().Changed("user") {
		payload.Username = u
		changed = true
	}
	if u, _ := cmd.Flags().GetString("url"); cmd.Flags().Changed("url") {
		payload.URL = u
		changed = true
	}
	if n, _ := cmd.Flags().GetString("notes"); cmd.Flags().Changed("notes") {
		payload.Notes = n
		changed = true
	}
	if t, _ := cmd.Flags().GetString("totp"); cmd.Flags().Changed("totp") {
		payload.TOTPSecret = t
		changed = true
	}

	if !changed {
		return fmt.Errorf("no fields specified — use --password, --user, --url, --notes, or --totp")
	}

	// Load the current entry to get the recipient list.
	e, err := entry.Load(entry.EntryPath(v.Dir, name))
	if err != nil {
		return err
	}

	// Re-seal with existing recipients and a fresh FEK.
	bundles, err := v.Members.GetAll(e.Recipients)
	if err != nil {
		return err
	}

	newEntry, err := entry.Seal(name, identity, payload, e.Recipients, bundles, kp, v.Cfg.Name, e.Tags, e.Threshold)
	if err != nil {
		return fmt.Errorf("re-seal: %w", err)
	}
	newEntry.CreatedAt = e.CreatedAt // preserve original creation time

	if err := entry.Save(newEntry, entry.EntryPath(v.Dir, name)); err != nil {
		return err
	}

	v.Audit.Append(audit.Event{
		Action:     "edit",
		Entry:      name,
		Actor:      identity,
		Recipients: changedFields(cmd),
	})

	fmt.Printf("✓ %q updated — re-encrypted for: %s\n", name, strings.Join(e.Recipients, ", "))
	return nil
}

// changedFields returns the names of changed flags for the audit log.
func changedFields(cmd *cobra.Command) []string {
	var fields []string
	for _, f := range []string{"password", "user", "url", "notes", "totp"} {
		if cmd.Flags().Changed(f) {
			fields = append(fields, f)
		}
	}
	return fields
}

// openVaultTyped is a vault.Vault alias for callers that need the full type.
func openVaultTyped() (*vault.Vault, error) {
	return vault.Open(vaultDir())
}
