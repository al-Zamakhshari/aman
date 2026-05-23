package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var grantCmd = &cobra.Command{
	Use:   "grant <secret>",
	Short: "Add a recipient to an existing secret",
	Long: `Re-encrypts a secret to include a new recipient.

You must be a current recipient to grant access (you need to decrypt
the secret to re-encrypt it for the new person).

Example:
  aman grant github --to carol`,
	Args: cobra.ExactArgs(1),
	RunE: runGrant,
}

var revokeCmd = &cobra.Command{
	Use:   "revoke <secret>",
	Short: "Remove a recipient from an existing secret",
	Long: `Re-encrypts a secret excluding a recipient.

A new FEK is generated — the removed member's wrapped key is discarded.
Their local copies of the old value are unaffected; rotate the secret
itself if that is a concern.

Example:
  aman revoke github --from bob`,
	Args: cobra.ExactArgs(1),
	RunE: runRevoke,
}

func init() {
	rootCmd.AddCommand(grantCmd)
	grantCmd.Flags().String("to", "", "member to grant access to (required)")
	grantCmd.MarkFlagRequired("to") //nolint:errcheck

	rootCmd.AddCommand(revokeCmd)
	revokeCmd.Flags().String("from", "", "member to revoke access from (required)")
	revokeCmd.MarkFlagRequired("from") //nolint:errcheck
}

func runGrant(cmd *cobra.Command, args []string) error {
	secretName := args[0]
	newMember, _ := cmd.Flags().GetString("to")

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

	if err := v.Grant(secretName, newMember, identity, identity, kp); err != nil {
		return err
	}

	fmt.Printf("✓ %s now has access to %q\n", newMember, secretName)
	return nil
}

func runRevoke(cmd *cobra.Command, args []string) error {
	secretName := args[0]
	removeMember, _ := cmd.Flags().GetString("from")

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

	if err := v.Revoke(secretName, removeMember, identity, identity, kp); err != nil {
		return err
	}

	fmt.Printf("✓ %s access revoked from %q (new FEK generated)\n", removeMember, secretName)
	fmt.Printf("  Rotate the secret value itself if the old value was compromised.\n")
	return nil
}
