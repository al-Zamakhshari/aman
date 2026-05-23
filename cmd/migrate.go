package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Upgrade v1 entries to v2 format",
	Long: `Re-seals all accessible v1 entries as v2.

v2 changes vs v1:
  • Length-prefixed HPKE info (prevents vault-name/entry-name separator ambiguity)
  • UpdatedAt included in signature (prevents git-revert rollback attacks)
  • Per-share HMAC key for Shamir shares (replaces hardcoded global key)

Only entries you can decrypt are migrated. Ask teammates to run 'aman migrate'
on their machines to upgrade entries they hold but you do not.

Example:
  aman migrate`,
	RunE: runMigrate,
}

func init() {
	rootCmd.AddCommand(migrateCmd)
}

func runMigrate(_ *cobra.Command, _ []string) error {
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

	fmt.Printf("Migrating v1 entries to v2 in vault %q...\n", v.Cfg.Name)

	n, err := v.Migrate(identity, kp)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	if n == 0 {
		fmt.Println("✓ All accessible entries are already v2 — nothing to do.")
		return nil
	}

	fmt.Printf("✓ Migrated %d entries to v2\n", n)
	fmt.Printf("\nCommit the vault to git. Ask teammates to run 'aman migrate' for entries they hold.\n")
	return nil
}
