package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var deleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Permanently delete a secret from the vault",
	Long: `Removes the encrypted entry file from the vault.

This operation is permanent and cannot be undone. The secret is gone
from the vault — holders of old copies are not affected.

Example:
  aman delete old-api-key`,
	Args:    cobra.ExactArgs(1),
	Aliases: []string{"rm", "remove"},
	RunE:    runDelete,
}

func init() {
	rootCmd.AddCommand(deleteCmd)
	deleteCmd.Flags().Bool("yes", false, "skip confirmation prompt")
}

func runDelete(cmd *cobra.Command, args []string) error {
	name := args[0]
	yes, _ := cmd.Flags().GetBool("yes")

	identity, err := identityName()
	if err != nil {
		return err
	}

	v, err := openVault()
	if err != nil {
		return err
	}

	if !yes {
		fmt.Printf("Delete %q from vault %q? [y/N] ", name, v.Cfg.Name)
		var confirm string
		fmt.Scanln(&confirm) //nolint:errcheck
		if confirm != "y" && confirm != "Y" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	if err := v.Delete(name, identity); err != nil {
		return err
	}

	fmt.Printf("✓ %q deleted\n", name)
	return nil
}
