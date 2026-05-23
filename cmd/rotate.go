package cmd

import (
	"fmt"
	"os"

	"github.com/al-Zamakhshari/aman/internal/crypto"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var rotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Replace your keypair across all accessible entries",
	Long: `Re-encrypts every entry you are a recipient of, swapping your old
public key for a new one. Run this after generating a replacement keypair.

Steps:
  1. Generate a new keypair:  aman keygen --name alice-new
  2. Rotate in the vault:     aman rotate --new-key ~/.aman/alice-new.key --new-pub ./alice-new.pub

The member registry is updated automatically. Your old .key file is NOT
deleted — archive it until you confirm the rotation succeeded.

Example:
  aman rotate --new-key ~/.aman/alice-new.key --new-pub ./alice-new.pub`,
	RunE: runRotate,
}

func init() {
	rootCmd.AddCommand(rotateCmd)
	rotateCmd.Flags().String("new-key", "", "path to the new encrypted private key file (required)")
	rotateCmd.Flags().String("new-pub", "", "path to the new public key file (required)")
	rotateCmd.MarkFlagRequired("new-key") //nolint:errcheck
	rotateCmd.MarkFlagRequired("new-pub") //nolint:errcheck
}

func runRotate(cmd *cobra.Command, _ []string) error {
	newKeyPath, _ := cmd.Flags().GetString("new-key")
	newPubPath, _ := cmd.Flags().GetString("new-pub")

	identity, err := identityName()
	if err != nil {
		return err
	}

	// Load current keypair.
	oldKP, err := loadKeyPair(identity)
	if err != nil {
		return fmt.Errorf("load current key: %w", err)
	}

	// Load new private key.
	newKeyData, err := os.ReadFile(newKeyPath) //nolint:gosec
	if err != nil {
		return fmt.Errorf("read new key file: %w", err)
	}
	fmt.Printf("Passphrase for new key (%s): ", newKeyPath)
	newPass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return err
	}
	newKP, err := crypto.OpenKeyPair(newKeyData, newPass)
	if err != nil {
		return fmt.Errorf("open new key: %w", err)
	}

	// Validate new pub file matches the new private key.
	newPubData, err := os.ReadFile(newPubPath) //nolint:gosec
	if err != nil {
		return fmt.Errorf("read new pub file: %w", err)
	}
	newPubBundle, err := crypto.LoadPublicBundle(newPubData)
	if err != nil {
		return fmt.Errorf("parse new pub file: %w", err)
	}
	newKPPubData, err := crypto.MarshalPublicBundle(newKP)
	if err != nil {
		return err
	}
	newKPBundle, err := crypto.LoadPublicBundle(newKPPubData)
	if err != nil {
		return err
	}
	if crypto.Fingerprint(newKPBundle) != crypto.Fingerprint(newPubBundle) {
		return fmt.Errorf("--new-key and --new-pub do not match (fingerprint mismatch)")
	}

	v, err := openVault()
	if err != nil {
		return err
	}

	// Show old fingerprint.
	oldFP := "unknown"
	if oldBundle, err := v.Members.Get(identity); err == nil {
		oldFP = crypto.Fingerprint(oldBundle)
	}
	newFP := crypto.Fingerprint(newPubBundle)

	fmt.Printf("Rotating key for %q in vault %q\n", identity, v.Cfg.Name)
	fmt.Printf("  Old fingerprint: %s\n", oldFP)
	fmt.Printf("  New fingerprint: %s\n\n", newFP)

	if !confirmPrompt("Proceed with rotation?") {
		fmt.Println("Aborted.")
		return nil
	}

	n, err := v.Rotate(identity, oldKP, newKP)
	if err != nil {
		return fmt.Errorf("rotate: %w", err)
	}

	fmt.Printf("✓ Rotated %d entries\n", n)
	fmt.Printf("✓ Member registry updated → new fingerprint: %s\n", newFP)
	fmt.Printf("\nCommit the vault to git to share the rotation with teammates.\n")
	return nil
}
