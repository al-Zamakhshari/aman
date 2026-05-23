package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/al-Zamakhshari/aman/internal/crypto"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate a new PQC keypair (ML-KEM-768+X25519 / ML-DSA-87)",
	Long: `Generates a fresh post-quantum keypair for a team member.

Two files are written:
  ~/.aman/<name>.key   private key (Argon2id-encrypted, never share this)
  <name>.pub           public bundle  (share this with teammates)

Example:
  aman keygen --name alice`,
	RunE: runKeygen,
}

func init() {
	rootCmd.AddCommand(keygenCmd)
	keygenCmd.Flags().String("name", "", "your member name (required)")
	keygenCmd.Flags().String("out", "", "output directory for .pub file (default: current dir)")
	keygenCmd.MarkFlagRequired("name") //nolint:errcheck
}

func runKeygen(cmd *cobra.Command, _ []string) error {
	name, _ := cmd.Flags().GetString("name")
	outDir, _ := cmd.Flags().GetString("out")
	if outDir == "" {
		outDir = "."
	}

	fmt.Printf("Generating ML-KEM-768+X25519 / ML-DSA-87 keypair for %q...\n", name)

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("keygen: %w", err)
	}

	// Prompt for passphrase twice.
	pass, err := promptPassphrase("Enter passphrase to protect your private key: ", true)
	if err != nil {
		return err
	}

	// Seal private key.
	sealed, err := crypto.SealKeyPair(kp, pass)
	if err != nil {
		return fmt.Errorf("seal keypair: %w", err)
	}

	// Write private key to ~/.aman/<name>.key
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	keyDir := filepath.Join(home, ".aman")
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return err
	}
	keyFile := filepath.Join(keyDir, name+".key")
	if err := os.WriteFile(keyFile, sealed, 0600); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}

	// Write public bundle to <outDir>/<name>.pub
	pubData, err := crypto.MarshalPublicBundle(kp)
	if err != nil {
		return err
	}
	pubFile := filepath.Join(outDir, name+".pub")
	if err := os.WriteFile(pubFile, pubData, 0644); err != nil {
		return fmt.Errorf("write pub file: %w", err)
	}

	fmt.Printf("\n✓ Private key → %s\n", keyFile)
	fmt.Printf("✓ Public key  → %s\n\n", pubFile)
	fmt.Println("Share the .pub file with your team. Keep the .key file private.")
	fmt.Printf("\nRegister yourself in the vault:\n  aman member add %s %s\n", name, pubFile)

	return nil
}

func promptPassphrase(prompt string, confirm bool) ([]byte, error) {
	fmt.Print(prompt)
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	if len(pass) == 0 {
		return nil, fmt.Errorf("passphrase cannot be empty")
	}
	if confirm {
		fmt.Print("Confirm passphrase: ")
		pass2, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return nil, fmt.Errorf("read passphrase: %w", err)
		}
		if string(pass) != string(pass2) {
			return nil, fmt.Errorf("passphrases do not match")
		}
	}
	return pass, nil
}

// loadKeyPair loads and decrypts the caller's private key.
func loadKeyPair(identity string) (*crypto.KeyPair, error) {
	kf := keyPath(identity)
	data, err := os.ReadFile(kf) //nolint:gosec
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("key file not found at %s — run: aman keygen --name %s", kf, identity)
		}
		return nil, err
	}
	fmt.Printf("Passphrase for %s: ", identity)
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, err
	}
	return crypto.OpenKeyPair(data, pass)
}
