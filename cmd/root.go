// Package cmd implements the aman CLI.
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	defaultIdentityKey = "AMAN_IDENTITY"
	defaultVaultDir    = "."
)

var rootCmd = &cobra.Command{
	Use:   "aman",
	Short: "أمان — quantum-safe team credential manager",
	Long: `aman (أمان) is a post-quantum team credential manager.

Each secret is encrypted directly to its recipients' PQC public keys.
No shared vault password exists. The vault is a plain directory — commit it to git.

Quick start:
  aman init                        initialise a vault in the current directory
  aman keygen --name alice         generate your keypair
  aman member add alice alice.pub  register a team member
  aman add github --to alice,bob   add a secret
  aman get github                  decrypt to clipboard (clears in 30s)`,
	SilenceUsage: true,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().String("vault", "", "vault directory (default: current directory)")
	rootCmd.PersistentFlags().String("identity", "", "your member name (default: $AMAN_IDENTITY)")
	rootCmd.PersistentFlags().String("key", "", "path to your encrypted private key file")
	viper.BindPFlag("vault", rootCmd.PersistentFlags().Lookup("vault"))    //nolint:errcheck
	viper.BindPFlag("identity", rootCmd.PersistentFlags().Lookup("identity")) //nolint:errcheck
	viper.BindPFlag("key", rootCmd.PersistentFlags().Lookup("key"))        //nolint:errcheck
}

func initConfig() {
	viper.SetEnvPrefix("AMAN")
	viper.AutomaticEnv()

	// Defaults.
	if v := viper.GetString("vault"); v == "" {
		viper.SetDefault("vault", defaultVaultDir)
	}
	if v := viper.GetString("identity"); v == "" {
		if env := os.Getenv(defaultIdentityKey); env != "" {
			viper.Set("identity", env)
		}
	}
}

// vaultDir resolves the vault directory from flags or cwd.
func vaultDir() string {
	if d := viper.GetString("vault"); d != "" {
		return d
	}
	return "."
}

// keyPath resolves the private key file path: --key flag, then ~/.aman/<identity>.key
func keyPath(identity string) string {
	if k := viper.GetString("key"); k != "" {
		return k
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".aman", identity+".key")
}

// identity resolves the caller's member name.
func identityName() (string, error) {
	if id := viper.GetString("identity"); id != "" {
		return id, nil
	}
	return "", fmt.Errorf("identity not set — use --identity or export AMAN_IDENTITY=<your-name>")
}
