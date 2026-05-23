package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/al-Zamakhshari/aman/internal/audit"
	"github.com/al-Zamakhshari/aman/internal/vault"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init [directory]",
	Short: "Initialise a new aman vault",
	Long: `Creates a new vault in the specified directory (default: current directory).

The vault is a plain directory you can commit to git:
  .qpm/config.toml     vault metadata
  .qpm/members/        team member public keys
  entries/             encrypted secret files
  audit.log            tamper-evident operation log

Example:
  aman init                    init in current directory
  aman init ~/team-vault       init in a specific directory`,
	Args: cobra.MaximumNArgs(1),
	RunE: runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)
	initCmd.Flags().String("name", "", "vault name (default: directory name)")
}

func runInit(cmd *cobra.Command, args []string) error {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}

	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}

	name, _ := cmd.Flags().GetString("name")
	if name == "" {
		name = filepath.Base(abs)
	}

	// Check if already initialised.
	if _, err := os.Stat(filepath.Join(abs, ".qpm", "config.toml")); err == nil {
		return fmt.Errorf("vault already initialised in %s", abs)
	}

	v, err := vault.Init(abs, name)
	if err != nil {
		return fmt.Errorf("init vault: %w", err)
	}

	v.Audit.Append(audit.Event{Action: "init"})

	fmt.Printf("✓ Vault %q initialised in %s\n\n", name, abs)
	fmt.Println("Next steps:")
	fmt.Println("  aman keygen --name <your-name>              generate your keypair")
	fmt.Println("  aman member add <name> <name>.pub           register yourself")
	fmt.Println("  aman add <secret> --to <name> [--user ...]  add your first secret")

	return nil
}
