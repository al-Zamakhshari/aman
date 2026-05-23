package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify [name]",
	Short: "Verify entry signatures",
	Long: `Checks the ML-DSA-87 signature on one or all vault entries.

A valid signature proves the entry was sealed by the registered creator
and has not been tampered with since.

Examples:
  aman verify github        verify a single entry
  aman verify --all         verify every entry in the vault`,
	Args: cobra.MaximumNArgs(1),
	RunE: runVerify,
}

func init() {
	rootCmd.AddCommand(verifyCmd)
	verifyCmd.Flags().Bool("all", false, "verify every entry in the vault")
}

func runVerify(cmd *cobra.Command, args []string) error {
	all, _ := cmd.Flags().GetBool("all")

	v, err := openVault()
	if err != nil {
		return err
	}

	if !all && len(args) == 0 {
		return fmt.Errorf("specify an entry name or use --all")
	}

	if all {
		results, err := v.VerifyAll()
		if err != nil {
			return err
		}
		var failed int
		for _, r := range results {
			if r.OK {
				fmt.Printf("  ✓  %-35s  creator=%-15s  v%d\n", r.Name, r.CreatedBy, r.Version)
			} else {
				fmt.Printf("  ✗  %-35s  %v\n", r.Name, r.Err)
				failed++
			}
		}
		fmt.Printf("\n%d/%d entries OK\n", len(results)-failed, len(results))
		if failed > 0 {
			return fmt.Errorf("%d entries failed verification", failed)
		}
		return nil
	}

	// Single entry.
	name := args[0]
	results, err := v.VerifyAll()
	if err != nil {
		return err
	}
	for _, r := range results {
		if r.Name != name {
			continue
		}
		if r.OK {
			fmt.Printf("✓ %q signature valid (creator: %s, v%d)\n", name, r.CreatedBy, r.Version)
		} else {
			fmt.Printf("✗ %q verification FAILED: %v\n", name, r.Err)
			return fmt.Errorf("verification failed")
		}
		return nil
	}
	return fmt.Errorf("entry %q not found", name)
}
