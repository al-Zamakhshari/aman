package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List secrets in the vault",
	Long: `Lists secrets in the vault.

By default only shows secrets you can decrypt.
Use --all to see every entry including those you don't have access to.

Examples:
  aman list               your accessible secrets
  aman list --all         all secrets with recipient info
  aman list --tag prod    filter by tag`,
	RunE: runList,
}

func init() {
	rootCmd.AddCommand(listCmd)
	listCmd.Flags().Bool("all", false, "show all entries, including inaccessible ones")
	listCmd.Flags().String("tag", "", "filter by tag")
}

func runList(cmd *cobra.Command, _ []string) error {
	showAll, _ := cmd.Flags().GetBool("all")
	tagFilter, _ := cmd.Flags().GetString("tag")

	identity, _ := identityName() // non-fatal if not set

	v, err := openVault()
	if err != nil {
		return err
	}

	items, err := v.List(identity)
	if err != nil {
		return err
	}

	if len(items) == 0 {
		fmt.Println("No secrets found. Run: aman add <name> --to <member>")
		return nil
	}

	var shown int
	for _, item := range items {
		if !showAll && !item.CanDecrypt {
			continue
		}
		if tagFilter != "" && !hasTag(item.Tags, tagFilter) {
			continue
		}

		lock := "🔒"
		if item.CanDecrypt {
			lock = "🔓"
		}

		age := formatAge(item.UpdatedAt)
		recipients := strings.Join(item.Recipients, ", ")

		if showAll {
			fmt.Printf("%s %-30s  %-20s  %s\n", lock, item.Name, recipients, age)
		} else {
			tags := ""
			if len(item.Tags) > 0 {
				tags = "[" + strings.Join(item.Tags, ", ") + "]"
			}
			fmt.Printf("  %-30s  %-8s  %s\n", item.Name, age, tags)
		}
		shown++
	}

	if shown == 0 {
		if showAll {
			fmt.Println("No secrets match the filter.")
		} else {
			fmt.Printf("No secrets accessible to %q. Use --all to see all entries.\n", identity)
		}
	}

	return nil
}

func hasTag(tags []string, filter string) bool {
	for _, t := range tags {
		if t == filter {
			return true
		}
	}
	return false
}

func formatAge(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return t.Format("2006-01-02")
	}
}
