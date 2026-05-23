package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var envCmd = &cobra.Command{
	Use:   "env <name>",
	Short: "Print a secret's fields as shell export statements",
	Long: `Decrypts a secret and prints its fields as shell export statements.
Pipe into eval to inject credentials directly into your shell.

Field → variable mapping (PREFIX defaults to uppercased secret name):
  password     → <PREFIX>_PASSWORD
  username     → <PREFIX>_USER
  url          → <PREFIX>_URL
  custom field → <PREFIX>_<FIELD>

Examples:
  eval $(aman env aws-prod)
  eval $(aman env stripe --prefix STRIPE)
  aman env github --shell fish | source`,
	Args: cobra.ExactArgs(1),
	RunE: runEnv,
}

func init() {
	rootCmd.AddCommand(envCmd)
	envCmd.Flags().String("prefix", "", "env var prefix (default: uppercased secret name)")
	envCmd.Flags().String("shell", "sh", "output syntax: sh (default) or fish")
}

func runEnv(cmd *cobra.Command, args []string) error {
	name := args[0]
	prefix, _ := cmd.Flags().GetString("prefix")
	shell, _ := cmd.Flags().GetString("shell")

	if prefix == "" {
		prefix = toEnvName(name)
	} else {
		prefix = toEnvName(prefix)
	}

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

	payload, err := v.Get(name, identity, kp)
	if err != nil {
		return err
	}

	// Build the var map.
	vars := map[string]string{}
	if payload.Password != "" {
		vars[prefix+"_PASSWORD"] = payload.Password
	}
	if payload.Username != "" {
		vars[prefix+"_USER"] = payload.Username
	}
	if payload.URL != "" {
		vars[prefix+"_URL"] = payload.URL
	}
	for k, val := range payload.Fields {
		vars[prefix+"_"+toEnvName(k)] = val
	}

	// Emit.
	for key, val := range vars {
		switch shell {
		case "fish":
			fmt.Fprintf(os.Stdout, "set -x %s %q;\n", key, val)
		default:
			fmt.Fprintf(os.Stdout, "export %s=%q\n", key, val)
		}
	}

	return nil
}

// toEnvName converts an arbitrary string to a safe uppercase env var segment.
// "aws-prod" → "AWS_PROD", "my.service" → "MY_SERVICE"
func toEnvName(s string) string {
	s = strings.ToUpper(s)
	var b strings.Builder
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
		} else {
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_")
}
