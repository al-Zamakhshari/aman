package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/al-Zamakhshari/aman/internal/audit"
	"github.com/al-Zamakhshari/aman/internal/vault"
)

// audit_event is a convenience constructor for audit.Event used in commands.
func audit_event(action, entryName, actor string, recipients []string) audit.Event {
	return audit.Event{Action: action, Entry: entryName, Actor: actor, Recipients: recipients}
}

// openVault loads the vault from the configured directory.
func openVault() (*vault.Vault, error) {
	return vault.Open(vaultDir())
}

// confirmPrompt prints a yes/no prompt and returns true only if the user types "y" or "yes".
// Returns false on any read error (safe default for scripted/piped contexts).
func confirmPrompt(prompt string) bool {
	fmt.Printf("%s [y/N]: ", prompt)
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return false
	}
	resp := strings.TrimSpace(strings.ToLower(scanner.Text()))
	return resp == "y" || resp == "yes"
}
