package cmd

import (
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
