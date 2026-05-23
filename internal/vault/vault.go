// Package vault manages the aman vault — a directory of encrypted entry files
// and a member registry. The vault lives in a plain directory that can be
// committed to git; no binary database is involved.
package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/al-Zamakhshari/aman/internal/audit"
	"github.com/al-Zamakhshari/aman/internal/crypto"
	"github.com/al-Zamakhshari/aman/internal/entry"
	"github.com/al-Zamakhshari/aman/internal/member"
)

const (
	qpmDir     = ".qpm"
	entriesDir = "entries"
	configFile = "config.toml"
	auditFile  = "audit.log"
)

// Config holds vault-wide metadata stored in .qpm/config.toml.
type Config struct {
	Name      string    `json:"name"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
}

// Vault is the handle for all vault operations.
type Vault struct {
	Dir     string
	Cfg     *Config
	Members *member.Registry
	Audit   *audit.Logger
}

// Init creates a new vault in dir.
func Init(dir, name string) (*Vault, error) {
	qpm := filepath.Join(dir, qpmDir)
	for _, sub := range []string{qpm, filepath.Join(qpm, "members"), filepath.Join(dir, entriesDir)} {
		if err := os.MkdirAll(sub, 0700); err != nil {
			return nil, fmt.Errorf("create vault dir %s: %w", sub, err)
		}
	}

	cfg := &Config{Name: name, Version: 1, CreatedAt: time.Now().UTC()}
	if err := writeConfig(filepath.Join(qpm, configFile), cfg); err != nil {
		return nil, err
	}

	al, err := audit.NewLogger(filepath.Join(dir, auditFile))
	if err != nil {
		return nil, err
	}

	return &Vault{
		Dir:     dir,
		Cfg:     cfg,
		Members: member.NewRegistry(qpm),
		Audit:   al,
	}, nil
}

// Open loads an existing vault from dir.
func Open(dir string) (*Vault, error) {
	qpm := filepath.Join(dir, qpmDir)
	cfgPath := filepath.Join(qpm, configFile)

	data, err := os.ReadFile(cfgPath) //nolint:gosec
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%s is not an aman vault (run: aman init)", dir)
		}
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse vault config: %w", err)
	}

	al, err := audit.NewLogger(filepath.Join(dir, auditFile))
	if err != nil {
		return nil, err
	}

	return &Vault{
		Dir:     dir,
		Cfg:     &cfg,
		Members: member.NewRegistry(qpm),
		Audit:   al,
	}, nil
}

// Add encrypts a payload and saves it as a new entry.
// threshold=1 means any single recipient can decrypt; threshold>1 requires M-of-N Shamir cooperation.
func (v *Vault) Add(
	name string,
	actor string,
	payload *entry.Payload,
	recipients []string,
	signerKP *crypto.KeyPair,
	tags []string,
	threshold int,
) error {
	path, err := entry.EntryPath(v.Dir, name)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("entry %q already exists (use edit to update)", name)
	}

	bundles, err := v.Members.GetAll(recipients)
	if err != nil {
		return err
	}

	e, err := entry.Seal(name, actor, payload, recipients, bundles, signerKP, v.Cfg.Name, tags, threshold, time.Time{})
	if err != nil {
		return fmt.Errorf("seal entry: %w", err)
	}

	if err := entry.Save(e, path); err != nil {
		return fmt.Errorf("save entry: %w", err)
	}

	v.Audit.Append(audit.Event{Action: "add", Entry: name, Actor: actor, Recipients: recipients})
	return nil
}

// Get decrypts and returns an entry's payload.
// The entry's signature is verified against the creator's registered public key
// before decryption. Tampered or unsigned entries are rejected.
func (v *Vault) Get(name, myName string, myKP *crypto.KeyPair) (*entry.Payload, error) {
	path, err := entry.EntryPath(v.Dir, name)
	if err != nil {
		return nil, err
	}
	e, err := entry.Load(path)
	if err != nil {
		return nil, err
	}

	if err := v.verifySig(e); err != nil {
		return nil, err
	}

	payload, err := entry.Open(e, myName, myKP, v.Cfg.Name)
	if err != nil {
		return nil, err
	}

	v.Audit.Append(audit.Event{Action: "get", Entry: name, Actor: myName})
	return payload, nil
}

// List returns all entry names visible in the vault.
// If myName is set, marks which entries the caller can decrypt.
func (v *Vault) List(myName string) ([]ListItem, error) {
	dir := filepath.Join(v.Dir, entriesDir)
	des, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var items []ListItem
	for _, de := range des {
		if de.IsDir() || !strings.HasSuffix(de.Name(), entry.FileExt) {
			continue
		}
		name := strings.TrimSuffix(de.Name(), entry.FileExt)
		e, err := entry.Load(filepath.Join(dir, de.Name()))
		if err != nil {
			continue
		}
		canDecrypt := false
		for _, r := range e.Recipients {
			if r == myName {
				canDecrypt = true
				break
			}
		}
		items = append(items, ListItem{
			Name:       name,
			Recipients: e.Recipients,
			Tags:       e.Tags,
			UpdatedAt:  e.UpdatedAt,
			CanDecrypt: canDecrypt,
		})
	}
	return items, nil
}

// Grant re-encrypts an entry to add a new recipient.
func (v *Vault) Grant(name, newRecipient, actor string, myName string, myKP *crypto.KeyPair) error {
	path, err := entry.EntryPath(v.Dir, name)
	if err != nil {
		return err
	}
	e, err := entry.Load(path)
	if err != nil {
		return err
	}

	if err := v.verifySig(e); err != nil {
		return err
	}

	// Ensure newRecipient is not already a recipient.
	for _, r := range e.Recipients {
		if r == newRecipient {
			return fmt.Errorf("%s is already a recipient of %q", newRecipient, name)
		}
	}

	// Decrypt to get the payload.
	payload, err := entry.Open(e, myName, myKP, v.Cfg.Name)
	if err != nil {
		return fmt.Errorf("decrypt to re-seal: %w", err)
	}

	// Re-seal with the extended recipient list.
	newRecipients := append(e.Recipients, newRecipient)
	bundles, err := v.Members.GetAll(newRecipients)
	if err != nil {
		return err
	}

	newEntry, err := entry.Seal(name, actor, payload, newRecipients, bundles, myKP, v.Cfg.Name, e.Tags, e.Threshold, e.CreatedAt)
	if err != nil {
		return err
	}

	if err := entry.Save(newEntry, path); err != nil {
		return err
	}

	v.Audit.Append(audit.Event{Action: "grant", Entry: name, Actor: actor, Recipients: []string{newRecipient}})
	return nil
}

// Revoke re-encrypts an entry removing a recipient. The removed member can no
// longer decrypt future versions; past versions they may have cached are unaffected
// (rotate the secret itself if that matters).
func (v *Vault) Revoke(name, removeRecipient, actor string, myName string, myKP *crypto.KeyPair) error {
	path, err := entry.EntryPath(v.Dir, name)
	if err != nil {
		return err
	}
	e, err := entry.Load(path)
	if err != nil {
		return err
	}

	if err := v.verifySig(e); err != nil {
		return err
	}

	// Build new recipient list without the removed member.
	var newRecipients []string
	found := false
	for _, r := range e.Recipients {
		if r == removeRecipient {
			found = true
			continue
		}
		newRecipients = append(newRecipients, r)
	}
	if !found {
		return fmt.Errorf("%s is not a recipient of %q", removeRecipient, name)
	}
	if len(newRecipients) == 0 {
		return fmt.Errorf("cannot remove last recipient — delete the entry instead")
	}

	// Decrypt with our key.
	payload, err := entry.Open(e, myName, myKP, v.Cfg.Name)
	if err != nil {
		return fmt.Errorf("decrypt to re-seal: %w", err)
	}

	// Re-seal with new FEK (critical: old FEK is gone, removed member's wrapped copy is useless).
	bundles, err := v.Members.GetAll(newRecipients)
	if err != nil {
		return err
	}

	newEntry, err := entry.Seal(name, actor, payload, newRecipients, bundles, myKP, v.Cfg.Name, e.Tags, e.Threshold, e.CreatedAt)
	if err != nil {
		return err
	}

	if err := entry.Save(newEntry, path); err != nil {
		return err
	}

	v.Audit.Append(audit.Event{Action: "revoke", Entry: name, Actor: actor, Recipients: []string{removeRecipient}})
	return nil
}

// Delete removes an entry file permanently.
func (v *Vault) Delete(name, actor string) error {
	path, err := entry.EntryPath(v.Dir, name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("entry %q not found", name)
		}
		return err
	}
	v.Audit.Append(audit.Event{Action: "delete", Entry: name, Actor: actor})
	return nil
}

// Rotate re-encrypts all accessible entries replacing the caller's old public key
// with a new one. Call after generating a replacement keypair with 'aman keygen'.
// Returns the number of entries successfully rotated.
func (v *Vault) Rotate(myName string, oldKP, newKP *crypto.KeyPair) (int, error) {
	items, err := v.List(myName)
	if err != nil {
		return 0, err
	}

	// Pre-compute the new public bundle once.
	newPubData, err := crypto.MarshalPublicBundle(newKP)
	if err != nil {
		return 0, fmt.Errorf("marshal new public bundle: %w", err)
	}
	newBundle, err := crypto.LoadPublicBundle(newPubData)
	if err != nil {
		return 0, err
	}

	var rotated int
	for _, item := range items {
		if !item.CanDecrypt {
			continue
		}

		path, err := entry.EntryPath(v.Dir, item.Name)
		if err != nil {
			return rotated, err
		}
		e, err := entry.Load(path)
		if err != nil {
			return rotated, fmt.Errorf("load %q: %w", item.Name, err)
		}

		// Decrypt with the old key (skip sig verification — the old key may differ from registry).
		payload, err := entry.Open(e, myName, oldKP, v.Cfg.Name)
		if err != nil {
			return rotated, fmt.Errorf("decrypt %q: %w", item.Name, err)
		}

		// Re-seal: replace myName's bundle with the new one.
		bundles, err := v.Members.GetAll(e.Recipients)
		if err != nil {
			return rotated, err
		}
		bundles[myName] = newBundle

		newEntry, err := entry.Seal(item.Name, myName, payload, e.Recipients, bundles, newKP, v.Cfg.Name, e.Tags, e.Threshold, e.CreatedAt)
		if err != nil {
			return rotated, fmt.Errorf("re-seal %q: %w", item.Name, err)
		}

		if err := entry.Save(newEntry, path); err != nil {
			return rotated, fmt.Errorf("save %q: %w", item.Name, err)
		}
		rotated++
	}

	// Update the member registry with the new public key.
	if err := v.Members.Update(myName, newBundle); err != nil {
		return rotated, fmt.Errorf("update member registry: %w", err)
	}

	v.Audit.Append(audit.Event{Action: "rotate", Actor: myName})
	return rotated, nil
}

// Migrate re-seals all v1 entries accessible to the caller as v2 (new EntryInfo, UpdatedAt in sig).
// Returns the number of entries migrated.
func (v *Vault) Migrate(myName string, myKP *crypto.KeyPair) (int, error) {
	items, err := v.List(myName)
	if err != nil {
		return 0, err
	}

	var migrated int
	for _, item := range items {
		if !item.CanDecrypt {
			continue
		}

		path, err := entry.EntryPath(v.Dir, item.Name)
		if err != nil {
			return migrated, err
		}
		e, err := entry.Load(path)
		if err != nil {
			return migrated, fmt.Errorf("load %q: %w", item.Name, err)
		}
		if e.Version >= 2 {
			continue // already v2
		}

		// Decrypt with v1 info.
		payload, err := entry.Open(e, myName, myKP, v.Cfg.Name)
		if err != nil {
			return migrated, fmt.Errorf("decrypt %q: %w", item.Name, err)
		}

		bundles, err := v.Members.GetAll(e.Recipients)
		if err != nil {
			return migrated, err
		}

		// Re-seal as v2.
		newEntry, err := entry.Seal(item.Name, myName, payload, e.Recipients, bundles, myKP, v.Cfg.Name, e.Tags, e.Threshold, e.CreatedAt)
		if err != nil {
			return migrated, fmt.Errorf("re-seal %q: %w", item.Name, err)
		}

		if err := entry.Save(newEntry, path); err != nil {
			return migrated, fmt.Errorf("save %q: %w", item.Name, err)
		}
		migrated++
	}

	v.Audit.Append(audit.Event{Action: "migrate", Actor: myName})
	return migrated, nil
}

// VerifyAll checks signatures on all entries and returns per-entry results.
func (v *Vault) VerifyAll() ([]VerifyResult, error) {
	items, err := v.List("")
	if err != nil {
		return nil, err
	}

	results := make([]VerifyResult, 0, len(items))
	for _, item := range items {
		path, err := entry.EntryPath(v.Dir, item.Name)
		if err != nil {
			results = append(results, VerifyResult{Name: item.Name, Err: err})
			continue
		}
		e, err := entry.Load(path)
		if err != nil {
			results = append(results, VerifyResult{Name: item.Name, Err: err})
			continue
		}
		err = v.verifySig(e)
		results = append(results, VerifyResult{
			Name:      item.Name,
			CreatedBy: e.CreatedBy,
			Version:   e.Version,
			OK:        err == nil,
			Err:       err,
		})
	}
	return results, nil
}

// VerifyResult holds the outcome of a signature check for one entry.
type VerifyResult struct {
	Name      string
	CreatedBy string
	Version   int
	OK        bool
	Err       error
}

// verifySig checks the ML-DSA-87 signature on an entry against the creator's
// registered public key. Returns a descriptive error if verification fails.
func (v *Vault) verifySig(e *entry.Entry) error {
	bundle, err := v.Members.Get(e.CreatedBy)
	if err != nil {
		return fmt.Errorf("cannot verify %q: creator %q not in registry — "+
			"run: aman member add %s <pubkey>", e.Name, e.CreatedBy, e.CreatedBy)
	}
	ok, err := entry.VerifySig(e, bundle)
	if err != nil {
		return fmt.Errorf("signature check failed for %q: %w", e.Name, err)
	}
	if !ok {
		return fmt.Errorf("⚠ signature verification FAILED for %q — entry may be tampered", e.Name)
	}
	return nil
}

// ListItem is a summary of an entry returned by List.
type ListItem struct {
	Name       string
	Recipients []string
	Tags       []string
	UpdatedAt  time.Time
	CanDecrypt bool
}

func writeConfig(path string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
