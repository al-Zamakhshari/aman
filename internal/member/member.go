// Package member manages the team member registry — the set of public key bundles
// stored in .qpm/members/. Each member is identified by a short name and has
// a public bundle (KEM pub + SIG pub) that other members use to encrypt to them.
package member

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/al-Zamakhshari/aman/internal/crypto"
)

const (
	membersDir = "members"
	pubExt     = ".pub"
)

// Registry manages member public keys on disk.
type Registry struct {
	dir string // absolute path to .qpm/members/
}

// NewRegistry creates a Registry pointing at the given members directory.
func NewRegistry(qpmDir string) *Registry {
	return &Registry{dir: filepath.Join(qpmDir, membersDir)}
}

// Add writes a public bundle for a named member.
func (r *Registry) Add(name string, bundle *crypto.PublicBundle) error {
	if err := validateName(name); err != nil {
		return err
	}
	if err := os.MkdirAll(r.dir, 0700); err != nil {
		return fmt.Errorf("create members dir: %w", err)
	}
	path := r.path(name)
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("member %q already exists (use member update to replace)", name)
	}
	return r.write(path, bundle)
}

// Update overwrites an existing member's public bundle.
func (r *Registry) Update(name string, bundle *crypto.PublicBundle) error {
	if err := validateName(name); err != nil {
		return err
	}
	return r.write(r.path(name), bundle)
}

// Get loads the public bundle for a named member.
func (r *Registry) Get(name string) (*crypto.PublicBundle, error) {
	data, err := os.ReadFile(r.path(name)) //nolint:gosec
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("member %q not found — run: aman member add %s <pubkey-file>", name, name)
		}
		return nil, err
	}
	return crypto.LoadPublicBundle(data)
}

// Remove deletes a member from the registry.
// Note: existing entries encrypted to this member remain until re-encrypted via grant/revoke.
func (r *Registry) Remove(name string) error {
	path := r.path(name)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("member %q not found", name)
	}
	return os.Remove(path)
}

// List returns all registered member names.
func (r *Registry) List() ([]string, error) {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), pubExt) {
			names = append(names, strings.TrimSuffix(e.Name(), pubExt))
		}
	}
	return names, nil
}

// GetAll loads bundles for a specific set of member names.
func (r *Registry) GetAll(names []string) (map[string]*crypto.PublicBundle, error) {
	out := make(map[string]*crypto.PublicBundle, len(names))
	for _, n := range names {
		b, err := r.Get(n)
		if err != nil {
			return nil, err
		}
		out[n] = b
	}
	return out, nil
}

// Exists reports whether a member is registered.
func (r *Registry) Exists(name string) bool {
	_, err := os.Stat(r.path(name))
	return err == nil
}

func (r *Registry) write(path string, bundle *crypto.PublicBundle) error {
	data, err := crypto.MarshalBundle(bundle)
	if err != nil {
		return fmt.Errorf("marshal bundle: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

func (r *Registry) path(name string) string {
	return filepath.Join(r.dir, name+pubExt)
}

func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("member name cannot be empty")
	}
	for _, c := range name {
		if !isAlphanumOrDash(c) {
			return fmt.Errorf("member name %q contains invalid character %q (use a-z, A-Z, 0-9, hyphen, underscore)", name, c)
		}
	}
	return nil
}

func isAlphanumOrDash(c rune) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '-' || c == '_'
}
