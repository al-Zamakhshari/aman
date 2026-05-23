package vault_test

import (
	"testing"

	"github.com/al-Zamakhshari/aman/internal/crypto"
	"github.com/al-Zamakhshari/aman/internal/entry"
	"github.com/al-Zamakhshari/aman/internal/vault"
)

// helpers

func genKP(t *testing.T) *crypto.KeyPair {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return kp
}

func registerMember(t *testing.T, v *vault.Vault, name string, kp *crypto.KeyPair) {
	t.Helper()
	data, err := crypto.MarshalPublicBundle(kp)
	if err != nil {
		t.Fatalf("MarshalPublicBundle: %v", err)
	}
	bundle, err := crypto.LoadPublicBundle(data)
	if err != nil {
		t.Fatalf("LoadPublicBundle: %v", err)
	}
	if err := v.Members.Add(name, bundle); err != nil {
		t.Fatalf("member add %s: %v", name, err)
	}
}

// tests

func TestInitOpen(t *testing.T) {
	dir := t.TempDir()
	v, err := vault.Init(dir, "test-vault")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if v.Cfg.Name != "test-vault" {
		t.Errorf("Name = %q, want %q", v.Cfg.Name, "test-vault")
	}

	// Re-open should succeed.
	v2, err := vault.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if v2.Cfg.Name != "test-vault" {
		t.Errorf("reopened Name = %q, want %q", v2.Cfg.Name, "test-vault")
	}
}

func TestAddGet(t *testing.T) {
	dir := t.TempDir()
	v, _ := vault.Init(dir, "acme")

	alice := genKP(t)
	registerMember(t, v, "alice", alice)

	payload := &entry.Payload{
		Username: "alice@acme.com",
		Password: "hunter2",
		URL:      "https://acme.com",
	}

	if err := v.Add("acme-login", "alice", payload, []string{"alice"}, alice, nil, 1); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got, err := v.Get("acme-login", "alice", alice)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Password != payload.Password {
		t.Errorf("Password = %q, want %q", got.Password, payload.Password)
	}
	if got.Username != payload.Username {
		t.Errorf("Username = %q, want %q", got.Username, payload.Username)
	}
}

func TestAddDuplicate(t *testing.T) {
	dir := t.TempDir()
	v, _ := vault.Init(dir, "v")
	alice := genKP(t)
	registerMember(t, v, "alice", alice)
	p := &entry.Payload{Password: "x"}

	v.Add("key", "alice", p, []string{"alice"}, alice, nil, 1) //nolint:errcheck
	err := v.Add("key", "alice", p, []string{"alice"}, alice, nil, 1)
	if err == nil {
		t.Fatal("expected duplicate error, got nil")
	}
}

func TestList(t *testing.T) {
	dir := t.TempDir()
	v, _ := vault.Init(dir, "v")

	alice := genKP(t)
	bob := genKP(t)
	registerMember(t, v, "alice", alice)
	registerMember(t, v, "bob", bob)

	v.Add("shared", "alice", &entry.Payload{Password: "a"}, []string{"alice", "bob"}, alice, []string{"prod"}, 1) //nolint:errcheck
	v.Add("alice-only", "alice", &entry.Payload{Password: "b"}, []string{"alice"}, alice, nil, 1)                  //nolint:errcheck

	items, err := v.List("alice")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
	for _, item := range items {
		if !item.CanDecrypt {
			t.Errorf("alice should be able to decrypt %q", item.Name)
		}
	}

	// Bob can only decrypt "shared".
	items, err = v.List("bob")
	if err != nil {
		t.Fatal(err)
	}
	var bobCan int
	for _, item := range items {
		if item.CanDecrypt {
			bobCan++
		}
	}
	if bobCan != 1 {
		t.Errorf("bob should be able to decrypt 1 entry, got %d", bobCan)
	}
}

func TestGrantRevoke(t *testing.T) {
	dir := t.TempDir()
	v, _ := vault.Init(dir, "v")

	alice := genKP(t)
	bob := genKP(t)
	carol := genKP(t)
	registerMember(t, v, "alice", alice)
	registerMember(t, v, "bob", bob)
	registerMember(t, v, "carol", carol)

	// Add entry for alice only.
	v.Add("secret", "alice", &entry.Payload{Password: "pw"}, []string{"alice"}, alice, nil, 1) //nolint:errcheck

	// Bob cannot decrypt yet.
	_, err := v.Get("secret", "bob", bob)
	if err == nil {
		t.Fatal("bob should not decrypt before grant")
	}

	// Grant bob.
	if err := v.Grant("secret", "bob", "alice", "alice", alice); err != nil {
		t.Fatalf("Grant: %v", err)
	}

	// Bob can now decrypt.
	got, err := v.Get("secret", "bob", bob)
	if err != nil {
		t.Fatalf("Get after grant: %v", err)
	}
	if got.Password != "pw" {
		t.Errorf("password after grant = %q, want %q", got.Password, "pw")
	}

	// Revoke bob.
	if err := v.Revoke("secret", "bob", "alice", "alice", alice); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Bob can no longer decrypt (new FEK was generated).
	_, err = v.Get("secret", "bob", bob)
	if err == nil {
		t.Fatal("bob should not decrypt after revoke")
	}

	// Alice still can.
	got, err = v.Get("secret", "alice", alice)
	if err != nil {
		t.Fatalf("alice Get after revoke: %v", err)
	}
	if got.Password != "pw" {
		t.Errorf("alice password after revoke = %q", got.Password)
	}
}

func TestDelete(t *testing.T) {
	dir := t.TempDir()
	v, _ := vault.Init(dir, "v")
	alice := genKP(t)
	registerMember(t, v, "alice", alice)

	v.Add("todelete", "alice", &entry.Payload{Password: "bye"}, []string{"alice"}, alice, nil, 1) //nolint:errcheck

	if err := v.Delete("todelete", "alice"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := v.Get("todelete", "alice", alice)
	if err == nil {
		t.Fatal("expected error after delete, got nil")
	}

	// Delete non-existent.
	if err := v.Delete("missing", "alice"); err == nil {
		t.Fatal("expected error deleting missing entry")
	}
}
