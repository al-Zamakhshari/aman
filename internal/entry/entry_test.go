package entry_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/al-Zamakhshari/aman/internal/crypto"
	"github.com/al-Zamakhshari/aman/internal/entry"
)

func makeKeyPair(t *testing.T) *crypto.KeyPair {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return kp
}

func makeBundles(t *testing.T, kps map[string]*crypto.KeyPair) map[string]*crypto.PublicBundle {
	t.Helper()
	bundles := make(map[string]*crypto.PublicBundle)
	for name, kp := range kps {
		data, err := crypto.MarshalPublicBundle(kp)
		if err != nil {
			t.Fatalf("MarshalPublicBundle for %s: %v", name, err)
		}
		b, err := crypto.LoadPublicBundle(data)
		if err != nil {
			t.Fatalf("LoadPublicBundle for %s: %v", name, err)
		}
		bundles[name] = b
	}
	return bundles
}

func TestSealOpen_SingleRecipient(t *testing.T) {
	alice := makeKeyPair(t)
	kps := map[string]*crypto.KeyPair{"alice": alice}
	bundles := makeBundles(t, kps)

	payload := &entry.Payload{
		Username: "alice@example.com",
		Password: "s3cr3t!",
		URL:      "https://github.com",
		Notes:    "main deploy key",
	}

	e, err := entry.Seal("github", "alice", payload, []string{"alice"}, bundles, alice, "test-vault", nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if e.Name != "github" {
		t.Errorf("Name = %q, want %q", e.Name, "github")
	}
	if e.CreatedBy != "alice" {
		t.Errorf("CreatedBy = %q, want %q", e.CreatedBy, "alice")
	}
	if len(e.Blocks) != 1 || e.Blocks[0].ID != "alice" {
		t.Error("expected one recipient block for alice")
	}
	if len(e.Signature) == 0 {
		t.Error("signature is empty")
	}

	// Alice can decrypt.
	got, err := entry.Open(e, "alice", alice, "test-vault")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got.Password != payload.Password {
		t.Errorf("Password = %q, want %q", got.Password, payload.Password)
	}
	if got.Username != payload.Username {
		t.Errorf("Username = %q, want %q", got.Username, payload.Username)
	}
	if got.URL != payload.URL {
		t.Errorf("URL = %q, want %q", got.URL, payload.URL)
	}
}

func TestSealOpen_MultipleRecipients(t *testing.T) {
	alice := makeKeyPair(t)
	bob := makeKeyPair(t)
	carol := makeKeyPair(t)

	kps := map[string]*crypto.KeyPair{"alice": alice, "bob": bob}
	bundles := makeBundles(t, kps)

	payload := &entry.Payload{Password: "shared-secret-42"}

	e, err := entry.Seal("stripe", "alice", payload, []string{"alice", "bob"}, bundles, alice, "acme-vault", []string{"prod"})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if len(e.Blocks) != 2 {
		t.Fatalf("expected 2 recipient blocks, got %d", len(e.Blocks))
	}

	// Both alice and bob can decrypt independently.
	for name, kp := range map[string]*crypto.KeyPair{"alice": alice, "bob": bob} {
		got, err := entry.Open(e, name, kp, "acme-vault")
		if err != nil {
			t.Errorf("Open as %s: %v", name, err)
			continue
		}
		if got.Password != payload.Password {
			t.Errorf("%s: password mismatch", name)
		}
	}

	// Carol (not a recipient) cannot decrypt.
	_, err = entry.Open(e, "carol", carol, "acme-vault")
	if err == nil {
		t.Fatal("carol should not be able to decrypt: expected error, got nil")
	}
}

func TestVerifySig(t *testing.T) {
	alice := makeKeyPair(t)
	bundles := makeBundles(t, map[string]*crypto.KeyPair{"alice": alice})

	payload := &entry.Payload{Password: "verified"}
	e, err := entry.Seal("svc", "alice", payload, []string{"alice"}, bundles, alice, "vault", nil)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := entry.VerifySig(e, bundles["alice"])
	if err != nil {
		t.Fatalf("VerifySig: %v", err)
	}
	if !ok {
		t.Fatal("signature verification failed for valid entry")
	}

	// Tamper with the entry — sig must fail.
	e.Ciphertext[0] ^= 0xFF
	ok, err = entry.VerifySig(e, bundles["alice"])
	if err != nil {
		t.Fatalf("VerifySig on tampered: %v", err)
	}
	if ok {
		t.Fatal("signature verified for tampered entry — expected false")
	}
}

func TestVaultBinding(t *testing.T) {
	// An entry sealed for vault-A cannot be decrypted as if it's from vault-B
	// because EntryInfo is bound to (vaultName, entryName).
	alice := makeKeyPair(t)
	bundles := makeBundles(t, map[string]*crypto.KeyPair{"alice": alice})
	payload := &entry.Payload{Password: "bound"}

	e, err := entry.Seal("secret", "alice", payload, []string{"alice"}, bundles, alice, "vault-A", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Decrypting with the correct vault name works.
	_, err = entry.Open(e, "alice", alice, "vault-A")
	if err != nil {
		t.Fatalf("Open with correct vault: %v", err)
	}

	// Decrypting with a different vault name must fail.
	_, err = entry.Open(e, "alice", alice, "vault-B")
	if err == nil {
		t.Fatal("expected error when decrypting with wrong vault name, got nil")
	}
}

func TestSaveLoad(t *testing.T) {
	alice := makeKeyPair(t)
	bundles := makeBundles(t, map[string]*crypto.KeyPair{"alice": alice})
	payload := &entry.Payload{Password: "persisted", Username: "u@example.com"}

	e, err := entry.Seal("saved", "alice", payload, []string{"alice"}, bundles, alice, "v", nil)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "saved.enc")

	if err := entry.Save(e, path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not created: %v", err)
	}

	loaded, err := entry.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	got, err := entry.Open(loaded, "alice", alice, "v")
	if err != nil {
		t.Fatalf("Open after load: %v", err)
	}
	if got.Password != payload.Password {
		t.Errorf("Password after load = %q, want %q", got.Password, payload.Password)
	}
}
