package crypto_test

import (
	"bytes"
	"testing"

	"github.com/al-Zamakhshari/aman/internal/crypto"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if kp.KEMPriv == nil || kp.KEMPub == nil {
		t.Fatal("KEM keys are nil")
	}
	if kp.SIGPriv == nil || kp.SIGPub == nil {
		t.Fatal("SIG keys are nil")
	}
}

func TestMarshalPublicBundle(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	data, err := crypto.MarshalPublicBundle(kp)
	if err != nil {
		t.Fatalf("MarshalPublicBundle: %v", err)
	}

	bundle, err := crypto.LoadPublicBundle(data)
	if err != nil {
		t.Fatalf("LoadPublicBundle: %v", err)
	}

	// Round-trip: re-derive public key from bundle and compare bytes.
	pub, err := crypto.KEMPublicFromBundle(bundle)
	if err != nil {
		t.Fatalf("KEMPublicFromBundle: %v", err)
	}
	if !bytes.Equal(pub.Bytes(), kp.KEMPub.Bytes()) {
		t.Fatal("KEM public key round-trip mismatch")
	}

	sigPub, err := crypto.SIGPublicFromBundle(bundle)
	if err != nil {
		t.Fatalf("SIGPublicFromBundle: %v", err)
	}
	sigPubBytes, _ := sigPub.MarshalBinary()
	origBytes, _ := kp.SIGPub.MarshalBinary()
	if !bytes.Equal(sigPubBytes, origBytes) {
		t.Fatal("SIG public key round-trip mismatch")
	}
}

func TestSealOpenKeyPair(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	passphrase := []byte("correct-horse-battery-staple")

	sealed, err := crypto.SealKeyPair(kp, passphrase)
	if err != nil {
		t.Fatalf("SealKeyPair: %v", err)
	}

	recovered, err := crypto.OpenKeyPair(sealed, passphrase)
	if err != nil {
		t.Fatalf("OpenKeyPair: %v", err)
	}

	// Verify the recovered KEM private key matches by comparing public key bytes.
	if !bytes.Equal(recovered.KEMPub.Bytes(), kp.KEMPub.Bytes()) {
		t.Fatal("KEM key mismatch after round-trip")
	}

	// Wrong passphrase must fail.
	_, err = crypto.OpenKeyPair(sealed, []byte("wrong"))
	if err == nil {
		t.Fatal("expected error with wrong passphrase, got nil")
	}
}

func TestWrapUnwrapFEK(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	fek := make([]byte, 32)
	for i := range fek {
		fek[i] = byte(i)
	}

	info := crypto.EntryInfo("test-vault", "github-deploy")

	sealed, err := crypto.WrapFEK(kp.KEMPub, fek, info)
	if err != nil {
		t.Fatalf("WrapFEK: %v", err)
	}

	recovered, err := crypto.UnwrapFEK(kp.KEMPriv, sealed, info)
	if err != nil {
		t.Fatalf("UnwrapFEK: %v", err)
	}

	if !bytes.Equal(recovered, fek) {
		t.Fatalf("FEK mismatch: got %x, want %x", recovered, fek)
	}

	// Wrong info must fail.
	_, err = crypto.UnwrapFEK(kp.KEMPriv, sealed, crypto.EntryInfo("other-vault", "github-deploy"))
	if err == nil {
		t.Fatal("expected error with wrong info, got nil")
	}
}

func TestEncryptDecryptPayload(t *testing.T) {
	fek := make([]byte, 32)
	for i := range fek {
		fek[i] = byte(i * 3)
	}

	plaintext := []byte(`{"password":"s3cr3t","username":"alice@example.com"}`)

	nonce, ct, err := crypto.EncryptPayload(fek, plaintext)
	if err != nil {
		t.Fatalf("EncryptPayload: %v", err)
	}

	recovered, err := crypto.DecryptPayload(fek, nonce, ct)
	if err != nil {
		t.Fatalf("DecryptPayload: %v", err)
	}

	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("payload mismatch: got %s", recovered)
	}

	// Tampered ciphertext must fail.
	ct[0] ^= 0xFF
	_, err = crypto.DecryptPayload(fek, nonce, ct)
	if err == nil {
		t.Fatal("expected error on tampered ciphertext, got nil")
	}
}

func TestSignVerify(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("aman:test:payload:2026")

	sig, err := crypto.Sign(kp.SIGPriv, data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if !crypto.Verify(kp.SIGPub, data, sig) {
		t.Fatal("Verify returned false for valid signature")
	}

	// Tampered data must fail.
	data[0] ^= 0xFF
	if crypto.Verify(kp.SIGPub, data, sig) {
		t.Fatal("Verify returned true for tampered data")
	}
}

func TestEntryInfoBinds(t *testing.T) {
	a := crypto.EntryInfo("vault-a", "entry-x")
	b := crypto.EntryInfo("vault-a", "entry-y")
	c := crypto.EntryInfo("vault-b", "entry-x")

	if bytes.Equal(a, b) {
		t.Fatal("different entry names produced same info")
	}
	if bytes.Equal(a, c) {
		t.Fatal("different vault names produced same info")
	}
}
