// Package crypto provides the PQC cryptographic primitives for aman.
// It wraps ML-KEM-768+X25519 hybrid KEM (via crypto/hpke) and ML-DSA-87
// (via cloudflare/circl) to provide per-recipient key encapsulation and
// entry signing. No shared secret is ever derived.
package crypto

import (
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/awnumar/memguard"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	saltSize  = 32
	nonceSize = chacha20poly1305.NonceSize
)

// kdf and aead used for HPKE key wrapping.
func kdf() hpke.KDF  { return hpke.HKDFSHA256() }
func aead() hpke.AEAD { return hpke.ChaCha20Poly1305() }

// theKEM returns the X-Wing KEM (ML-KEM-768 + X25519).
func theKEM() hpke.KEM { return hpke.MLKEM768X25519() }

// KeyPair holds a member's full PQC keypair.
type KeyPair struct {
	KEMPriv hpke.PrivateKey
	KEMPub  hpke.PublicKey
	SIGPriv *mldsa87.PrivateKey
	SIGPub  *mldsa87.PublicKey
}

// PublicBundle is stored in .qpm/members/<name>.pub and shared with teammates.
type PublicBundle struct {
	KEMPublic []byte `json:"kem_public"` // ML-KEM-768+X25519 serialised public key
	SIGPublic []byte `json:"sig_public"` // ML-DSA-87 serialised public key
}

// encryptedKeyFile is the on-disk format for a passphrase-protected private key.
type encryptedKeyFile struct {
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// RecipientBlock holds one recipient's HPKE-sealed copy of the FEK.
type RecipientBlock struct {
	ID         string `json:"id"`
	SealedFEK  []byte `json:"sealed_fek"` // hpke.Seal output (enc + ciphertext)
}

// GenerateKeyPair generates a fresh ML-KEM-768+X25519 + ML-DSA-87 keypair.
func GenerateKeyPair() (*KeyPair, error) {
	kemPriv, err := theKEM().GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("kem keygen: %w", err)
	}

	sigPub, sigPriv, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sig keygen: %w", err)
	}

	return &KeyPair{
		KEMPriv: kemPriv,
		KEMPub:  kemPriv.PublicKey(),
		SIGPriv: sigPriv,
		SIGPub:  sigPub,
	}, nil
}

// MarshalPublicBundle serialises the public keys for sharing / storing in members/.
func MarshalPublicBundle(kp *KeyPair) ([]byte, error) {
	sigPubBytes, err := kp.SIGPub.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal sig pub: %w", err)
	}
	return json.Marshal(PublicBundle{
		KEMPublic: kp.KEMPub.Bytes(),
		SIGPublic: sigPubBytes,
	})
}

// MarshalBundle serialises an existing PublicBundle to JSON.
func MarshalBundle(b *PublicBundle) ([]byte, error) {
	return json.Marshal(b)
}

// LoadPublicBundle parses a .pub file.
func LoadPublicBundle(data []byte) (*PublicBundle, error) {
	var b PublicBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse public bundle: %w", err)
	}
	if len(b.KEMPublic) == 0 || len(b.SIGPublic) == 0 {
		return nil, errors.New("incomplete public bundle")
	}
	return &b, nil
}

// KEMPublicFromBundle deserialises the KEM public key from a bundle.
func KEMPublicFromBundle(b *PublicBundle) (hpke.PublicKey, error) {
	pub, err := theKEM().NewPublicKey(b.KEMPublic)
	if err != nil {
		return nil, fmt.Errorf("unmarshal kem pub: %w", err)
	}
	return pub, nil
}

// SIGPublicFromBundle deserialises the signing public key from a bundle.
func SIGPublicFromBundle(b *PublicBundle) (*mldsa87.PublicKey, error) {
	var pub mldsa87.PublicKey
	if err := pub.UnmarshalBinary(b.SIGPublic); err != nil {
		return nil, fmt.Errorf("unmarshal sig pub: %w", err)
	}
	return &pub, nil
}

// SealKeyPair encrypts a keypair to disk with Argon2id + ChaCha20-Poly1305.
func SealKeyPair(kp *KeyPair, passphrase []byte) ([]byte, error) {
	kemPrivBytes, err := kp.KEMPriv.Bytes()
	if err != nil {
		return nil, fmt.Errorf("marshal kem priv: %w", err)
	}
	sigPrivBytes, err := kp.SIGPriv.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal sig priv: %w", err)
	}
	defer memguard.WipeBytes(kemPrivBytes)
	defer memguard.WipeBytes(sigPrivBytes)

	// Encode as: [4-byte kem len][kem priv][sig priv]
	plain := make([]byte, 4+len(kemPrivBytes)+len(sigPrivBytes))
	plain[0] = byte(len(kemPrivBytes) >> 24)
	plain[1] = byte(len(kemPrivBytes) >> 16)
	plain[2] = byte(len(kemPrivBytes) >> 8)
	plain[3] = byte(len(kemPrivBytes))
	copy(plain[4:], kemPrivBytes)
	copy(plain[4+len(kemPrivBytes):], sigPrivBytes)
	defer memguard.WipeBytes(plain)

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("rand salt: %w", err)
	}

	key := argon2.IDKey(passphrase, salt, 3, 64*1024, 4, 32)
	defer memguard.WipeBytes(key)

	cipherAEAD, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("aead init: %w", err)
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("rand nonce: %w", err)
	}
	ct := cipherAEAD.Seal(nil, nonce, plain, nil)

	return json.Marshal(encryptedKeyFile{Salt: salt, Nonce: nonce, Ciphertext: ct})
}

// OpenKeyPair decrypts a keypair from disk.
func OpenKeyPair(data, passphrase []byte) (*KeyPair, error) {
	var kf encryptedKeyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, fmt.Errorf("parse key file: %w", err)
	}

	key := argon2.IDKey(passphrase, kf.Salt, 3, 64*1024, 4, 32)
	defer memguard.WipeBytes(key)

	cipherAEAD, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("aead init: %w", err)
	}

	plain, err := cipherAEAD.Open(nil, kf.Nonce, kf.Ciphertext, nil)
	if err != nil {
		return nil, errors.New("wrong passphrase or corrupted key file")
	}
	defer memguard.WipeBytes(plain)

	if len(plain) < 4 {
		return nil, errors.New("key file too short")
	}
	kemLen := int(plain[0])<<24 | int(plain[1])<<16 | int(plain[2])<<8 | int(plain[3])
	if len(plain) < 4+kemLen {
		return nil, errors.New("key file truncated")
	}

	kemPriv, err := theKEM().NewPrivateKey(plain[4 : 4+kemLen])
	if err != nil {
		return nil, fmt.Errorf("unmarshal kem priv: %w", err)
	}
	var sigPriv mldsa87.PrivateKey
	if err := sigPriv.UnmarshalBinary(plain[4+kemLen:]); err != nil {
		return nil, fmt.Errorf("unmarshal sig priv: %w", err)
	}

	return &KeyPair{
		KEMPriv: kemPriv,
		KEMPub:  kemPriv.PublicKey(),
		SIGPriv: &sigPriv,
		SIGPub:  sigPriv.Public().(*mldsa87.PublicKey),
	}, nil
}

// WrapFEK seals a 32-byte FEK to a recipient's public key using HPKE.
// The returned bytes are the complete hpke.Seal output (enc || ciphertext).
func WrapFEK(recipientPub hpke.PublicKey, fek, info []byte) ([]byte, error) {
	sealed, err := hpke.Seal(recipientPub, kdf(), aead(), info, fek)
	if err != nil {
		return nil, fmt.Errorf("hpke seal fek: %w", err)
	}
	return sealed, nil
}

// UnwrapFEK recovers the FEK from a sealed block using the recipient's private key.
func UnwrapFEK(privKey hpke.PrivateKey, sealedFEK, info []byte) ([]byte, error) {
	fek, err := hpke.Open(privKey, kdf(), aead(), info, sealedFEK)
	if err != nil {
		return nil, errors.New("decryption failed: wrong key or corrupted entry")
	}
	return fek, nil
}

// EncryptPayload encrypts plaintext with a FEK using ChaCha20-Poly1305.
func EncryptPayload(fek, plaintext []byte) (nonce, ciphertext []byte, err error) {
	payloadAEAD, err := chacha20poly1305.New(fek)
	if err != nil {
		return nil, nil, fmt.Errorf("aead init: %w", err)
	}
	nonce = make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("rand nonce: %w", err)
	}
	return nonce, payloadAEAD.Seal(nil, nonce, plaintext, nil), nil
}

// DecryptPayload decrypts a ciphertext with a FEK.
func DecryptPayload(fek, nonce, ciphertext []byte) ([]byte, error) {
	payloadAEAD, err := chacha20poly1305.New(fek)
	if err != nil {
		return nil, fmt.Errorf("aead init: %w", err)
	}
	plain, err := payloadAEAD.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed: wrong key or corrupted payload")
	}
	return plain, nil
}

// Sign signs data with an ML-DSA-87 private key.
func Sign(priv *mldsa87.PrivateKey, data []byte) ([]byte, error) {
	sig := make([]byte, mldsa87.SignatureSize)
	if err := mldsa87.SignTo(priv, data, nil, false, sig); err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return sig, nil
}

// Verify verifies an ML-DSA-87 signature.
func Verify(pub *mldsa87.PublicKey, data, sig []byte) bool {
	return mldsa87.Verify(pub, data, nil, sig)
}

// EntryInfo returns the HPKE info bytes for a given vault+entry pair (v2 format).
// Uses length-prefixed encoding to prevent separator-ambiguity attacks.
func EntryInfo(vaultName, entryName string) []byte {
	h := sha256.New()
	h.Write([]byte("aman:entry:v2:"))
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(len(vaultName)))
	h.Write(buf[:])
	h.Write([]byte(vaultName))
	binary.BigEndian.PutUint32(buf[:], uint32(len(entryName)))
	h.Write(buf[:])
	h.Write([]byte(entryName))
	return h.Sum(nil)
}

// entryInfoV1 is the original v1 HPKE info with ambiguous colon separator.
// Kept for reading/migrating v1 entries — do not use for new entries.
func entryInfoV1(vaultName, entryName string) []byte {
	h := sha256.New()
	h.Write([]byte("aman:entry:"))
	h.Write([]byte(vaultName))
	h.Write([]byte(":"))
	h.Write([]byte(entryName))
	return h.Sum(nil)
}

// EntryInfoForVersion returns the appropriate HPKE info for the given entry version.
func EntryInfoForVersion(version int, vaultName, entryName string) []byte {
	if version >= 2 {
		return EntryInfo(vaultName, entryName)
	}
	return entryInfoV1(vaultName, entryName)
}

// Fingerprint returns a short human-readable identifier for a public bundle.
// It is the first 8 bytes of SHA-256(KEMPublic || SIGPublic), hex-encoded (16 chars).
func Fingerprint(b *PublicBundle) string {
	h := sha256.New()
	h.Write(b.KEMPublic)
	h.Write(b.SIGPublic)
	return fmt.Sprintf("%x", h.Sum(nil)[:8])
}
