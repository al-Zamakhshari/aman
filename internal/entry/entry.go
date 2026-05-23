// Package entry defines the aman secret entry format.
// Each entry is a standalone JSON file encrypted to a specific list of recipients.
// No shared vault key exists — each recipient has their own copy of the FEK,
// wrapped with their individual ML-KEM-768+X25519 public key.
package entry

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/al-Zamakhshari/aman/internal/crypto"
	"github.com/awnumar/memguard"
)

const FileExt = ".enc"

// Payload is the secret data stored inside an entry — never written to disk unencrypted.
type Payload struct {
	Username   string            `json:"username,omitempty"`
	Password   string            `json:"password,omitempty"`
	URL        string            `json:"url,omitempty"`
	TOTPSecret string            `json:"totp_secret,omitempty"`
	Notes      string            `json:"notes,omitempty"`
	Fields     map[string]string `json:"fields,omitempty"`
}

// Entry is the on-disk envelope for a single secret.
type Entry struct {
	Version    int                      `json:"version"`
	Name       string                   `json:"name"`
	CreatedBy  string                   `json:"created_by"`
	CreatedAt  time.Time                `json:"created_at"`
	UpdatedAt  time.Time                `json:"updated_at"`
	Recipients []string                 `json:"recipients"`
	Threshold  int                      `json:"threshold"` // 1 = any recipient; K>1 = M-of-N (future)
	Blocks     []crypto.RecipientBlock  `json:"recipient_blocks"`
	Nonce      []byte                   `json:"nonce"`
	Ciphertext []byte                   `json:"ciphertext"`
	Signature  []byte                   `json:"signature"`
	Tags       []string                 `json:"tags,omitempty"`
}

// sigPayload returns the stable bytes that are signed over an entry.
// Excludes the Signature field itself.
func sigPayload(e *Entry) ([]byte, error) {
	type signable struct {
		Version    int                     `json:"version"`
		Name       string                  `json:"name"`
		CreatedBy  string                  `json:"created_by"`
		CreatedAt  time.Time               `json:"created_at"`
		Recipients []string                `json:"recipients"`
		Threshold  int                     `json:"threshold"`
		Blocks     []crypto.RecipientBlock `json:"recipient_blocks"`
		Nonce      []byte                  `json:"nonce"`
		Ciphertext []byte                  `json:"ciphertext"`
		Tags       []string                `json:"tags,omitempty"`
	}
	return json.Marshal(signable{
		Version:    e.Version,
		Name:       e.Name,
		CreatedBy:  e.CreatedBy,
		CreatedAt:  e.CreatedAt,
		Recipients: e.Recipients,
		Threshold:  e.Threshold,
		Blocks:     e.Blocks,
		Nonce:      e.Nonce,
		Ciphertext: e.Ciphertext,
		Tags:       e.Tags,
	})
}

// Seal creates and signs a new entry, encrypting payload to all recipients.
func Seal(
	name string,
	createdBy string,
	payload *Payload,
	recipients []string,
	bundles map[string]*crypto.PublicBundle,
	signerKP *crypto.KeyPair,
	vaultName string,
	tags []string,
) (*Entry, error) {
	// 1. Generate a fresh FEK in a guarded buffer.
	fekBuf := memguard.NewBufferRandom(32)
	defer fekBuf.Destroy()
	fek := fekBuf.Bytes()

	// 2. Encrypt the payload with the FEK.
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	defer memguard.WipeBytes(payloadBytes)

	info := crypto.EntryInfo(vaultName, name)
	nonce, ciphertext, err := crypto.EncryptPayload(fek, payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("encrypt payload: %w", err)
	}

	// 3. Wrap the FEK for each recipient.
	blocks := make([]crypto.RecipientBlock, 0, len(recipients))
	for _, r := range recipients {
		bundle, ok := bundles[r]
		if !ok {
			return nil, fmt.Errorf("no public key found for recipient %q", r)
		}
		kemPub, err := crypto.KEMPublicFromBundle(bundle)
		if err != nil {
			return nil, fmt.Errorf("parse kem pub for %q: %w", r, err)
		}
		sealedFEK, err := crypto.WrapFEK(kemPub, fek, info)
		if err != nil {
			return nil, fmt.Errorf("wrap fek for %q: %w", r, err)
		}
		blocks = append(blocks, crypto.RecipientBlock{
			ID:        r,
			SealedFEK: sealedFEK,
		})
	}

	now := time.Now().UTC()
	e := &Entry{
		Version:    1,
		Name:       name,
		CreatedBy:  createdBy,
		CreatedAt:  now,
		UpdatedAt:  now,
		Recipients: recipients,
		Threshold:  1,
		Blocks:     blocks,
		Nonce:      nonce,
		Ciphertext: ciphertext,
		Tags:       tags,
	}

	// 4. Sign the entry.
	sp, err := sigPayload(e)
	if err != nil {
		return nil, fmt.Errorf("build sig payload: %w", err)
	}
	sig, err := crypto.Sign(signerKP.SIGPriv, sp)
	if err != nil {
		return nil, fmt.Errorf("sign entry: %w", err)
	}
	e.Signature = sig

	return e, nil
}

// Open decrypts an entry using the caller's private key.
func Open(e *Entry, myName string, myKP *crypto.KeyPair, vaultName string) (*Payload, error) {
	// 1. Find our recipient block.
	var block *crypto.RecipientBlock
	for i := range e.Blocks {
		if e.Blocks[i].ID == myName {
			block = &e.Blocks[i]
			break
		}
	}
	if block == nil {
		return nil, fmt.Errorf("you (%s) are not a recipient of this entry", myName)
	}

	// 2. Unwrap FEK.
	info := crypto.EntryInfo(vaultName, e.Name)
	fek, err := crypto.UnwrapFEK(myKP.KEMPriv, block.SealedFEK, info)
	if err != nil {
		return nil, err
	}
	defer memguard.WipeBytes(fek)

	// 3. Decrypt payload.
	plain, err := crypto.DecryptPayload(fek, e.Nonce, e.Ciphertext)
	if err != nil {
		return nil, err
	}
	defer memguard.WipeBytes(plain)

	var p Payload
	if err := json.Unmarshal(plain, &p); err != nil {
		return nil, fmt.Errorf("unmarshal payload: %w", err)
	}
	return &p, nil
}

// VerifySig checks the entry's ML-DSA-87 signature against the creator's public bundle.
func VerifySig(e *Entry, creatorBundle *crypto.PublicBundle) (bool, error) {
	sigPub, err := crypto.SIGPublicFromBundle(creatorBundle)
	if err != nil {
		return false, err
	}
	sp, err := sigPayload(e)
	if err != nil {
		return false, err
	}
	return crypto.Verify(sigPub, sp, e.Signature), nil
}

// Fingerprint returns a short stable ID for an entry (first 8 hex chars of SHA-256 of name).
func Fingerprint(name string) string {
	h := sha256.Sum256([]byte(name))
	return fmt.Sprintf("%x", h[:4])
}

// EntryPath returns the path for an entry file within the vault.
func EntryPath(vaultDir, name string) string {
	return filepath.Join(vaultDir, "entries", name+FileExt)
}

// Save writes an entry to disk as JSON.
func Save(e *Entry, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// Load reads and parses an entry from disk.
func Load(path string) (*Entry, error) {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil, err
	}
	var e Entry
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("parse entry %s: %w", filepath.Base(path), err)
	}
	return &e, nil
}
