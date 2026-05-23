// Package entry defines the aman secret entry format.
// Each entry is a standalone JSON file encrypted to a specific list of recipients.
// No shared vault key exists — each recipient has their own copy of the FEK,
// wrapped with their individual ML-KEM-768+X25519 public key.
//
// When Threshold = 1 (default): each recipient block wraps the full FEK.
// When Threshold = K > 1: each recipient block wraps one Shamir share of the FEK;
// K recipients must cooperate to reconstruct the FEK.
package entry

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	Version    int                     `json:"version"`
	Name       string                  `json:"name"`
	CreatedBy  string                  `json:"created_by"`
	CreatedAt  time.Time               `json:"created_at"`
	UpdatedAt  time.Time               `json:"updated_at"`
	Recipients []string                `json:"recipients"`
	Threshold  int                     `json:"threshold"` // 1 = any recipient; K>1 = M-of-N Shamir
	Blocks     []crypto.RecipientBlock `json:"recipient_blocks"`
	Nonce      []byte                  `json:"nonce"`
	Ciphertext []byte                  `json:"ciphertext"`
	Signature  []byte                  `json:"signature"`
	Tags       []string                `json:"tags,omitempty"`
}

// signableV1 is the v1 signable struct — does not include UpdatedAt.
type signableV1 struct {
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

// signableV2 includes UpdatedAt for rollback-attack protection.
type signableV2 struct {
	Version    int                     `json:"version"`
	Name       string                  `json:"name"`
	CreatedBy  string                  `json:"created_by"`
	CreatedAt  time.Time               `json:"created_at"`
	UpdatedAt  time.Time               `json:"updated_at"`
	Recipients []string                `json:"recipients"`
	Threshold  int                     `json:"threshold"`
	Blocks     []crypto.RecipientBlock `json:"recipient_blocks"`
	Nonce      []byte                  `json:"nonce"`
	Ciphertext []byte                  `json:"ciphertext"`
	Tags       []string                `json:"tags,omitempty"`
}

func sigPayload(e *Entry) ([]byte, error) {
	if e.Version >= 2 {
		return json.Marshal(signableV2{
			Version:    e.Version,
			Name:       e.Name,
			CreatedBy:  e.CreatedBy,
			CreatedAt:  e.CreatedAt,
			UpdatedAt:  e.UpdatedAt,
			Recipients: e.Recipients,
			Threshold:  e.Threshold,
			Blocks:     e.Blocks,
			Nonce:      e.Nonce,
			Ciphertext: e.Ciphertext,
			Tags:       e.Tags,
		})
	}
	return json.Marshal(signableV1{
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
// threshold=1: any recipient can decrypt independently.
// threshold=K>1: K recipients must cooperate (Shamir M-of-N).
// createdAt: original creation time; pass zero to use now (for brand-new entries).
// Passing the original createdAt for re-seals (grant/revoke/edit) ensures the
// preserved timestamp is covered by the signature, preventing tampering.
func Seal(
	name string,
	createdBy string,
	payload *Payload,
	recipients []string,
	bundles map[string]*crypto.PublicBundle,
	signerKP *crypto.KeyPair,
	vaultName string,
	tags []string,
	threshold int,
	createdAt time.Time,
) (*Entry, error) {
	if threshold < 1 {
		threshold = 1
	}
	if threshold > len(recipients) {
		return nil, fmt.Errorf("threshold %d exceeds recipient count %d", threshold, len(recipients))
	}

	// 1. Generate a fresh FEK.
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

	// 3a. Threshold=1: wrap the full FEK for each recipient.
	// 3b. Threshold>1: Shamir-split the FEK into N shares, wrap one share per recipient.
	var blocks []crypto.RecipientBlock

	if threshold == 1 {
		blocks, err = wrapFullFEK(fek, recipients, bundles, info)
	} else {
		blocks, err = wrapShamirShares(fek, recipients, bundles, info, threshold)
	}
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	if createdAt.IsZero() {
		createdAt = now
	}
	e := &Entry{
		Version:    2,
		Name:       name,
		CreatedBy:  createdBy,
		CreatedAt:  createdAt,
		UpdatedAt:  now,
		Recipients: recipients,
		Threshold:  threshold,
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

// Open decrypts a threshold=1 entry using the caller's private key.
func Open(e *Entry, myName string, myKP *crypto.KeyPair, vaultName string) (*Payload, error) {
	if e.Threshold > 1 {
		return nil, fmt.Errorf("%q requires %d-of-%d cooperation — use 'aman collect' to gather shares, then 'aman get --shares'",
			e.Name, e.Threshold, len(e.Recipients))
	}

	block := findBlock(e, myName)
	if block == nil {
		return nil, fmt.Errorf("you (%s) are not a recipient of %q", myName, e.Name)
	}

	info := crypto.EntryInfoForVersion(e.Version, vaultName, e.Name)
	fek, err := crypto.UnwrapFEK(myKP.KEMPriv, block.SealedFEK, info)
	if err != nil {
		return nil, err
	}
	defer memguard.WipeBytes(fek)

	return decryptPayload(fek, e.Nonce, e.Ciphertext)
}

// CollectShare unwraps the caller's Shamir share from a threshold entry.
// The returned share must be saved and combined with K-1 other shares via CombineShares.
func CollectShare(e *Entry, myName string, myKP *crypto.KeyPair, vaultName string) (*crypto.ShamirShare, error) {
	if e.Threshold == 1 {
		return nil, fmt.Errorf("%q is not a threshold entry — use 'aman get' directly", e.Name)
	}

	block := findBlock(e, myName)
	if block == nil {
		return nil, fmt.Errorf("you (%s) are not a recipient of %q", myName, e.Name)
	}

	info := crypto.EntryInfoForVersion(e.Version, vaultName, e.Name)
	shareBytes, err := crypto.UnwrapFEK(myKP.KEMPriv, block.SealedFEK, info)
	if err != nil {
		return nil, err
	}

	return crypto.UnmarshalShare(shareBytes)
}

// OpenWithShares decrypts a threshold entry by combining K Shamir shares.
func OpenWithShares(e *Entry, shares []*crypto.ShamirShare) (*Payload, error) {
	if e.Threshold == 1 {
		return nil, fmt.Errorf("use Open for non-threshold entries")
	}
	if len(shares) < e.Threshold {
		return nil, fmt.Errorf("need %d shares, got %d", e.Threshold, len(shares))
	}

	plain := make([]crypto.ShamirShare, len(shares))
	for i, s := range shares {
		plain[i] = *s
	}

	fek, err := crypto.CombineFEK(plain)
	if err != nil {
		return nil, fmt.Errorf("combine shares: %w", err)
	}
	defer memguard.WipeBytes(fek)

	return decryptPayload(fek, e.Nonce, e.Ciphertext)
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

// Fingerprint returns a short stable ID for an entry.
func Fingerprint(name string) string {
	h := sha256.Sum256([]byte(name))
	return fmt.Sprintf("%x", h[:4])
}

// EntryPath returns the validated path for an entry file within the vault.
// Returns an error if name contains path-traversal sequences that would
// escape the entries directory.
func EntryPath(vaultDir, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("entry name cannot be empty")
	}
	base := filepath.Join(vaultDir, entriesDir)
	p := filepath.Join(base, name+FileExt)
	// filepath.Join already cleans the path; verify it stays inside entries/.
	if !strings.HasPrefix(p, base+string(filepath.Separator)) {
		return "", fmt.Errorf("entry name %q is invalid", name)
	}
	return p, nil
}

const entriesDir = "entries"

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

// ── internal helpers ─────────────────────────────────────────────────────────

func findBlock(e *Entry, name string) *crypto.RecipientBlock {
	for i := range e.Blocks {
		if e.Blocks[i].ID == name {
			return &e.Blocks[i]
		}
	}
	return nil
}

func decryptPayload(fek, nonce, ciphertext []byte) (*Payload, error) {
	plain, err := crypto.DecryptPayload(fek, nonce, ciphertext)
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

func wrapFullFEK(fek []byte, recipients []string, bundles map[string]*crypto.PublicBundle, info []byte) ([]crypto.RecipientBlock, error) {
	blocks := make([]crypto.RecipientBlock, 0, len(recipients))
	for _, r := range recipients {
		bundle, ok := bundles[r]
		if !ok {
			return nil, fmt.Errorf("no public key for recipient %q", r)
		}
		kemPub, err := crypto.KEMPublicFromBundle(bundle)
		if err != nil {
			return nil, fmt.Errorf("parse kem pub for %q: %w", r, err)
		}
		sealed, err := crypto.WrapFEK(kemPub, fek, info)
		if err != nil {
			return nil, fmt.Errorf("wrap fek for %q: %w", r, err)
		}
		blocks = append(blocks, crypto.RecipientBlock{ID: r, SealedFEK: sealed})
	}
	return blocks, nil
}

func wrapShamirShares(fek []byte, recipients []string, bundles map[string]*crypto.PublicBundle, info []byte, threshold int) ([]crypto.RecipientBlock, error) {
	shares, err := crypto.SplitFEK(fek, threshold, len(recipients))
	if err != nil {
		return nil, fmt.Errorf("shamir split: %w", err)
	}

	blocks := make([]crypto.RecipientBlock, 0, len(recipients))
	for i, r := range recipients {
		bundle, ok := bundles[r]
		if !ok {
			return nil, fmt.Errorf("no public key for recipient %q", r)
		}
		kemPub, err := crypto.KEMPublicFromBundle(bundle)
		if err != nil {
			return nil, fmt.Errorf("parse kem pub for %q: %w", r, err)
		}

		// Serialise the share so it can be HPKE-sealed.
		shareBytes, err := crypto.MarshalShare(&shares[i])
		if err != nil {
			return nil, fmt.Errorf("marshal share for %q: %w", r, err)
		}

		sealed, err := crypto.WrapFEK(kemPub, shareBytes, info)
		if err != nil {
			return nil, fmt.Errorf("wrap share for %q: %w", r, err)
		}
		blocks = append(blocks, crypto.RecipientBlock{ID: r, SealedFEK: sealed})
	}
	return blocks, nil
}
