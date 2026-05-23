// Package crypto — Shamir Secret Sharing over GF(2^8).
// Adapted from github.com/al-Zamakhshari/maknoon/pkg/crypto/shares.go.
package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
)

// ShamirShare is one shard of a split secret.
type ShamirShare struct {
	Version   byte   `json:"v"`
	Threshold byte   `json:"t"`
	Index     byte   `json:"i"`
	Data      []byte `json:"d"`
	HMACKey   []byte `json:"k,omitempty"` // random per-share HMAC key (v2+); absent in v1 shares
	Checksum  []byte `json:"c"`
}

const (
	shamirVersion = 1
	shamirChkSize = 16
	shamirKeySize = 16
)

// shamirChkKeyLegacy is the hardcoded key used by v1 shares — kept for backward compat only.
var shamirChkKeyLegacy = []byte("aman SSS share checksum v1")

// GF(2^8) tables — initialised once.
var (
	sfLog [256]byte
	sfExp [512]byte
)

func init() {
	var x byte = 1
	for i := 0; i < 255; i++ {
		sfLog[x] = byte(i)
		sfExp[i] = x
		sfExp[i+255] = x
		x = sfMulStep(x, 0x03)
	}
}

func sfMulStep(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		hi := a&0x80 != 0
		a <<= 1
		if hi {
			a ^= 0x1b
		}
		b >>= 1
	}
	return p
}

func sfAdd(a, b byte) byte { return a ^ b }

func sfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return sfExp[uint16(sfLog[a])+uint16(sfLog[b])]
}

func sfDiv(a, b byte) byte {
	if b == 0 {
		panic("gf division by zero")
	}
	if a == 0 {
		return 0
	}
	return sfExp[uint16(sfLog[a])+255-uint16(sfLog[b])]
}

// SplitFEK splits a 32-byte FEK into n shares requiring m to reconstruct.
func SplitFEK(fek []byte, m, n int) ([]ShamirShare, error) {
	if m < 2 || m > n || n > 255 {
		return nil, errors.New("invalid threshold: need 2 ≤ m ≤ n ≤ 255")
	}

	shares := make([]ShamirShare, n)
	for i := range shares {
		shares[i] = ShamirShare{
			Version:   shamirVersion,
			Threshold: byte(m),
			Index:     byte(i + 1),
			Data:      make([]byte, len(fek)),
		}
	}

	for j, s := range fek {
		poly := make([]byte, m)
		poly[0] = s
		for i := 1; i < m; i++ {
			r, _ := rand.Int(rand.Reader, big.NewInt(256))
			poly[i] = byte(r.Int64())
		}
		for i := 1; i <= n; i++ {
			val := poly[0]
			xi := byte(i)
			x := byte(i)
			for k := 1; k < m; k++ {
				val = sfAdd(val, sfMul(poly[k], xi))
				xi = sfMul(xi, x)
			}
			shares[i-1].Data[j] = val
		}
	}

	for i := range shares {
		key := make([]byte, shamirKeySize)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("rand hmac key: %w", err)
		}
		shares[i].HMACKey = key
		h := hmac.New(newSHA256, key)
		h.Write([]byte{shares[i].Version, shares[i].Threshold, shares[i].Index})
		h.Write(shares[i].Data)
		sum := h.Sum(nil)
		shares[i].Checksum = sum[:shamirChkSize]
	}
	return shares, nil
}

// CombineFEK reconstructs the FEK from at least m shares.
func CombineFEK(shares []ShamirShare) ([]byte, error) {
	if len(shares) == 0 {
		return nil, errors.New("no shares provided")
	}
	m := int(shares[0].Threshold)
	if len(shares) < m {
		return nil, fmt.Errorf("need %d shares, got %d", m, len(shares))
	}

	secretLen := len(shares[0].Data)
	seen := make(map[byte]bool)
	for _, s := range shares {
		if seen[s.Index] {
			return nil, fmt.Errorf("duplicate share index %d", s.Index)
		}
		seen[s.Index] = true
		if s.Version != shamirVersion {
			return nil, fmt.Errorf("unsupported share version %d", s.Version)
		}
		if int(s.Threshold) != m {
			return nil, errors.New("inconsistent threshold across shares")
		}
		if len(s.Data) != secretLen {
			return nil, errors.New("inconsistent share data length")
		}
		// Use the per-share HMAC key if present (v2+); fall back to legacy key for v1 shares.
		chkKey := s.HMACKey
		if len(chkKey) == 0 {
			chkKey = shamirChkKeyLegacy
		}
		h := hmac.New(newSHA256, chkKey)
		h.Write([]byte{s.Version, s.Threshold, s.Index})
		h.Write(s.Data)
		sum := h.Sum(nil)
		if !hmac.Equal(s.Checksum, sum[:shamirChkSize]) {
			return nil, fmt.Errorf("checksum mismatch on share %d", s.Index)
		}
	}

	secret := make([]byte, secretLen)
	for j := 0; j < secretLen; j++ {
		var val byte
		for i := range shares {
			basis := byte(1)
			for k := range shares {
				if i == k {
					continue
				}
				num := shares[k].Index
				den := sfAdd(shares[i].Index, shares[k].Index)
				basis = sfMul(basis, sfDiv(num, den))
			}
			val = sfAdd(val, sfMul(shares[i].Data[j], basis))
		}
		secret[j] = val
	}
	return secret, nil
}

// MarshalShare serialises a share to JSON for saving to a .share file.
func MarshalShare(s *ShamirShare) ([]byte, error) {
	return json.Marshal(s)
}

// UnmarshalShare parses a share from JSON.
func UnmarshalShare(data []byte) (*ShamirShare, error) {
	var s ShamirShare
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse share: %w", err)
	}
	return &s, nil
}

// newSHA256 is a crypto/sha256 constructor for hmac.New.
func newSHA256() hash.Hash { return sha256.New() }
