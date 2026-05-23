// Package audit provides an append-only, hash-chained audit log for aman.
// Every vault operation is recorded as a JSON line; each entry carries the
// SHA-256 hash of the previous line, forming a tamper-evident chain.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Event describes a single vault operation.
type Event struct {
	Action     string   `json:"action"`               // add, get, grant, revoke, delete, init
	Entry      string   `json:"entry,omitempty"`
	Actor      string   `json:"actor,omitempty"`
	Recipients []string `json:"recipients,omitempty"` // added or removed recipients
}

// LogEntry is a single line in the audit log.
type LogEntry struct {
	Seq      int64     `json:"seq"`
	Time     time.Time `json:"time"`
	PrevHash string    `json:"prev_hash"` // SHA-256 hex of the previous raw JSON line
	Event    Event     `json:"event"`
}

// Logger is an append-only audit log writer.
type Logger struct {
	path     string
	mu       sync.Mutex
	prevHash string
	seq      int64
}

// NewLogger opens (or creates) the audit log at path and reads the last hash.
func NewLogger(path string) (*Logger, error) {
	l := &Logger{path: path, prevHash: "0000000000000000000000000000000000000000000000000000000000000000"}

	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("open audit log: %w", err)
	}

	if len(data) > 0 {
		// Walk all lines to get the last hash and seq.
		lines := splitLines(data)
		for _, line := range lines {
			if len(line) == 0 {
				continue
			}
			var entry LogEntry
			if err := json.Unmarshal(line, &entry); err == nil {
				l.seq = entry.Seq
				h := sha256.Sum256(line)
				l.prevHash = hex.EncodeToString(h[:])
			}
		}
	}

	return l, nil
}

// Append records an event. Errors are intentionally silent to avoid disrupting
// vault operations — the log is best-effort for auditability, not for correctness.
func (l *Logger) Append(ev Event) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.seq++
	entry := LogEntry{
		Seq:      l.seq,
		Time:     time.Now().UTC(),
		PrevHash: l.prevHash,
		Event:    ev,
	}

	line, err := json.Marshal(entry)
	if err != nil {
		return
	}

	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()

	line = append(line, '\n')
	if _, err := f.Write(line); err != nil {
		return
	}

	h := sha256.Sum256(line[:len(line)-1]) // hash without trailing newline
	l.prevHash = hex.EncodeToString(h[:])
}

// ReadAll reads and returns all log entries from the file.
func ReadAll(path string) ([]LogEntry, error) {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var entries []LogEntry
	for _, line := range splitLines(data) {
		if len(line) == 0 {
			continue
		}
		var e LogEntry
		if err := json.Unmarshal(line, &e); err == nil {
			entries = append(entries, e)
		}
	}
	return entries, nil
}

// Verify walks the chain and returns an error if any link is broken.
func Verify(path string) error {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return err
	}

	prev := "0000000000000000000000000000000000000000000000000000000000000000"
	for i, line := range splitLines(data) {
		if len(line) == 0 {
			continue
		}
		var e LogEntry
		if err := json.Unmarshal(line, &e); err != nil {
			return fmt.Errorf("line %d: invalid JSON: %w", i+1, err)
		}
		if e.PrevHash != prev {
			return fmt.Errorf("line %d: chain broken (expected %s, got %s)", i+1, prev, e.PrevHash)
		}
		h := sha256.Sum256(line)
		prev = hex.EncodeToString(h[:])
	}
	return nil
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}
