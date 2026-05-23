package audit_test

import (
	"path/filepath"
	"testing"

	"github.com/al-Zamakhshari/aman/internal/audit"
)

func TestAppendReadAll(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")

	l, err := audit.NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	l.Append(audit.Event{Action: "init"})
	l.Append(audit.Event{Action: "add", Entry: "github", Actor: "alice", Recipients: []string{"alice", "bob"}})
	l.Append(audit.Event{Action: "get", Entry: "github", Actor: "bob"})

	entries, err := audit.ReadAll(path)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries[0].Event.Action != "init" {
		t.Errorf("entry[0] action = %q, want %q", entries[0].Event.Action, "init")
	}
	if entries[1].Event.Entry != "github" {
		t.Errorf("entry[1] name = %q, want %q", entries[1].Event.Entry, "github")
	}
	if entries[2].Event.Actor != "bob" {
		t.Errorf("entry[2] actor = %q, want %q", entries[2].Event.Actor, "bob")
	}

	// Sequence numbers must be monotonically increasing.
	for i, e := range entries {
		if e.Seq != int64(i+1) {
			t.Errorf("entry[%d] seq = %d, want %d", i, e.Seq, i+1)
		}
	}
}

func TestVerifyChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")

	l, _ := audit.NewLogger(path)
	l.Append(audit.Event{Action: "a"})
	l.Append(audit.Event{Action: "b"})
	l.Append(audit.Event{Action: "c"})

	if err := audit.Verify(path); err != nil {
		t.Fatalf("Verify on intact log: %v", err)
	}
}

func TestResumeAfterReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")

	l1, _ := audit.NewLogger(path)
	l1.Append(audit.Event{Action: "first"})
	l1.Append(audit.Event{Action: "second"})

	// Reopen and append more.
	l2, err := audit.NewLogger(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	l2.Append(audit.Event{Action: "third"})

	// Chain must still be valid end-to-end.
	if err := audit.Verify(path); err != nil {
		t.Fatalf("Verify after reopen: %v", err)
	}

	entries, _ := audit.ReadAll(path)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries after reopen, got %d", len(entries))
	}
	if entries[2].Event.Action != "third" {
		t.Errorf("entry[2] = %q, want %q", entries[2].Event.Action, "third")
	}
}

func TestEmptyLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")

	entries, err := audit.ReadAll(path)
	if err != nil {
		t.Fatalf("ReadAll on missing log: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}
