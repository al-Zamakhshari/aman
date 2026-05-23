// Package clipboard copies a secret to the system clipboard and wipes it after a TTL.
package clipboard

import (
	"fmt"
	"time"

	"github.com/atotto/clipboard"
	"github.com/awnumar/memguard"
)

const DefaultTTL = 30 * time.Second

// Copy writes text to the clipboard and schedules a wipe after ttl.
// It returns immediately; the wipe runs in a background goroutine.
// A cancel function is returned to wipe early.
func Copy(text string, ttl time.Duration) (cancel func(), err error) {
	if err := clipboard.WriteAll(text); err != nil {
		return nil, fmt.Errorf("copy to clipboard: %w", err)
	}

	done := make(chan struct{})
	cancel = func() {
		select {
		case <-done:
		default:
			close(done)
		}
	}

	go func() {
		select {
		case <-time.After(ttl):
		case <-done:
		}
		// Wipe clipboard by overwriting with empty string.
		_ = clipboard.WriteAll("")
		// Wipe the in-memory copy.
		buf := []byte(text)
		memguard.WipeBytes(buf)
	}()

	return cancel, nil
}

// CopyWithNotice copies text to the clipboard, prints a TTL notice to stdout,
// and blocks until the TTL expires or the user presses Enter.
func CopyWithNotice(text string, ttl time.Duration, fieldName string) error {
	cancel, err := Copy(text, ttl)
	if err != nil {
		return err
	}
	defer cancel()

	fmt.Printf("✓ %s copied to clipboard — will clear in %s\n", fieldName, ttl)
	return nil
}
