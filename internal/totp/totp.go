// Package totp generates RFC 6238 TOTP codes from a base32 secret.
package totp

import (
	"fmt"
	"time"

	"github.com/pquerna/otp/totp"
)

// Code returns the current TOTP code for a base32-encoded secret.
func Code(secret string) (string, error) {
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		return "", fmt.Errorf("generate totp: %w", err)
	}
	return code, nil
}

// TimeRemaining returns the seconds remaining in the current 30-second window.
func TimeRemaining() int {
	return 30 - int(time.Now().Unix()%30)
}

// ValidateSecret checks whether a base32 string is a plausible TOTP secret.
func ValidateSecret(secret string) error {
	_, err := totp.GenerateCode(secret, time.Now())
	return err
}
