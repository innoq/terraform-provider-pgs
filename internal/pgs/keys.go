package pgs

import (
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ParsedKey is an SSH public key in the exact form pgs stores and compares it.
type ParsedKey struct {
	// Normalized is "<type> <base64>" with no comment (shared.KeyForKeyText in pico).
	Normalized string
	// Comment is the authorized_keys comment, "" if none.
	Comment string
}

// ParseKey parses an authorized_keys-format line.
func ParseKey(s string) (ParsedKey, error) {
	if strings.ContainsAny(strings.TrimSpace(s), "\r\n") {
		return ParsedKey{}, fmt.Errorf("a key must be a single line; list each key as its own entry (e.g. split an authorized_keys file with split/for_each)")
	}
	pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(s)))
	if err != nil {
		return ParsedKey{}, fmt.Errorf("not a valid SSH public key: %w", err)
	}
	return ParsedKey{
		Normalized: fmt.Sprintf("%s %s", pub.Type(), base64.StdEncoding.EncodeToString(pub.Marshal())),
		Comment:    comment,
	}, nil
}

// DefaultDescription is what `pgs init` stores as the key name: the key comment, else "main".
func DefaultDescription(comment string) string {
	if comment == "" {
		return "main"
	}
	return comment
}
