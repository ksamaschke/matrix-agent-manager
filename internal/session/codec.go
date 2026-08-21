package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	keyBytes       = 32
	version        = byte(1)
	timestampBytes = 8
)

// Codec seals small opaque browser values. The key must be provided by the
// deployment and is never generated or persisted by this package.
type Codec struct {
	aead cipher.AEAD
	now  func() time.Time
}

// NewKey creates a codec from an exact 256-bit key.
func NewKey(raw string, now func() time.Time) (*Codec, error) {
	if len(raw) != keyBytes {
		return nil, fmt.Errorf("session key must be exactly %d bytes", keyBytes)
	}
	block, err := aes.NewCipher([]byte(raw))
	if err != nil {
		return nil, fmt.Errorf("create session cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create session AEAD: %w", err)
	}
	if now == nil {
		now = time.Now
	}
	return &Codec{aead: aead, now: now}, nil
}

// Seal encrypts a payload and binds it to a purpose and expiry.
func (c *Codec) Seal(purpose string, expiresAt time.Time, payload any) (string, error) {
	if strings.TrimSpace(purpose) == "" {
		return "", errors.New("session purpose is required")
	}
	if !expiresAt.After(c.now()) {
		return "", errors.New("session expiry must be in the future")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode session payload: %w", err)
	}
	plaintext := make([]byte, timestampBytes+len(body))
	binary.BigEndian.PutUint64(plaintext[:timestampBytes], uint64(expiresAt.Unix()))
	copy(plaintext[timestampBytes:], body)
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate session nonce: %w", err)
	}
	sealed := c.aead.Seal(nil, nonce, plaintext, []byte(purpose))
	out := make([]byte, 0, 1+len(nonce)+len(sealed))
	out = append(out, version)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// Open authenticates, decrypts, purpose-checks, and expiry-checks a payload.
func (c *Codec) Open(token, purpose string, destination any) error {
	if strings.TrimSpace(purpose) == "" {
		return errors.New("session purpose is required")
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return errors.New("invalid session encoding")
	}
	minimum := 1 + c.aead.NonceSize() + c.aead.Overhead() + timestampBytes
	if len(raw) < minimum || raw[0] != version {
		return errors.New("invalid session token")
	}
	nonce := raw[1 : 1+c.aead.NonceSize()]
	plaintext, err := c.aead.Open(nil, nonce, raw[1+c.aead.NonceSize():], []byte(purpose))
	if err != nil {
		return errors.New("invalid session authentication")
	}
	expiresAt := time.Unix(int64(binary.BigEndian.Uint64(plaintext[:timestampBytes])), 0)
	if !expiresAt.After(c.now()) {
		return errors.New("session expired")
	}
	if err := json.Unmarshal(plaintext[timestampBytes:], destination); err != nil {
		return fmt.Errorf("decode session payload: %w", err)
	}
	return nil
}
