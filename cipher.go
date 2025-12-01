package ece

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
)

// Valid returns true if the content of b is ECE-encoded.
func Valid(b []byte) (ok bool) {
	h := Header{}
	if _, err := h.ReadFrom(bytes.NewReader(b)); err != nil {
		return
	}

	ok = true
	return
}

// Cipher represents an ECE-encoded cipher.
//
// Cipher is useful to validate an ECE-encoded value
// read from JSON or a database.
type Cipher []byte

// UnmarshalJSON implements [json.Unmarshaler], and
// returns an error if b does not start with a valid
// ECE header.
func (c *Cipher) UnmarshalJSON(b []byte) error {
	raw := make([]byte, base64.StdEncoding.DecodedLen(len(b)))
	n, err := base64.StdEncoding.Decode(raw, bytes.Trim(b, `"`))
	if err != nil {
		return fmt.Errorf("value is not a valid quoted base64 string: %v", err)
	}
	raw = raw[:n]

	if !Valid(raw) {
		return errors.New("invalid ECE header")
	}

	*c = raw
	return nil
}

// Scan implements [sql.Scanner] and returns an error
// if v is not a []byte or string that starts with a valid ECE header.
func (c *Cipher) Scan(src interface{}) error {
	var b []byte
	switch v := src.(type) {
	case []byte:
		b = v
	case string:
		b = []byte(v)
	default:
		return errors.New("value must be []byte or string")
	}

	if !Valid(b) {
		return errors.New("invalid ECE header")
	}

	*c = b
	return nil
}
