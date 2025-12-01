package ece

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"testing"
)

// TestVector represents a test vector for cross-language interoperability.
type TestVector struct {
	Name       string `json:"name"`
	KeyBase64  string `json:"key"`
	SaltBase64 string `json:"salt"`
	RecordSize int    `json:"recordSize"`
	KeyID      string `json:"keyID"`
	Plain      string `json:"plain"`
	Cipher     string `json:"cipher"` // base64 encoded
}

// TestGenerateInteropVectors generates test vectors that can be used
// by the JavaScript implementation.
func TestGenerateInteropVectors(t *testing.T) {
	vectors := []TestVector{
		{
			Name:       "AES-128-GCM simple",
			KeyBase64:  base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")),
			SaltBase64: base64.StdEncoding.EncodeToString([]byte("saltsaltsaltsalt")),
			RecordSize: 4096,
			KeyID:      "",
			Plain:      "Hello, World!",
		},
		{
			Name:       "AES-256-GCM simple",
			KeyBase64:  base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
			SaltBase64: base64.StdEncoding.EncodeToString([]byte("saltsaltsaltsalt")),
			RecordSize: 4096,
			KeyID:      "test-key",
			Plain:      "Hello, World!",
		},
		{
			Name:       "AES-256-GCM multi-record",
			KeyBase64:  base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
			SaltBase64: base64.StdEncoding.EncodeToString([]byte("saltsaltsaltsalt")),
			RecordSize: 32,
			KeyID:      "",
			Plain:      "This is a longer message that will span multiple records.",
		},
	}

	for i := range vectors {
		v := &vectors[i]
		key, err := base64.StdEncoding.DecodeString(v.KeyBase64)
		if err != nil {
			t.Fatalf("%s: failed to decode key: %v", v.Name, err)
		}
		salt, err := base64.StdEncoding.DecodeString(v.SaltBase64)
		if err != nil {
			t.Fatalf("%s: failed to decode salt: %v", v.Name, err)
		}

		buf := new(bytes.Buffer)
		w, err := NewWriter(key, salt, v.RecordSize, v.KeyID, buf)
		if err != nil {
			t.Fatalf("%s: NewWriter failed: %v", v.Name, err)
		}
		if _, err := w.Write([]byte(v.Plain)); err != nil {
			t.Fatalf("%s: Write failed: %v", v.Name, err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("%s: Close failed: %v", v.Name, err)
		}
		v.Cipher = base64.StdEncoding.EncodeToString(buf.Bytes())
	}

	// Write vectors to file for JS tests
	data, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal vectors: %v", err)
	}
	if err := os.WriteFile("js/src/interop-vectors.json", data, 0o644); err != nil {
		t.Fatalf("Failed to write vectors: %v", err)
	}
	t.Logf("Generated %d test vectors", len(vectors))
}

// TestInteropVectorsRoundTrip verifies Go can decrypt its own vectors.
func TestInteropVectorsRoundTrip(t *testing.T) {
	data, err := os.ReadFile("js/src/interop-vectors.json")
	if err != nil {
		t.Skip("interop vectors not generated yet")
	}

	var vectors []TestVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("Failed to parse vectors: %v", err)
	}

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			key, err := base64.StdEncoding.DecodeString(v.KeyBase64)
			if err != nil {
				t.Fatalf("failed to decode key: %v", err)
			}
			cipher, err := base64.StdEncoding.DecodeString(v.Cipher)
			if err != nil {
				t.Fatalf("failed to decode cipher: %v", err)
			}

			r := NewReader(key, bytes.NewReader(cipher))
			plain, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}
			if string(plain) != v.Plain {
				t.Fatalf("Mismatch: got %q, want %q", plain, v.Plain)
			}
		})
	}
}
