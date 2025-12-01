package ece

import (
	"crypto/rand"
	"errors"
	"log/slog"
	"net/http"
)

// getContentEncoding returns the name of the encoding
// the request's data is encoded with according
// to the Content-Encoding.
//
// If an empty or unknown value if found instead,
// the returned string is empty.
func getContentEncoding(h http.Header) (*Encoding, bool) {
	for _, v := range h.Values("Content-Encoding") {
		encoding, _ := EncodingFromString(v)
		if encoding != nil {
			return encoding, true
		}
	}

	return nil, false
}

// getAcceptedEncoding returns the name of the encoding
// the user-agent accepts according to the
// Accept-Encoding header.
//
// If X-Accept-Encoding exist, it will be considered
// first.
//
// If an empty or unknown value if found instead,
// the returned string is empty.
func getAcceptedEncoding(h http.Header) (*Encoding, bool) {
	values := h.Values("X-Accept-Encoding")
	if len(values) == 0 {
		values = h.Values("Accept-Encoding")
	}

	for _, v := range values {
		encoding, _ := EncodingFromString(v)
		if encoding != nil {
			return encoding, true
		}
	}
	return nil, false
}

// ResponseWriter wraps a pre-existing http.ResponseWriter
// to add supports for encryption using ECE.
type ResponseWriter struct {
	encoding *Encoding
	ew       *Writer
	http.ResponseWriter
}

// Flush implements http.Flusher.
//
// Flush must be called in order for the data written
// to the underlying ResponseWriter to be formatted
// correctly.
func (w *ResponseWriter) Flush() {
	w.ew.Flush()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Write encrypts p and writes it to the underlying ResponseWriter.
func (w *ResponseWriter) Write(p []byte) (int, error) {
	return w.ew.Write(p)
}

// NewResponseWriter upgrades w to write ECE-encoded
// data in HTTP responses.
func NewResponseWriter(key []byte, recordSize int, keyID string, w http.ResponseWriter) (*ResponseWriter, error) {
	encoding, ok := encodingFromKey(key)
	if !ok {
		return nil, errors.New("invalid key size")
	}

	ew, err := NewWriter(key, GenerateSalt(rand.Reader), recordSize, keyID, w)
	if err != nil {
		return nil, err
	}
	w.Header().Add("Content-Encoding", encoding.Name)
	w.Header().Add("Vary", "Content-Encoding")
	return &ResponseWriter{encoding: encoding, ew: ew, ResponseWriter: w}, nil
}

// Handler is an HTTP middleware that can transparently decrypt
// incoming requests and encrypt outgoing responses.
//
// Incoming requests are decrypted if their Content-Encoding
// header is either "aes128gcm" or "aes256gcm". Similarly,
// responses are encrypted if the the Accept-Encoding
// (or X-Accept-Encoding) header is set to either value.
//
// If the configured key doesn't match the encoding scheme
// announced in a request, the server will responds with
// status code 415 Unsupported Media Type.
func Handler(key []byte, recordSize int, keyID string, next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		contentEncoding, ok := getContentEncoding(r.Header)
		if ok {
			if contentEncoding.checkKey(key) {
				r.Body = NewReader(key, r.Body)
			} else {
				w.WriteHeader(http.StatusUnsupportedMediaType)
				return
			}
		}

		acceptedEncoding, ok := getAcceptedEncoding(r.Header)
		if ok && acceptedEncoding.checkKey(key) {
			rw, err := NewResponseWriter(key, recordSize, keyID, w)
			if err != nil {
				slog.ErrorContext(r.Context(), "ece: failed to create ResponseWriter", "error", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			if r.Method == http.MethodHead || r.Method == http.MethodOptions {
				rw.Header().Set("Accept-Encoding", acceptedEncoding.Name)
			}

			defer func() {
				if err := rw.ew.Close(); err != nil {
					slog.ErrorContext(r.Context(), "ece: failed to close ResponseWriter", "error", err)
				}
				rw.Flush()
			}()
			w = rw
		}

		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

// Transport is an [http.RoundTripper] that encrypts outgoing
// request bodies and decrypts incoming response bodies using ECE.
//
// Request bodies are systematically encrypted, while responses
// are only decrypted if the Content-Encoding header is
// set to "aes128gcm" or "aes256gcm".
type Transport struct {
	// Base is the underlying RoundTripper. If nil, [http.DefaultTransport] is used.
	Base http.RoundTripper

	// KeyID is an optional identifier for the encryption key.
	KeyID string

	// RecordSize is the encryption record size. If zero, defaults to 4096.
	RecordSize int

	// Strict, when true, rejects responses that are not ECE-encoded.
	Strict bool

	key      []byte
	encoding *Encoding
}

// RoundTrip implements [http.RoundTripper].
//
// It encrypts the request body (if present) before sending,
// and decrypts the response body if the server returns an
// ECE-encoded response.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		if err := t.encryptRequest(req); err != nil {
			return nil, err
		}
	}
	req.Header.Set("Accept-Encoding", t.encoding.Name)

	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}

	resp, err := base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	encoding, ok := getContentEncoding(resp.Header)
	if ok && encoding.checkKey(t.key) {
		t.decryptResponse(resp)
	} else if t.Strict {
		if err := resp.Body.Close(); err != nil {
			slog.Error("ece: failed to close response body", "error", err)
		}
		return nil, errors.New("ece: strict mode requires encrypted response")
	}

	return resp, nil
}

// encryptRequest encrypts req.Body using ECE.
func (t *Transport) encryptRequest(req *http.Request) error {
	rs := t.RecordSize
	if rs == 0 {
		rs = 4096
	}

	r, err := Pipe(req.Body, t.key, rs, t.KeyID)
	if err != nil {
		return err
	}

	req.ContentLength = -1
	req.Body = r
	req.Header.Set("Content-Encoding", t.encoding.Name)
	return nil
}

// decryptResponse wraps resp.Body with an ECE decrypter.
func (t *Transport) decryptResponse(resp *http.Response) {
	resp.Body = NewReader(t.key, resp.Body)
	resp.ContentLength = -1
}

// NewTransport returns an [http.RoundTripper] that encrypts requests
// and decrypts responses using this encoding.
//
// The base parameter specifies the underlying RoundTripper to use.
// If nil, [http.DefaultTransport] is used.
func (e *Encoding) NewTransport(key []byte, keyID string, recordSize int, base http.RoundTripper) (*Transport, error) {
	if !e.checkKey(key) {
		return nil, errors.New("ece: invalid key size for " + e.Name)
	}
	return &Transport{
		Base:       base,
		KeyID:      keyID,
		RecordSize: recordSize,
		key:        key,
		encoding:   e,
	}, nil
}
