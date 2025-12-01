# Changelog

## v2.0.0

### Breaking Changes

- **Module path changed**: Import path is now `mz.attahri.com/code/ece/v2` (was `code.posterity.life/ece`)
- **`NewRandomSalt()` renamed**: Use `GenerateSalt(rand.Reader)` instead
- **`RandomKey()` renamed**: Use `Encoding.GenerateKey(rand.Reader)` instead
- **`NewClient()` replaced**: Use `Encoding.NewTransport()` which returns an `http.RoundTripper` for use with any `http.Client`
- **`EncodeString()` replaced**: Use generic `Encode[T ~string | ~[]byte]()` function
- **`NewReader()` signature changed**: Now accepts `io.Reader` instead of `io.ReadCloser`
- **`Handler()` signature changed**: Now requires `keyID` parameter
- **`NewResponseWriter()` signature changed**: Now requires `keyID` parameter
- **`NewReader()` panics on invalid key**: Instead of returning an error

### Added

- **JavaScript/TypeScript implementation** (`@mzattahri/ece` on npm):
  - `Encoder` and `Decoder` classes for encryption/decryption
  - Streaming support via `TransformStream`
  - HTTP handler middleware for servers
  - `eceFetch()` wrapper for client-side fetch with automatic encryption
  - Full interoperability with the Go implementation

- **New Go functions**:
  - `Valid([]byte)` - Check if bytes contain a valid ECE header
  - `Decode(key, cipher)` - Decode ECE-encoded bytes
  - `Encode[T](key, plain)` - Generic encode function for strings and byte slices

- **Cipher type improvements**:
  - `Scan()` now accepts both `[]byte` and `string` types

- **HTTP Transport**:
  - `Transport` implements `http.RoundTripper` interface
  - Configurable `RecordSize` and `KeyID` fields
  - `Strict` mode to reject non-encrypted responses

- **Interoperability tests**: Cross-language tests between Go and TypeScript implementations

### Changed

- **HTTP Handler**: Properly handles `HEAD` and `OPTIONS` requests
- **Record size validation**: Minimum record size is now enforced (18 bytes)
- **Logging**: Uses `log/slog` instead of `log` package
- **XOR implementation**: Uses `crypto/subtle.XORBytes` for constant-time operations
- **CEK derivation**: Encoding-specific info strings for key derivation

### Fixed

- `Header.ReadFrom()` now correctly returns bytes read on partial errors
- `Writer.ReadFrom()` and `Reader.WriteTo()` implement proper `io.ReaderFrom`/`io.WriterTo` semantics
- `ResponseWriter` no longer sets `Content-Type` header (left to application)
- HTTP client properly sets `ContentLength = -1` for chunked encoding
