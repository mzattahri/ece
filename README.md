[![GoDoc reference](https://img.shields.io/badge/godoc-reference-blue.svg)](https://pkg.go.dev/mz.attahri.com/code/ece/v2)
[![npm version](https://img.shields.io/npm/v/@mzattahri/ece.svg)](https://www.npmjs.com/package/@mzattahri/ece)
[![Lint](https://github.com/mzattahri/ece/actions/workflows/lint.yml/badge.svg)](https://github.com/mzattahri/ece/actions/workflows/lint.yml)
[![Test](https://github.com/mzattahri/ece/actions/workflows/test.yml/badge.svg)](https://github.com/mzattahri/ece/actions/workflows/test.yml)

# Encrypted-Content-Encoding for HTTP

An implementation of [RFC 8188](https://datatracker.ietf.org/doc/html/rfc8188)
in Go and JavaScript/TypeScript.

ECE for HTTP defines a way to use standard HTTP content encoding to exchange
AES-GCM encrypted payloads between a client and server.

While the RFC only mentions 128-bit encryption with `AES-128-GCM`, this
library provides support for `AES-256-GCM` as well when a key sufficiently
long (32 bytes) is provided.

## JavaScript / TypeScript

```bash
npm i @mzattahri/ece
```

See [js/README.md](js/README.md) for full documentation.

## Go

See also: [TypeScript/JavaScript implementation](js/README.md)

The library exposes 4 basic elements:

1. A `Reader` to decrypt;
2. A `Writer` to encrypt;
3. An HTTP middleware to handle server-side encryption/decryption;
4. An HTTP `Transport` for client-side encryption/decryption.

### Reader

`Reader` deciphers data from a reader (`io.Reader`) containing encrypted
data.

```go
var key []byte            // Main decryption key
var cipher io.ReadCloser  // AES-GCM encrypted data

r := ece.NewReader(key, cipher)
plain, err := io.ReadAll(r)
if err != nil {
  log.Fatalf("error during decryption: %v", err)
}
defer r.Close()

fmt.Println(plain) // plain version of the content of cipher.
```

### Writer

`Writer` writes encrypted data into another writer (`io.Writer`).

```go
var key = []byte("16 or 32 bytes long key")   // Main decryption key
var dest io.Writer                            // Where cipher will be written

var (
  salt        = ece.GenerateSalt(rand.Reader)  // Must be random
  recordSize  = 4096                    // Record size
  keyID       = "ID of the main key"    // (Empty string to omit)
)
w, err := ece.NewWriter(key, salt, recordSize, keyID, dest)
if err != nil {
  log.Fatalf("error initializing writer: %v", err)
}
defer w.Close()     // Cipher may be mis-formatted if omitted

if _, err := io.WriteString(w, "Hello, World!"); err != nil {
  log.Fatalf("error writing cipher: %v", err)
}

log.Println("dest now contains encrypted data")
```

### HTTP Handler

`Handler` is an HTTP middleware you can use to transparently
decrypt incoming requests and encrypt outgoing responses.

Incoming requests are decrypted if they come with a header `Content-Encoding`
set to either `aes128gcm` or `aes256gcm`. Similarly, responses are encrypted
if the request's `Accept-Encoding` or `X-Accept-Encoding` headers are set
to either value.

```go
h := http.HandlerFunc(
  func(w http.ResponseWriter, r *http.Request) {
    // r.Body now contains plain data if the client sent
    // encrypted request.

    // w.Write will encrypt the data before sending
    // it back.
  },
)

var (
  key = []byte("256-bit long key")
  rs  = 4096
)
http.ListenAndServe(":8000", ece.Handler(key, rs, h))
```

### HTTP Transport

`Transport` is an `http.RoundTripper` that handles the encryption of
outgoing requests and the decryption of responses. Use it with any
`http.Client`.

Requests are systematically encrypted, while responses are only decrypted if
the `Content-Encoding` header is set to `aes128gcm` or `aes256gcm`.

```go
var (
  keyID       = "ID of the key below"              // (Empty string to omit)
  key         = []byte("16 or 32 byte long key")
  payload     = strings.NewReader(`{"key": "value"}`)
)

transport, err := ece.AES128GCM.NewTransport(key, keyID, 4096, nil)
if err != nil {
  log.Fatalf("error initializing transport: %v", err)
}

client := &http.Client{Transport: transport}
resp, err := client.Post("https://api.example.com", "application/json", payload)
if err != nil {
  log.Fatalf("HTTP request failed: %v", err)
}

// payload was encrypted before it was sent

// resp.Body is decrypted if the server returned an encrypted response.
data, err := io.ReadAll(resp.Body)
if err != nil {
  log.Fatalf("error reading response: %v", err)
}

log.Println(data) // plain data
```

### Generating Keys

Use the `GenerateKey` method on the encoding to create a key of the correct size:

```go
import "crypto/rand"

// 256-bit key (32 bytes)
key256 := ece.AES256GCM.GenerateKey(rand.Reader)

// 128-bit key (16 bytes)
key128 := ece.AES128GCM.GenerateKey(rand.Reader)
```

## Contributions

Contributions are welcome via Pull Requests.
