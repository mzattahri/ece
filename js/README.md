[![npm version](https://img.shields.io/npm/v/@mzattahri/ece.svg)](https://www.npmjs.com/package/@mzattahri/ece)

# Encrypted-Content-Encoding for HTTP

A TypeScript/JavaScript implementation of
[RFC 8188](https://datatracker.ietf.org/doc/html/rfc8188).

ECE for HTTP defines a way to use standard HTTP content encoding to exchange
AES-GCM encrypted payloads between a client and server.

While the RFC only mentions 128-bit encryption with `AES-128-GCM`, this
library provides support for `AES-256-GCM` as well when a 256-bit key
is provided.

See also: [Go implementation](../README.md#go)

## Installation

```bash
npm install @mzattahri/ece
```

## Library

The library exposes 4 basic elements:

1. A `Decoder` to decrypt;
2. An `Encoder` to encrypt;
3. An HTTP handler/middleware for server-side encryption/decryption;
4. An HTTP `fetch` wrapper for client-side encryption/decryption.

### Decoder

`Decoder` deciphers data from an ECE-encoded cipher.

```typescript
import { Decoder } from '@mzattahri/ece'

const key: CryptoKey = // AES-GCM key
const cipher: Uint8Array = // AES-GCM encrypted data

const plain = await Decoder.decode(key, cipher)
console.log(new TextDecoder().decode(plain))
```

For streaming decryption, use `Decoder.transformStream()`:

```typescript
const response = await fetch('https://example.com/encrypted')
const decryptStream = Decoder.transformStream(key)
const plainStream = response.body.pipeThrough(decryptStream)
```

### Encoder

`Encoder` encrypts data into ECE format.

```typescript
import { Encoder, randomSalt } from '@mzattahri/ece'

const key: CryptoKey = // AES-GCM key (128 or 256 bit)

const salt = randomSalt()         // Must be random
const recordSize = 4096           // Record size
const keyID = 'ID of the key'     // (Empty string to omit)

const plain = new TextEncoder().encode('Hello, World!')
const cipher = await Encoder.encode(key, plain, salt, recordSize, keyID)
```

For streaming encryption, use `Encoder.transformStream()`:

```typescript
const encryptStream = await Encoder.transformStream(key, salt, recordSize, keyID)
const encryptedStream = plainStream.pipeThrough(encryptStream)
```

### HTTP Handler

`handler` wraps a request handler to transparently decrypt incoming requests
and encrypt outgoing responses.

Incoming requests are decrypted if they come with a header `Content-Encoding`
set to either `aes128gcm` or `aes256gcm`. Similarly, responses are encrypted
if the request's `Accept-Encoding` or `X-Accept-Encoding` headers are set
to either value.

```typescript
import { AES256GCM } from '@mzattahri/ece'

const key: CryptoKey = // 256-bit AES-GCM key

const handler = AES256GCM.handler(key, async (request) => {
  // request.body is automatically decrypted if the client
  // sent an encrypted request.

  const data = await request.json()

  // The response will be encrypted before sending if the
  // client sent Accept-Encoding: aes256gcm
  return new Response(JSON.stringify({ ok: true }))
}, {
  recordSize: 4096,    // Optional (default: 4096)
  keyID: 'my-key-id',  // Optional (default: '')
})
```

For middleware-based frameworks:

```typescript
const middleware = AES256GCM.middleware(key, { recordSize: 4096 })

// Use with your framework's middleware pattern
const response = await middleware(request, nextHandler)
```

### HTTP Fetch

`fetch` is a wrapper around the standard `fetch` API that handles encryption
of outgoing requests and decryption of responses.

Requests are systematically encrypted, while responses are only decrypted if
the `Content-Encoding` header is set to `aes128gcm` or `aes256gcm`.

```typescript
import { fetch } from '@mzattahri/ece'

const key: CryptoKey = // 128 or 256-bit AES-GCM key

const response = await fetch('https://api.example.com', key, {
  method: 'POST',
  body: JSON.stringify({ key: 'value' }),
  recordSize: 4096,    // Optional (default: 4096)
  keyID: 'my-key-id',  // Optional (default: '')
})

// Request body was encrypted before it was sent.
// Response body is decrypted if the server returned an encrypted response.
const data = await response.json()
console.log(data)
```

## Generating Keys

Use the `generateKey()` method on the encoding to create a key of the correct size:

```typescript
import { AES256GCM, AES128GCM } from '@mzattahri/ece'

// 256-bit key
const key = await AES256GCM.generateKey()

// 128-bit key
const key128 = await AES128GCM.generateKey()

// Non-extractable key (cannot be exported)
const nonExtractable = await AES256GCM.generateKey(false)
```

## Contributions

Contributions are welcome via Pull Requests.
