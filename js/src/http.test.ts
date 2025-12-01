import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import {
  AES128GCM,
  AES256GCM,
  Encoder,
  Decoder,
  getContentEncoding,
  getAcceptedEncoding,
  isEncrypted,
  fetch,
} from "./index"

// Helper to generate AES-GCM keys
async function generateKey(bits: 128 | 256): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: bits }, true, [
    "encrypt",
    "decrypt",
  ])
}

// Helper to read a stream to completion
async function streamToUint8Array(
  stream: ReadableStream<Uint8Array>,
): Promise<Uint8Array> {
  const reader = stream.getReader()
  const chunks: Uint8Array[] = []
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    chunks.push(value)
  }
  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0)
  const result = new Uint8Array(totalLength)
  let offset = 0
  for (const chunk of chunks) {
    result.set(chunk, offset)
    offset += chunk.length
  }
  return result
}

describe("getContentEncoding", () => {
  it("should return AES128GCM for aes128gcm header", () => {
    const headers = new Headers({ "Content-Encoding": "aes128gcm" })
    expect(getContentEncoding(headers)).toBe(AES128GCM)
  })

  it("should return AES256GCM for aes256gcm header", () => {
    const headers = new Headers({ "Content-Encoding": "aes256gcm" })
    expect(getContentEncoding(headers)).toBe(AES256GCM)
  })

  it("should return null for gzip header", () => {
    const headers = new Headers({ "Content-Encoding": "gzip" })
    expect(getContentEncoding(headers)).toBeNull()
  })

  it("should return null for missing header", () => {
    const headers = new Headers()
    expect(getContentEncoding(headers)).toBeNull()
  })

  it("should handle compound encoding values", () => {
    const headers = new Headers({ "Content-Encoding": "gzip, aes256gcm" })
    expect(getContentEncoding(headers)).toBe(AES256GCM)
  })
})

describe("getAcceptedEncoding", () => {
  it("should return AES128GCM for aes128gcm Accept-Encoding", () => {
    const headers = new Headers({ "Accept-Encoding": "aes128gcm" })
    expect(getAcceptedEncoding(headers)).toBe(AES128GCM)
  })

  it("should return AES256GCM for aes256gcm Accept-Encoding", () => {
    const headers = new Headers({ "Accept-Encoding": "aes256gcm" })
    expect(getAcceptedEncoding(headers)).toBe(AES256GCM)
  })

  it("should prefer X-Accept-Encoding over Accept-Encoding", () => {
    const headers = new Headers({
      "Accept-Encoding": "aes128gcm",
      "X-Accept-Encoding": "aes256gcm",
    })
    expect(getAcceptedEncoding(headers)).toBe(AES256GCM)
  })

  it("should return null for missing headers", () => {
    const headers = new Headers()
    expect(getAcceptedEncoding(headers)).toBeNull()
  })

  it("should return null for non-ECE encodings", () => {
    const headers = new Headers({ "Accept-Encoding": "gzip, deflate, br" })
    expect(getAcceptedEncoding(headers)).toBeNull()
  })
})

describe("isEncrypted", () => {
  it("should return true for ECE-encoded content", () => {
    const headers = new Headers({ "Content-Encoding": "aes128gcm" })
    expect(isEncrypted(headers)).toBe(true)
  })

  it("should return false for non-ECE content", () => {
    const headers = new Headers({ "Content-Encoding": "gzip" })
    expect(isEncrypted(headers)).toBe(false)
  })

  it("should return false for missing Content-Encoding", () => {
    const headers = new Headers()
    expect(isEncrypted(headers)).toBe(false)
  })
})

describe("fetch", () => {
  const originalFetch = globalThis.fetch

  beforeEach(() => {
    vi.restoreAllMocks()
  })

  afterEach(() => {
    globalThis.fetch = originalFetch
  })

  it("should set Accept-Encoding header", async () => {
    const key = await generateKey(256)
    let capturedRequest: Request | null = null

    globalThis.fetch = vi.fn(async (request: Request) => {
      capturedRequest = request
      return new Response("ok")
    }) as typeof globalThis.fetch

    await fetch("https://example.com/api", key)

    expect(capturedRequest).not.toBeNull()
    expect(capturedRequest!.headers.get("Accept-Encoding")).toBe("aes256gcm")
  })

  it("should encrypt request body", async () => {
    const key = await generateKey(256)
    const plaintext = new TextEncoder().encode("Hello, World!")
    let capturedBody: Uint8Array | null = null

    globalThis.fetch = vi.fn(async (request: Request) => {
      if (request.body) {
        capturedBody = await streamToUint8Array(request.body)
      }
      return new Response("ok")
    }) as typeof globalThis.fetch

    await fetch("https://example.com/api", key, {
      method: "POST",
      body: plaintext,
    })

    expect(capturedBody).not.toBeNull()
    // Encrypted body should be different from plaintext
    expect(capturedBody).not.toEqual(plaintext)
    // Should have Content-Encoding header set
  })

  it("should set Content-Encoding when encrypting body", async () => {
    const key = await generateKey(128)
    let capturedRequest: Request | null = null

    globalThis.fetch = vi.fn(async (request: Request) => {
      capturedRequest = request
      // Consume the body to avoid warnings
      if (request.body) await streamToUint8Array(request.body)
      return new Response("ok")
    }) as typeof globalThis.fetch

    await fetch("https://example.com/api", key, {
      method: "POST",
      body: new TextEncoder().encode("test"),
    })

    expect(capturedRequest!.headers.get("Content-Encoding")).toBe("aes128gcm")
  })

  it("should decrypt encrypted response", async () => {
    const key = await generateKey(256)
    const plaintext = new TextEncoder().encode("Secret message from server")

    // Create encrypted response body
    const encrypted = await Encoder.encode(key, plaintext)

    globalThis.fetch = vi.fn(async () => {
      return new Response(encrypted, {
        headers: { "Content-Encoding": "aes256gcm" },
      })
    }) as typeof globalThis.fetch

    const response = await fetch("https://example.com/api", key)
    const decrypted = new Uint8Array(await response.arrayBuffer())

    expect(decrypted).toEqual(plaintext)
  })

  it("should pass through non-encrypted responses", async () => {
    const key = await generateKey(256)
    const plaintext = "Plain response"

    globalThis.fetch = vi.fn(async () => {
      return new Response(plaintext, {
        headers: { "Content-Type": "text/plain" },
      })
    }) as typeof globalThis.fetch

    const response = await fetch("https://example.com/api", key)
    const text = await response.text()

    expect(text).toBe(plaintext)
  })

  it("should perform full round-trip encryption/decryption", async () => {
    const key = await generateKey(256)
    const originalData = new TextEncoder().encode("Round-trip test data!")

    // Simulate server that decrypts request and encrypts response
    globalThis.fetch = vi.fn(async (request: Request) => {
      // Decrypt incoming request
      if (request.body) {
        const encryptedRequest = await streamToUint8Array(request.body)
        const decryptedRequest = await Decoder.decode(key, encryptedRequest)

        // Echo it back encrypted
        const encryptedResponse = await Encoder.encode(key, decryptedRequest)
        return new Response(encryptedResponse, {
          headers: { "Content-Encoding": "aes256gcm" },
        })
      }
      return new Response("no body")
    }) as typeof globalThis.fetch

    const response = await fetch("https://example.com/echo", key, {
      method: "POST",
      body: originalData,
    })

    const receivedData = new Uint8Array(await response.arrayBuffer())
    expect(receivedData).toEqual(originalData)
  })
})

describe("Encoding.handler", () => {
  it("should decrypt incoming encrypted request", async () => {
    const key = await generateKey(256)
    const plaintext = new TextEncoder().encode("Encrypted request body")

    // Encrypt the request body
    const encrypted = await Encoder.encode(key, plaintext)

    let receivedBody: Uint8Array | null = null
    const handler = AES256GCM.handler(key, async (request) => {
      if (request.body) {
        receivedBody = await streamToUint8Array(request.body)
      }
      return new Response("ok")
    })

    const request = new Request("https://example.com/api", {
      method: "POST",
      body: encrypted,
      headers: { "Content-Encoding": "aes256gcm" },
    })

    await handler(request)

    expect(receivedBody).toEqual(plaintext)
  })

  it("should encrypt response when client accepts ECE", async () => {
    const key = await generateKey(256)
    const plaintext = new TextEncoder().encode("Response to encrypt")

    const handler = AES256GCM.handler(key, async () => {
      return new Response(plaintext)
    })

    const request = new Request("https://example.com/api", {
      headers: { "Accept-Encoding": "aes256gcm" },
    })

    const response = await handler(request)

    // Response should be encrypted
    expect(response.headers.get("Content-Encoding")).toBe("aes256gcm")
    expect(response.headers.get("Vary")).toBe("Content-Encoding")

    // Decrypt and verify
    const encryptedBody = await streamToUint8Array(response.body!)
    const decrypted = await Decoder.decode(key, encryptedBody)
    expect(decrypted).toEqual(plaintext)
  })

  it("should return 415 for mismatched encoding", async () => {
    const key = await generateKey(128) // 128-bit key

    const handler = AES128GCM.handler(key, async () => {
      return new Response("ok")
    })

    // Request claims aes256gcm but handler has 128-bit key
    const request = new Request("https://example.com/api", {
      method: "POST",
      body: new Uint8Array([1, 2, 3]),
      headers: { "Content-Encoding": "aes256gcm" },
    })

    const response = await handler(request)
    expect(response.status).toBe(415)
  })

  it("should pass through unencrypted requests", async () => {
    const key = await generateKey(256)
    const plaintext = new TextEncoder().encode("Plain request")

    let receivedBody: Uint8Array | null = null
    const handler = AES256GCM.handler(key, async (request) => {
      if (request.body) {
        receivedBody = await streamToUint8Array(request.body)
      }
      return new Response("ok")
    })

    const request = new Request("https://example.com/api", {
      method: "POST",
      body: plaintext,
      // No Content-Encoding header
    })

    await handler(request)

    expect(receivedBody).toEqual(plaintext)
  })

  it("should not encrypt response if client doesn't accept ECE", async () => {
    const key = await generateKey(256)
    const plaintext = new TextEncoder().encode("Response")

    const handler = AES256GCM.handler(key, async () => {
      return new Response(plaintext)
    })

    const request = new Request("https://example.com/api", {
      headers: { "Accept-Encoding": "gzip" }, // Not ECE
    })

    const response = await handler(request)

    expect(response.headers.get("Content-Encoding")).toBeNull()
    const body = new Uint8Array(await response.arrayBuffer())
    expect(body).toEqual(plaintext)
  })
})

describe("Encoding.middleware", () => {
  it("should work as middleware", async () => {
    const key = await generateKey(256)
    const plaintext = new TextEncoder().encode("Middleware test")

    const middleware = AES256GCM.middleware(key)

    const encrypted = await Encoder.encode(key, plaintext)
    const request = new Request("https://example.com/api", {
      method: "POST",
      body: encrypted,
      headers: {
        "Content-Encoding": "aes256gcm",
        "Accept-Encoding": "aes256gcm",
      },
    })

    let receivedBody: Uint8Array | null = null
    const response = await middleware(request, async (req) => {
      if (req.body) {
        receivedBody = await streamToUint8Array(req.body)
      }
      return new Response(receivedBody)
    })

    // Handler received decrypted body
    expect(receivedBody).toEqual(plaintext)

    // Response is encrypted
    expect(response.headers.get("Content-Encoding")).toBe("aes256gcm")
  })
})

describe("strict mode", () => {
  describe("Encoding.handler with strict", () => {
    it("should throw EncodingError for unencrypted request with body", async () => {
      const key = await generateKey(256)
      const plaintext = new TextEncoder().encode("Plain request")

      const handler = AES256GCM.handler(key, async () => new Response("ok"), {
        strict: true,
      })

      const request = new Request("https://example.com/api", {
        method: "POST",
        body: plaintext,
        // No Content-Encoding header
      })

      await expect(handler(request)).rejects.toThrow(
        "encrypted request required",
      )
    })

    it("should allow requests without body in strict mode", async () => {
      const key = await generateKey(256)

      const handler = AES256GCM.handler(key, async () => new Response("ok"), {
        strict: true,
      })

      const request = new Request("https://example.com/api", {
        method: "GET",
        // No body, no Content-Encoding
      })

      const response = await handler(request)
      expect(response.status).toBe(200)
    })

    it("should accept encrypted requests in strict mode", async () => {
      const key = await generateKey(256)
      const plaintext = new TextEncoder().encode("Secret data")
      const encrypted = await Encoder.encode(key, plaintext)

      let receivedBody: Uint8Array | null = null
      const handler = AES256GCM.handler(
        key,
        async (req) => {
          if (req.body) {
            receivedBody = await streamToUint8Array(req.body)
          }
          return new Response("ok")
        },
        { strict: true },
      )

      const request = new Request("https://example.com/api", {
        method: "POST",
        body: encrypted,
        headers: { "Content-Encoding": "aes256gcm" },
      })

      const response = await handler(request)
      expect(response.status).toBe(200)
      expect(receivedBody).toEqual(plaintext)
    })
  })

  describe("fetch with strict", () => {
    const originalFetch = globalThis.fetch

    afterEach(() => {
      globalThis.fetch = originalFetch
    })

    it("should throw EncodingError for unencrypted response in strict mode", async () => {
      const key = await generateKey(256)

      globalThis.fetch = vi.fn(async () => {
        return new Response("plain response", {
          headers: { "Content-Type": "text/plain" },
          // No Content-Encoding header
        })
      }) as typeof globalThis.fetch

      await expect(
        fetch("https://example.com/api", key, { strict: true }),
      ).rejects.toThrow("encrypted response required")
    })

    it("should accept encrypted response in strict mode", async () => {
      const key = await generateKey(256)
      const plaintext = new TextEncoder().encode("Secret response")
      const encrypted = await Encoder.encode(key, plaintext)

      globalThis.fetch = vi.fn(async () => {
        return new Response(encrypted, {
          headers: { "Content-Encoding": "aes256gcm" },
        })
      }) as typeof globalThis.fetch

      const response = await fetch("https://example.com/api", key, {
        strict: true,
      })
      const decrypted = new Uint8Array(await response.arrayBuffer())

      expect(decrypted).toEqual(plaintext)
    })

    it("should allow unencrypted response without strict mode", async () => {
      const key = await generateKey(256)
      const plaintext = "Plain response"

      globalThis.fetch = vi.fn(async () => {
        return new Response(plaintext, {
          headers: { "Content-Type": "text/plain" },
        })
      }) as typeof globalThis.fetch

      const response = await fetch("https://example.com/api", key)
      const text = await response.text()

      expect(text).toBe(plaintext)
    })
  })
})
