import { describe, it, expect, beforeAll } from "vitest"
import ece, {
  AES128GCM,
  AES256GCM,
  Encoder,
  Decoder,
  Header,
  EncodingError,
  randomSalt,
  detectKeyEncoding,
  assertAesGcmKey,
} from "./index"

// Helper to generate AES-GCM keys
async function generateKey(bits: 128 | 256): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: bits }, true, [
    "encrypt",
    "decrypt",
  ])
}

// Helper to generate key with specific usages
async function generateKeyWithUsages(
  bits: 128 | 256,
  usages: KeyUsage[],
): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: "AES-GCM", length: bits },
    true,
    usages,
  )
}

describe("Encoding constants", () => {
  it("AES128GCM has correct properties", () => {
    expect(AES128GCM.name).toBe("aes128gcm")
    expect(AES128GCM.bits).toBe(128)
    expect(AES128GCM.info).toBeInstanceOf(Uint8Array)
  })

  it("AES256GCM has correct properties", () => {
    expect(AES256GCM.name).toBe("aes256gcm")
    expect(AES256GCM.bits).toBe(256)
    expect(AES256GCM.info).toBeInstanceOf(Uint8Array)
  })
})

describe("EncodingError", () => {
  it("should be an instance of Error", () => {
    const err = new EncodingError("test error")
    expect(err).toBeInstanceOf(Error)
    expect(err).toBeInstanceOf(EncodingError)
    expect(err.message).toBe("test error")
  })
})

describe("randomSalt", () => {
  it("should return 16 bytes", () => {
    const salt = randomSalt()
    expect(salt).toBeInstanceOf(Uint8Array)
    expect(salt.length).toBe(16)
  })

  it("should return unique values", () => {
    const salt1 = randomSalt()
    const salt2 = randomSalt()
    expect(salt1).not.toEqual(salt2)
  })
})

describe("detectKeyEncoding", () => {
  it("should detect AES-128-GCM encoding", async () => {
    const key = await generateKey(128)
    const encoding = detectKeyEncoding(key)
    expect(encoding).toBe(AES128GCM)
  })

  it("should detect AES-256-GCM encoding", async () => {
    const key = await generateKey(256)
    const encoding = detectKeyEncoding(key)
    expect(encoding).toBe(AES256GCM)
  })

  it("should return undefined for non-AES-GCM keys", async () => {
    const key = await crypto.subtle.generateKey(
      { name: "AES-CBC", length: 128 },
      true,
      ["encrypt", "decrypt"],
    )
    const encoding = detectKeyEncoding(key)
    expect(encoding).toBeUndefined()
  })
})

describe("assertAesGcmKey", () => {
  it("should not throw for valid AES-GCM key", async () => {
    const key = await generateKey(128)
    expect(() => assertAesGcmKey(key)).not.toThrow()
  })

  it("should throw for non-AES-GCM key", async () => {
    const key = await crypto.subtle.generateKey(
      { name: "AES-CBC", length: 128 },
      true,
      ["encrypt", "decrypt"],
    )
    expect(() => assertAesGcmKey(key)).toThrow(EncodingError)
    expect(() => assertAesGcmKey(key)).toThrow("expected an AES-GCM secret key")
  })

  it("should throw for key missing required usage", async () => {
    const key = await generateKeyWithUsages(128, ["encrypt"])
    expect(() => assertAesGcmKey(key, "decrypt")).toThrow(EncodingError)
    expect(() => assertAesGcmKey(key, "decrypt")).toThrow(
      "missing required usage",
    )
  })

  it("should not throw when key has required usage", async () => {
    const key = await generateKeyWithUsages(128, ["encrypt"])
    expect(() => assertAesGcmKey(key, "encrypt")).not.toThrow()
  })
})

describe("Header", () => {
  it("should create header with default values", () => {
    const header = Header.create()
    expect(header.salt.length).toBe(16)
    expect(header.recordSize).toBe(4096)
    expect(header.idLength).toBe(0)
    expect(header.keyID).toBe("")
  })

  it("should create header with custom salt", () => {
    const salt = new Uint8Array(16).fill(0xaa)
    const header = Header.create(salt)
    expect(header.salt).toEqual(salt)
  })

  it("should create header with custom record size", () => {
    const header = Header.create(undefined, 8192)
    expect(header.recordSize).toBe(8192)
  })

  it("should create header with keyID", () => {
    const header = Header.create(undefined, 4096, "my-key-id")
    expect(header.keyID).toBe("my-key-id")
    expect(header.idLength).toBe(9)
  })

  it("should return buffer", () => {
    const header = Header.create()
    expect(header.buffer).toBeInstanceOf(ArrayBuffer)
    expect(header.buffer.byteLength).toBe(16 + 4 + 1) // salt + rs + idLen
  })

  it("should parse header from buffer", () => {
    const original = Header.create(undefined, 2048, "test")
    const parsed = new Header(original.buffer)
    expect(parsed.recordSize).toBe(2048)
    expect(parsed.keyID).toBe("test")
  })
})

describe("Encoder", () => {
  describe("create", () => {
    it("should create encoder with valid key", async () => {
      const key = await generateKey(128)
      const encoder = await Encoder.create(key)
      expect(encoder).toBeInstanceOf(Encoder)
    })

    it("should throw for key without encrypt usage", async () => {
      const key = await generateKeyWithUsages(128, ["decrypt"])
      await expect(Encoder.create(key)).rejects.toThrow(EncodingError)
    })

    it("should throw for keyID over 255 bytes", async () => {
      const key = await generateKey(128)
      const longKeyID = "a".repeat(256)
      await expect(
        Encoder.create(key, undefined, 4096, longKeyID),
      ).rejects.toThrow("keyID length cannot be over 255 bytes long")
    })

    it("should throw for record size too small", async () => {
      const key = await generateKey(128)
      await expect(Encoder.create(key, undefined, 17)).rejects.toThrow(
        "record size must be at least 18 bytes",
      )
    })

    it("should accept minimum record size of 18", async () => {
      const key = await generateKey(128)
      const encoder = await Encoder.create(key, undefined, 18)
      expect(encoder).toBeInstanceOf(Encoder)
    })
  })

  describe("encode (one-shot)", () => {
    it("should encode empty data", async () => {
      const key = await generateKey(128)
      const cipher = await Encoder.encode(key, new Uint8Array(0))
      expect(cipher).toBeInstanceOf(Uint8Array)
      expect(cipher.length).toBeGreaterThan(0)
    })

    it("should encode small data", async () => {
      const key = await generateKey(128)
      const plain = new TextEncoder().encode("Hello, World!")
      const cipher = await Encoder.encode(key, plain)
      expect(cipher).toBeInstanceOf(Uint8Array)
      expect(cipher.length).toBeGreaterThan(plain.length) // Header + tag + delimiter
    })

    it("should encode data larger than record size", async () => {
      const key = await generateKey(128)
      const plain = new Uint8Array(10000).fill(0x42)
      const cipher = await Encoder.encode(key, plain, undefined, 100)
      expect(cipher).toBeInstanceOf(Uint8Array)
    })
  })

  describe("transformStream", () => {
    it("should return a TransformStream", async () => {
      const key = await generateKey(128)
      const stream = await Encoder.transformStream(key)
      expect(stream).toBeInstanceOf(TransformStream)
    })

    it("should encrypt data through stream", async () => {
      const key = await generateKey(256)
      const plain = new TextEncoder().encode("Stream test data")
      const encryptStream = await Encoder.transformStream(key)

      const chunks: Uint8Array[] = []
      const readable = new ReadableStream({
        start: function (controller) {
          controller.enqueue(plain)
          controller.close()
        },
      })

      const writableStream = new WritableStream({
        write: function (chunk) {
          chunks.push(chunk)
        },
      })

      await readable.pipeThrough(encryptStream).pipeTo(writableStream)
      expect(chunks.length).toBeGreaterThan(0)
    })
  })
})

describe("Decoder", () => {
  describe("constructor", () => {
    it("should create decoder with valid key", async () => {
      const key = await generateKey(128)
      const decoder = new Decoder(key)
      expect(decoder).toBeInstanceOf(Decoder)
    })

    it("should throw for non-AES-GCM key", async () => {
      const key = await crypto.subtle.generateKey(
        { name: "AES-CBC", length: 128 },
        true,
        ["encrypt", "decrypt"],
      )
      expect(() => new Decoder(key)).toThrow(EncodingError)
    })
  })

  describe("decode (one-shot)", () => {
    it("should decode previously encoded data", async () => {
      const key = await generateKey(128)
      const original = new TextEncoder().encode("Test message for encoding")
      const cipher = await Encoder.encode(key, original)
      const decoded = await Decoder.decode(key, cipher)
      expect(decoded).toEqual(original)
    })

    it("should decode empty data", async () => {
      const key = await generateKey(256)
      const original = new Uint8Array(0)
      const cipher = await Encoder.encode(key, original)
      const decoded = await Decoder.decode(key, cipher)
      expect(decoded).toEqual(original)
    })

    it("should decode multi-record data", async () => {
      const key = await generateKey(128)
      const original = new Uint8Array(5000).fill(0xaa)
      const cipher = await Encoder.encode(key, original, undefined, 100)
      const decoded = await Decoder.decode(key, cipher)
      expect(decoded).toEqual(original)
    })

    it("should fail with wrong key", async () => {
      const key1 = await generateKey(128)
      const key2 = await generateKey(128)
      const cipher = await Encoder.encode(
        key1,
        new TextEncoder().encode("secret"),
      )
      await expect(Decoder.decode(key2, cipher)).rejects.toThrow(EncodingError)
    })

    it("should fail with corrupted cipher", async () => {
      const key = await generateKey(128)
      const cipher = await Encoder.encode(key, new TextEncoder().encode("test"))
      // Corrupt the cipher
      cipher[cipher.length - 5] ^= 0xff
      await expect(Decoder.decode(key, cipher)).rejects.toThrow(EncodingError)
    })
  })

  describe("transformStream", () => {
    it("should return a TransformStream", async () => {
      const key = await generateKey(128)
      const stream = Decoder.transformStream(key)
      expect(stream).toBeInstanceOf(TransformStream)
    })

    it("should decrypt data through stream", async () => {
      const key = await generateKey(128)
      const original = new TextEncoder().encode("Streaming decryption test")
      const cipher = await Encoder.encode(key, original)

      const decryptStream = Decoder.transformStream(key)
      const chunks: Uint8Array[] = []

      const readable = new ReadableStream({
        start: function (controller) {
          controller.enqueue(cipher)
          controller.close()
        },
      })

      const writableStream = new WritableStream({
        write: function (chunk) {
          chunks.push(chunk)
        },
      })

      await readable.pipeThrough(decryptStream).pipeTo(writableStream)

      const result = new Uint8Array(
        chunks.reduce((acc, chunk) => acc + chunk.length, 0),
      )
      let offset = 0
      for (const chunk of chunks) {
        result.set(chunk, offset)
        offset += chunk.length
      }
      expect(result).toEqual(original)
    })
  })

  describe("header property", () => {
    it("should be undefined before decoding", async () => {
      const key = await generateKey(128)
      const decoder = new Decoder(key)
      expect(decoder.header).toBeUndefined()
    })
  })
})

describe("Round-trip tests", () => {
  const testCases = [
    { name: "empty data", data: new Uint8Array(0) },
    { name: "single byte", data: new Uint8Array([0x42]) },
    { name: "short text", data: new TextEncoder().encode("Hello") },
    {
      name: "medium text",
      data: new TextEncoder().encode(
        "The quick brown fox jumps over the lazy dog",
      ),
    },
    { name: "binary data", data: new Uint8Array(256).map((_, i) => i) },
    { name: "large data", data: new Uint8Array(100000).fill(0xab) },
  ]

  describe("AES-128-GCM", () => {
    let key: CryptoKey

    beforeAll(async () => {
      key = await generateKey(128)
    })

    for (const { name, data } of testCases) {
      it(`should round-trip ${name}`, async () => {
        const cipher = await Encoder.encode(key, data)
        const decoded = await Decoder.decode(key, cipher)
        expect(decoded).toEqual(data)
      })
    }
  })

  describe("AES-256-GCM", () => {
    let key: CryptoKey

    beforeAll(async () => {
      key = await generateKey(256)
    })

    for (const { name, data } of testCases) {
      it(`should round-trip ${name}`, async () => {
        const cipher = await Encoder.encode(key, data)
        const decoded = await Decoder.decode(key, cipher)
        expect(decoded).toEqual(data)
      })
    }
  })

  describe("with custom record sizes", () => {
    const recordSizes = [18, 32, 64, 100, 256, 1024, 4096]

    for (const rs of recordSizes) {
      it(`should round-trip with record size ${rs}`, async () => {
        const key = await generateKey(128)
        const data = new Uint8Array(500).fill(0xcc)
        const cipher = await Encoder.encode(key, data, undefined, rs)
        const decoded = await Decoder.decode(key, cipher)
        expect(decoded).toEqual(data)
      })
    }
  })

  describe("with keyID", () => {
    it("should preserve keyID in header", async () => {
      const key = await generateKey(128)
      const data = new TextEncoder().encode("test data")
      const keyID = "my-encryption-key-v1"

      const cipher = await Encoder.encode(key, data, undefined, 4096, keyID)

      // Parse the header to verify keyID
      const header = new Header(cipher.buffer.slice(0, 21 + keyID.length))
      expect(header.keyID).toBe(keyID)

      // Verify decryption still works
      const decoded = await Decoder.decode(key, cipher)
      expect(decoded).toEqual(data)
    })
  })
})

describe("Edge cases", () => {
  it("should handle data exactly filling one record", async () => {
    const key = await generateKey(128)
    // rs=100, tag=16, delimiter=1 => max plain per record = 83
    const data = new Uint8Array(83).fill(0x11)
    const cipher = await Encoder.encode(key, data, undefined, 100)
    const decoded = await Decoder.decode(key, cipher)
    expect(decoded).toEqual(data)
  })

  it("should handle data requiring exactly two records", async () => {
    const key = await generateKey(128)
    // Two records worth of data
    const data = new Uint8Array(84).fill(0x22)
    const cipher = await Encoder.encode(key, data, undefined, 100)
    const decoded = await Decoder.decode(key, cipher)
    expect(decoded).toEqual(data)
  })

  it("should handle different salts producing different ciphers", async () => {
    const key = await generateKey(128)
    const data = new TextEncoder().encode("same data")
    const salt1 = randomSalt()
    const salt2 = randomSalt()

    const cipher1 = await Encoder.encode(key, data, salt1)
    const cipher2 = await Encoder.encode(key, data, salt2)

    expect(cipher1).not.toEqual(cipher2)

    // Both should decrypt correctly
    const decoded1 = await Decoder.decode(key, cipher1)
    const decoded2 = await Decoder.decode(key, cipher2)
    expect(decoded1).toEqual(data)
    expect(decoded2).toEqual(data)
  })

  it("should handle maximum keyID length (255 bytes)", async () => {
    const key = await generateKey(128)
    const data = new TextEncoder().encode("test")
    const keyID = "k".repeat(255)

    const cipher = await Encoder.encode(key, data, undefined, 4096, keyID)
    const decoded = await Decoder.decode(key, cipher)
    expect(decoded).toEqual(data)
  })
})

describe("Default export", () => {
  it("should export all public APIs", () => {
    expect(ece.AES128GCM).toBe(AES128GCM)
    expect(ece.AES256GCM).toBe(AES256GCM)
    expect(ece.Encoder).toBe(Encoder)
    expect(ece.Decoder).toBe(Decoder)
    expect(ece.Header).toBe(Header)
    expect(ece.EncodingError).toBe(EncodingError)
    expect(ece.randomSalt).toBe(randomSalt)
    expect(ece.detectKeyEncoding).toBe(detectKeyEncoding)
  })
})
