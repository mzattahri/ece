import { describe, it, expect } from "vitest"
import { Encoder, Decoder } from "./index"
import vectors from "./interop-vectors.json"

// Helper to decode base64
function base64ToUint8Array(base64: string): Uint8Array {
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

// Helper to import a raw key
async function importKey(keyBytes: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM", length: keyBytes.length * 8 },
    true,
    ["encrypt", "decrypt"],
  )
}

describe("Cross-language interoperability", () => {
  describe("Decrypt Go-generated ciphers", () => {
    for (const vector of vectors) {
      it(`should decrypt: ${vector.name}`, async () => {
        const key = await importKey(base64ToUint8Array(vector.key))
        const cipher = base64ToUint8Array(vector.cipher)

        const plain = await Decoder.decode(key, cipher)
        const plainText = new TextDecoder().decode(plain)

        expect(plainText).toBe(vector.plain)
      })
    }
  })

  describe("Encrypt and verify Go can decrypt", () => {
    for (const vector of vectors) {
      it(`should produce compatible cipher: ${vector.name}`, async () => {
        const key = await importKey(base64ToUint8Array(vector.key))
        const salt = base64ToUint8Array(vector.salt)
        const plain = new TextEncoder().encode(vector.plain)

        // Encrypt with same parameters as Go
        const cipher = await Encoder.encode(
          key,
          plain,
          salt,
          vector.recordSize,
          vector.keyID,
        )

        // Decrypt to verify round-trip
        const decrypted = await Decoder.decode(key, cipher)
        expect(decrypted).toEqual(plain)

        // With same salt, should produce identical cipher
        const expectedCipher = base64ToUint8Array(vector.cipher)
        expect(cipher).toEqual(expectedCipher)
      })
    }
  })
})
