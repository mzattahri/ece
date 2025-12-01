/**
 * HTTP integration for ECE (Encrypted-Content-Encoding).
 *
 * Provides fetch wrapper for transparent encryption/decryption
 * of HTTP request and response bodies.
 */

import {
  Decoder,
  Encoder,
  Encoding,
  EncodingError,
  assertAesGcmKey,
  detectKeyEncoding,
  getContentEncoding,
  randomSalt,
} from "./index"

/**
 * Options for the fetch wrapper.
 */
export interface FetchOptions extends RequestInit {
  /** Record size for encryption (default: 4096) */
  recordSize?: number
  /** Key identifier to include in the ECE header */
  keyID?: string
  /** When true, throws EncodingError if the response is not ECE-encoded */
  strict?: boolean
}

/**
 * Encrypts a request body using ECE.
 * @internal
 */
async function encryptRequest(
  request: Request,
  key: CryptoKey,
  encoding: Encoding,
  options?: { recordSize?: number; keyID?: string },
): Promise<Request> {
  if (!request.body) return request

  const encryptStream = await Encoder.transformStream(
    key,
    randomSalt(),
    options?.recordSize ?? 4096,
    options?.keyID ?? "",
  )

  const encryptedBody = request.body.pipeThrough(encryptStream)

  const headers = new Headers(request.headers)
  headers.set("Content-Encoding", encoding.name)

  return new Request(request.url, {
    method: request.method,
    headers: headers,
    body: encryptedBody,
    // @ts-expect-error duplex is valid but not in all TS definitions
    duplex: "half",
  })
}

/**
 * Decrypts a response body using ECE.
 * @internal
 */
function decryptResponse(
  response: Response,
  key: CryptoKey,
  strict?: boolean,
): Response {
  const encoding = getContentEncoding(response.headers)
  if (!encoding) {
    if (strict) {
      throw new EncodingError("encrypted response required")
    }
    return response // Not encrypted, return as-is
  }

  const keyEncoding = detectKeyEncoding(key)
  if (encoding.bits !== keyEncoding?.bits) {
    throw new EncodingError("Key size does not match Content-Encoding")
  }

  if (!response.body) return response

  const decryptStream = Decoder.transformStream(key)
  const decryptedBody = response.body.pipeThrough(decryptStream)

  return new Response(decryptedBody, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  })
}

/**
 * Performs an HTTP fetch with automatic ECE encryption/decryption.
 *
 * - Request bodies are encrypted before sending
 * - Accept-Encoding header is set to request encrypted responses
 * - Response bodies are automatically decrypted if Content-Encoding indicates ECE
 *
 * @param input URL or Request object
 * @param key AES-GCM CryptoKey for encryption/decryption
 * @param init Optional fetch options including recordSize and keyID
 * @returns Promise resolving to the (decrypted) Response
 *
 * @example
 * ```typescript
 * import { fetch } from '@mzattahri/ece'
 *
 * const key = await crypto.subtle.generateKey(
 *   { name: 'AES-GCM', length: 256 },
 *   true,
 *   ['encrypt', 'decrypt']
 * )
 *
 * const response = await fetch('https://api.example.com/data', key, {
 *   method: 'POST',
 *   body: JSON.stringify({ message: 'Hello' }),
 * })
 *
 * const data = await response.json()
 * ```
 */
export async function fetch(
  input: RequestInfo | URL,
  key: CryptoKey,
  init?: FetchOptions,
): Promise<Response> {
  assertAesGcmKey(key)
  const encoding = detectKeyEncoding(key)
  if (!encoding) throw new EncodingError("Invalid key for ECE")

  const { recordSize, keyID, strict, ...fetchInit } = init ?? {}

  // Build request with Accept-Encoding header
  const headers = new Headers(fetchInit.headers)
  headers.set("Accept-Encoding", encoding.name)

  let request = new Request(input, { ...fetchInit, headers: headers })

  // Encrypt request body if present
  if (request.body) {
    request = await encryptRequest(request, key, encoding, {
      recordSize: recordSize,
      keyID: keyID,
    })
  }

  // Perform fetch using global fetch
  const response = await globalThis.fetch(request)

  // Decrypt response if encrypted (strict mode throws if not encrypted)
  return decryptResponse(response, key, strict)
}
