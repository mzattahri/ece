/**
 * Module ece is an implementation of Encrypted-Content-Encoding
 * as defined in RFC 8188.
 *
 * It exposes tools and methods to encrypt and decrypt data
 * using AES-128/256-GCM with buffers or streams.
 */

const saltLength = 16 // bytes
const nonceLength = 12 // bytes
const aesTagLength = 16 // bytes
// RFC 8188: minimum record size is tag (16) + delimiter (1) + at least 1 byte of content
const minRecordSize = aesTagLength + 1 + 1

// RFC 8188-defined constants
const recordDelimiter = 0x01
const recordDelimiterFinal = 0x02
const recordPadding = 0x00
const cekInfo128 = appendToUint8Array(
  new TextEncoder().encode("Content-Encoding: aes128gcm"),
  0x00,
  0x01,
)
const cekInfo256 = appendToUint8Array(
  new TextEncoder().encode("Content-Encoding: aes256gcm"),
  0x00,
  0x01,
)
const nonceInfo = appendToUint8Array(
  new TextEncoder().encode("Content-Encoding: nonce"),
  0x00,
  0x01,
)

/**
 * Base class for all error related
 * to encryption.
 */
export class EncodingError extends Error {
  constructor(message: string) {
    super(message)
  }
}

/**
 * Middleware function type for HTTP request handling.
 */
export type Middleware = (
  request: Request,
  next: (request: Request) => Promise<Response>,
) => Promise<Response>

/**
 * Options for handler and middleware.
 */
export interface HandlerOptions {
  /** Record size for encryption (default: 4096) */
  recordSize?: number
  /** Key identifier to include in the ECE header */
  keyID?: string
  /** When true, rejects requests/responses that are not ECE-encoded */
  strict?: boolean
}

/**
 * Returns the ECE encoding from the Content-Encoding header.
 *
 * @param headers HTTP headers
 * @returns Encoding if Content-Encoding indicates ECE, null otherwise
 */
export function getContentEncoding(headers: Headers): Encoding | null {
  const value = headers.get("Content-Encoding")
  if (!value) return null
  if (value.includes("aes128gcm")) return AES128GCM
  if (value.includes("aes256gcm")) return AES256GCM
  return null
}

/**
 * Returns the ECE encoding from the Accept-Encoding header.
 *
 * Checks X-Accept-Encoding first (for cases where Accept-Encoding
 * is modified by proxies), then falls back to Accept-Encoding.
 *
 * @param headers HTTP headers
 * @returns Encoding if Accept-Encoding indicates ECE, null otherwise
 */
export function getAcceptedEncoding(headers: Headers): Encoding | null {
  // Check X-Accept-Encoding first (like Go implementation)
  const xAccept = headers.get("X-Accept-Encoding")
  const accept = xAccept || headers.get("Accept-Encoding")
  if (!accept) return null
  if (accept.includes("aes128gcm")) return AES128GCM
  if (accept.includes("aes256gcm")) return AES256GCM
  return null
}

/**
 * Returns true if the headers indicate ECE-encoded content.
 *
 * @param headers HTTP headers
 * @returns true if Content-Encoding is aes128gcm or aes256gcm
 */
export function isEncrypted(headers: Headers): boolean {
  return getContentEncoding(headers) !== null
}

/**
 * Encoding holds information on an encoding scheme
 * and provides methods for HTTP handler/middleware creation.
 */
export class Encoding {
  constructor(
    public readonly name: string,
    public readonly bits: number,
    public readonly info: Uint8Array,
  ) {}

  /**
   * Wraps a handler function with ECE encryption/decryption.
   *
   * Incoming requests with Content-Encoding: aes128gcm/aes256gcm are decrypted.
   * Outgoing responses are encrypted if the client sends Accept-Encoding header.
   *
   * @param key AES-GCM CryptoKey for encryption/decryption
   * @param fn Handler function to wrap
   * @param options Optional record size and key ID
   * @returns Wrapped handler function
   */
  handler(
    key: CryptoKey,
    fn: (request: Request) => Promise<Response>,
    options?: HandlerOptions,
  ): (request: Request) => Promise<Response> {
    assertAesGcmKey(key)
    const keyEncoding = detectKeyEncoding(key)
    if (keyEncoding?.bits !== this.bits) {
      throw new EncodingError(`Key size does not match ${this.name}`)
    }

    return async (request: Request): Promise<Response> => {
      // Decrypt incoming request if encrypted
      const contentEncoding = getContentEncoding(request.headers)
      let processedRequest = request

      if (contentEncoding) {
        if (contentEncoding.bits !== this.bits) {
          return new Response("Unsupported Media Type", { status: 415 })
        }

        if (request.body) {
          const decryptStream = Decoder.transformStream(key)
          const decryptedBody = request.body.pipeThrough(decryptStream)
          processedRequest = new Request(request.url, {
            method: request.method,
            headers: request.headers,
            body: decryptedBody,
            // @ts-expect-error duplex is valid but not in all TS definitions
            duplex: "half",
          })
        }
      } else if (options?.strict && request.body) {
        // Strict mode: reject unencrypted requests with body
        throw new EncodingError("encrypted request required")
      }

      // Call the actual handler
      const response = await fn(processedRequest)

      // Encrypt response if client accepts ECE
      const acceptedEncoding = getAcceptedEncoding(request.headers)
      if (
        acceptedEncoding &&
        acceptedEncoding.bits === this.bits &&
        response.body
      ) {
        const encryptStream = await Encoder.transformStream(
          key,
          randomSalt(),
          options?.recordSize ?? 4096,
          options?.keyID ?? "",
        )

        const encryptedBody = response.body.pipeThrough(encryptStream)

        const headers = new Headers(response.headers)
        headers.set("Content-Encoding", this.name)
        headers.set("Vary", "Content-Encoding")

        return new Response(encryptedBody, {
          status: response.status,
          statusText: response.statusText,
          headers: headers,
        })
      }

      return response
    }
  }

  /**
   * Creates ECE middleware for use with middleware-based frameworks.
   *
   * @param key AES-GCM CryptoKey for encryption/decryption
   * @param options Optional record size and key ID
   * @returns Middleware function
   */
  middleware(key: CryptoKey, options?: HandlerOptions): Middleware {
    return (request, next) => {
      const wrappedHandler = this.handler(key, next, options)
      return wrappedHandler(request)
    }
  }

  /**
   * Generates a new AES-GCM key suitable for this encoding.
   *
   * @param extractable Whether the key can be exported (default: true)
   * @returns Promise resolving to a CryptoKey
   *
   * @example
   * ```typescript
   * const key = await AES256GCM.generateKey()
   * ```
   */
  generateKey(extractable = true): Promise<CryptoKey> {
    return crypto.subtle.generateKey(
      { name: "AES-GCM", length: this.bits },
      extractable,
      ["encrypt", "decrypt"],
    )
  }
}

/**
 * Supported encoding schemes.
 */
export const AES128GCM: Encoding = new Encoding("aes128gcm", 128, cekInfo128)
export const AES256GCM: Encoding = new Encoding("aes256gcm", 256, cekInfo256)

function isAesGcmKey(
  key: CryptoKey,
): key is CryptoKey & { algorithm: AesKeyAlgorithm } {
  const algo = key.algorithm as Algorithm
  return (
    key.type === "secret" &&
    typeof algo?.name === "string" &&
    algo.name === "AES-GCM" &&
    typeof (key.algorithm as AesKeyAlgorithm).length === "number"
  )
}

function hasUsage(key: CryptoKey, need: "encrypt" | "decrypt"): boolean {
  return key.usages.includes(need)
}

export function assertAesGcmKey(
  key: CryptoKey,
  need?: "encrypt" | "decrypt",
): asserts key is CryptoKey & { algorithm: AesKeyAlgorithm } {
  if (!isAesGcmKey(key)) {
    throw new EncodingError("expected an AES-GCM secret key")
  }
  if (need && !hasUsage(key, need)) {
    throw new EncodingError(`AES-GCM key missing required usage: ${need}`)
  }
}

/**
 * Returns the encoding for the given key.
 * @param key
 * @returns
 */
export function detectKeyEncoding(key: CryptoKey): Encoding | undefined {
  if (!isAesGcmKey(key)) return undefined
  switch ((key.algorithm as AesKeyAlgorithm).length) {
    case 128:
      return AES128GCM
    case 256:
      return AES256GCM
    default:
      return undefined
  }
}

/**
 * Returns the encoding associated with the
 * header value v.
 * @param v Header value
 * @returns
 */
export function detectHeaderEncoding(v: string): Encoding | null {
  if (v.indexOf(AES128GCM.name) !== -1) {
    return AES128GCM
  }
  if (v.indexOf(AES256GCM.name) !== -1) {
    return AES256GCM
  }

  return null
}

/**
 * randomSalt returns a randomly generated salt.
 * @returns Buffer
 */
export function randomSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(saltLength))
}

/**
 * Derives a pseudo-random key
 * from the given key and salt.
 *
 * Formula:
 *  HMAC-SHA-256 (salt, IKM)
 *
 * @param key Master key
 * @param salt Random salt
 * @returns PRK
 */
async function derivePRK(
  key: CryptoKey,
  salt: Uint8Array,
): Promise<Uint8Array> {
  const name = "HMAC"
  const hash = "SHA-256"
  const length = salt.length * 8 // bits

  // Create a fresh copy to ensure buffer boundaries match the actual data
  const saltCopy = new Uint8Array(salt)
  const secret = await crypto.subtle.importKey(
    "raw",
    saltCopy,
    { name: name, hash: hash, length: length },
    false,
    ["sign"],
  )
  const data = await crypto.subtle.exportKey("raw", key)
  const prk = await crypto.subtle.sign("HMAC", secret, data)
  return new Uint8Array(prk)
}

/**
 * Derives a content-encoding key
 * from the given PRK.
 *
 * Formula:
 *  CEK = HMAC-SHA-256(PRK, cek_info)[0..keyLen]
 *
 * Note: cek_info already includes the trailing 0x00 0x01 bytes per RFC 8188.
 *
 * @param prk PRK generated using derivePRK.
 * @param usage encrypt or decrypt
 * @returns CEK
 */
async function deriveCEK(
  prk: Uint8Array,
  enc: Encoding,
  usage: "encrypt" | "decrypt",
): Promise<CryptoKey> {
  // Ensure we're using fresh copies to avoid buffer boundary issues
  const prkCopy = new Uint8Array(prk)
  const infoCopy = new Uint8Array(enc.info)

  const macKey = await crypto.subtle.importKey(
    "raw",
    prkCopy,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  )
  const hashed = await crypto.subtle.sign("HMAC", macKey, infoCopy)
  const raw = new Uint8Array(hashed).slice(0, enc.bits / 8)
  return crypto.subtle.importKey(
    "raw",
    raw,
    { name: "AES-GCM", length: enc.bits },
    false,
    [usage],
  )
}

/**
 * Derives a nonce from the given prk
 * for the given record sequence in a stream.
 *
 * Formula:
 *  NONCE = HMAC-SHA-256(PRK, nonce_info || 0x01) XOR SEQ
 *
 * @param prk PRK generated with derivePRK
 * @param sequence Sequence for which the nonce needs to be computed.
 * @param length Length of the desired nonce (defaults to nonceLength).
 * @returns
 */
async function deriveNonce(
  prk: Uint8Array,
  sequence: bigint,
  length = nonceLength,
): Promise<Uint8Array> {
  const name = "HMAC"
  const hash = "SHA-256"
  const secret = await crypto.subtle.importKey(
    "raw",
    prk.buffer as ArrayBuffer,
    { name: name, hash: hash },
    false,
    ["sign"],
  )

  const hashed = await crypto.subtle.sign(
    "HMAC",
    secret,
    nonceInfo.buffer as ArrayBuffer,
  )
  const hashedSlice = hashed.slice(0, length)

  const nonce = xorBytes(
    new Uint8Array(hashedSlice),
    toByteArray(sequence, length * 8),
  )
  if (nonce.length != length) {
    return Promise.reject(new Error("XOR did not return the right length"))
  }
  return Promise.resolve(nonce)
}

/**
 * Header represents the header of an ECE
 * encoded message.
 *
 * Structure:
 * 	+-----------+--------+-----------+---------------+
 * 	| salt (16) | rs (4) | idLen (1) | keyID (idLen) |
 * 	+-----------+--------+-----------+---------------+
 */
export class Header {
  private data: Uint8Array

  /**
   * Creates a new Header instances from a
   * byte array.
   * @param data Header bytes
   */
  constructor(data: ArrayBuffer | Uint8Array) {
    this.data = data instanceof Uint8Array ? data : new Uint8Array(data)
  }

  /**
   * Returns the random salt used for
   * a message.
   */
  get salt(): Uint8Array {
    return this.data.subarray(0, saltLength)
  }

  /**
   * Returns the size of a record in
   * a ECE message.
   */
  get recordSize(): number {
    const v = new DataView(
      this.data.buffer as ArrayBuffer,
      this.data.byteOffset + 0,
      saltLength + 4,
    )
    return v.getUint32(saltLength, false)
  }

  /**
   * Returns the length of the
   * keyID field of the header.
   */
  get idLength(): number {
    return Number(this.data.at(saltLength + 4))
  }

  /**
   * Returns the ID of the encryption key
   * used for a message.
   */
  get keyID(): string {
    const offset = saltLength + 4 + 1
    const slice = this.data.subarray(offset, offset + this.idLength)
    return new TextDecoder().decode(slice)
  }

  /**
   * Returns a copy of the underlying buffer.
   */
  get buffer(): ArrayBuffer {
    return this.data.slice().buffer as ArrayBuffer
  }

  /**
   * Returns a new Header populated with the given fields.
   * @param salt Salt bytes (defaults to randomSalt())
   * @param recordSize Size of a single record (defaults to 4096)
   * @param keyID Key identifier
   * @returns
   */
  static create(
    salt: Uint8Array = randomSalt(),
    recordSize = 4096,
    keyID = "",
  ): Header {
    const dv = new DataView(new ArrayBuffer(5))
    dv.setUint32(0, recordSize)
    dv.setUint8(4, keyID.length)

    const data = concatUint8Array(
      new Uint8Array(salt),
      new Uint8Array(dv.buffer),
      new TextEncoder().encode(keyID),
    )

    return new Header(data)
  }
}

/**
 * Represents an encoder capable of encrypting
 * plain data into a cipher.
 */
export class Encoder {
  private prk: Uint8Array // Pseudo-random key
  private cek: CryptoKey // Content-Encoding Key
  private head: Header // Header
  private sequence = 0n // Current sequence (96 bits)
  private buf: Uint8Array // Buffer of data awaiting to be encrypted and flushed
  private maxPlainSize: number // Max-size of a block before encryption
  private eos = false // Value indicating end of stream.

  /**
   * Instantiates a new Encoder with the given parameters.
   * @param header Encoding header instance
   * @param prk Pseudo-random key generated with derivePRK
   * @param cek Content-encryption key generated with deriveCEK
   */
  constructor(header: Header, prk: Uint8Array, cek: CryptoKey) {
    this.prk = prk
    this.cek = cek
    this.head = header
    this.buf = new Uint8Array(0)

    this.maxPlainSize = header.recordSize - aesTagLength - 1
  }

  /**
   * Encrypts record and returns the cipher
   * @param record Plain data to form a record
   * @returns
   */
  private async encrypt(record: Uint8Array): Promise<Uint8Array> {
    const nonce = await deriveNonce(this.prk, this.sequence, nonceLength)
    const cipher = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: new Uint8Array(nonce),
        tagLength: aesTagLength * 8,
      },
      this.cek,
      new Uint8Array(record),
    )
    return new Uint8Array(cipher)
  }

  /**
   * Processes data to form and push a record
   * to the controller.
   *
   * If closing is set to true, the final delimiter (0x02)
   * to close the message, and padding bytes (0x00) are omitted.
   *
   * @param controller
   * @param closing Value indicating if this is the final write.
   */
  private async doFlush(
    controller: TransformStreamDefaultController<Uint8Array>,
    closing = false,
  ): Promise<void> {
    if (this.eos) {
      throw new Error("closed stream")
    }
    if (!closing && !this.buf.length) {
      return
    }

    const delimiter = closing ? recordDelimiterFinal : recordDelimiter
    const padding = closing ? 0 : this.maxPlainSize - 1 - this.buf.length

    const plain = new Uint8Array(this.buf.length + 1 + Math.max(0, padding))
    plain.set(this.buf, 0)
    plain.set([delimiter], this.buf.length)

    // Write the header once.
    if (this.sequence === 0n) {
      controller.enqueue(new Uint8Array(this.head.buffer))
    }

    const cipher = await this.encrypt(plain)
    if (!closing && cipher.length !== this.head.recordSize) {
      // Safety check for something that should never happen.
      const err = new Error("invalid record size")
      return Promise.reject(err)
    }

    controller.enqueue(cipher)
    this.buf = new Uint8Array()
    this.sequence++

    if (closing) {
      controller.terminate()
      this.eos = true
    }
  }

  /**
   * Adds chunk to buffer until there's enough data
   * to be flushed to the controller.
   * @param chunk Raw data to encrypt
   * @param controller
   */
  async transform(
    chunk: Uint8Array,
    controller: TransformStreamDefaultController<Uint8Array>,
  ): Promise<void> {
    let left = chunk.length

    while (true) {
      const cap = this.maxPlainSize - this.buf.length
      const n = Math.min(left, cap)
      const pos = chunk.length - left

      this.buf = concatUint8Array(this.buf, chunk.subarray(pos, pos + n))
      if (this.buf.length !== this.maxPlainSize) {
        break
      }

      left -= n
      await this.doFlush(controller)
    }
  }

  /**
   * Pushes any data remaining in the buffer.
   * @param controller
   * @returns
   */
  async flush(
    controller: TransformStreamDefaultController<Uint8Array>,
  ): Promise<void> {
    return this.doFlush(controller, true)
  }

  /**
   * Buffers data from raw until there's enough to decipher
   * a record and push it to the controller.
   * @implements WritableStream
   * @param raw
   * @param controller
   * @returns
   */
  async write(
    raw: Uint8Array,
    controller: TransformStreamDefaultController<Uint8Array>,
  ): Promise<void> {
    return this.transform(raw, controller)
  }

  /**
   * Closes the writer, sending in the final record
   * with the closing delimiter.
   * @implements WritableStream
   */
  close(
    controller: TransformStreamDefaultController<Uint8Array>,
  ): Promise<void> {
    return this.flush(controller)
  }

  /**
   * Returns a new instance of Encoder with the given
   * parameters.
   * @param key Master key
   * @param salt Random salt
   * @param rs Record size
   * @param keyID ID of the master key
   * @returns Encoder instance.
   */
  static async create(
    key: CryptoKey,
    salt: Uint8Array = randomSalt(),
    rs = 4096,
    keyID = "",
  ): Promise<Encoder> {
    assertAesGcmKey(key, "encrypt")
    if (keyID.length > 255)
      throw new EncodingError("keyID length cannot be over 255 bytes long")
    if (rs < minRecordSize)
      throw new EncodingError(
        `record size must be at least ${minRecordSize} bytes`,
      )

    const enc = detectKeyEncoding(key)!
    const prk = await derivePRK(key, salt)
    const cek = await deriveCEK(prk, enc, "encrypt")
    const head = Header.create(salt, rs, keyID)
    return new Encoder(head, prk, cek)
  }

  /**
   * Returns a new TransformStream which can be used to
   * encrypt data.
   * @param key Master key
   * @param salt Random salt
   * @param rs Record size
   * @param keyID ID of the master key
   * @returns TransformStream<Uint8Array>
   */
  static async transformStream(
    key: CryptoKey,
    salt: Uint8Array = randomSalt(),
    rs = 4096,
    keyID = "",
  ): Promise<TransformStream<Uint8Array, Uint8Array>> {
    const enc = await Encoder.create(key, salt, rs, keyID)
    return new TransformStream(enc)
  }

  /**
   * encode returns the cipher of plain.
   * @param key Master key
   * @param plain Plain data to ECE-encode
   * @param salt Random salt
   * @param rs Record size
   * @param keyID ID of the master key
   * @returns
   */
  static async encode(
    key: CryptoKey,
    plain: Uint8Array,
    salt: Uint8Array = randomSalt(),
    rs = 4096,
    keyID = "",
  ): Promise<Uint8Array> {
    const enc = await Encoder.create(key, salt, rs, keyID)

    let cipher = new Uint8Array()
    const controller: TransformStreamDefaultController<Uint8Array> = {
      desiredSize: null,
      enqueue: function (chunk: Uint8Array): void {
        cipher = concatUint8Array(cipher, chunk)
      },
      terminate: function (): void {
        return
      },
      error: function (): void {
        return
      },
    }

    await enc.write(plain, controller)
    await enc.flush(controller)
    return cipher
  }
}

/**
 * Represents a decoder capable of decrypting
 * a cipher into plain data.
 */
export class Decoder {
  private key: CryptoKey // Master key
  private prk?: Uint8Array // Pseudo-random key
  private cek?: CryptoKey // Content-encoding key
  private enc?: Encoding // Encoding
  private head?: Header // Header read from the first bytes
  private buf: Uint8Array // Buffer of data awaiting to be decrypted
  private sequence = 0n // Current sequence (96 bits)
  private eof = false // Value indicating if the final delimited (0x02) was hit

  /**
   * Instantiates a new Decoder with the given
   * key.
   * @param key Master key
   */
  constructor(key: CryptoKey) {
    assertAesGcmKey(key)
    this.enc = detectKeyEncoding(key)!
    this.buf = new Uint8Array(0)
    this.key = key
  }

  /**
   * Returns the header detected
   * at the first read.
   */
  get header(): Header | undefined {
    return this.head
  }

  /**
   * decrypt decrypts a record with the keys
   * of the decoder.
   * @param record Cipher to decrypt
   * @returns deciphered data
   */
  private async decrypt(record: Uint8Array): Promise<Uint8Array> {
    if (!this.prk || !this.cek) {
      return Promise.reject(new Error("decoder not ready"))
    }

    const nonce = await deriveNonce(this.prk, this.sequence, nonceLength)
    try {
      const plain = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: new Uint8Array(nonce),
          tagLength: aesTagLength * 8,
        },
        this.cek,
        new Uint8Array(record),
      )
      return new Uint8Array(plain)
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err)
      return Promise.reject(
        new EncodingError(`failed to decipher data: ${message}`),
      )
    }
  }

  /**
   * readHeaders buffers raw data in this.buf and returns false until
   * there's enough to read an ECE header, in which it returns
   * true.
   *
   * The header is sliced off the buffer before the function returns
   * true.
   *
   * @returns True when the header has been extracted.
   */
  private async readHeader(): Promise<boolean> {
    if (this.head) {
      throw new EncodingError("header has already been extracted")
    }

    const minLength = saltLength + 4 + 1 // rs + idLen
    if (this.buf.length < minLength) {
      return false
    }

    const tmpHead = new Header(this.buf.subarray(0, minLength))

    const headLength = minLength + tmpHead.idLength
    if (this.buf.length < headLength) {
      return false
    }

    this.head = new Header(this.buf.subarray(0, headLength))
    this.buf = this.buf.subarray(headLength)
    this.prk = await derivePRK(this.key, this.head.salt)
    if (!this.enc) {
      throw new EncodingError("encoding not detected from key")
    }
    this.cek = await deriveCEK(this.prk, this.enc, "decrypt")

    return true
  }

  /**
   * Buffers data from raw until there's enough to decipher
   * a record and push it to the controller.
   *
   * @implements TransformStream
   * @param controller
   * @returns
   */
  async transform(
    raw: Uint8Array,
    controller: TransformStreamDefaultController<Uint8Array>,
  ): Promise<void> {
    if (this.eof) {
      const err = new EncodingError("unexpected data after final delimiter")
      return Promise.reject(err)
    }

    this.buf = concatUint8Array(this.buf, raw)

    if (!this.head) {
      const done = await this.readHeader()
      if (!done) {
        return
      }
    }

    const rs = this.head!.recordSize
    while (this.buf.length >= rs) {
      const cipher = this.buf.subarray(0, rs)

      let decrypted = await this.decrypt(cipher)
      decrypted = trimRightUint8Array(decrypted, recordPadding)

      const delimiter = decrypted.at(decrypted.length - 1)
      if (delimiter === recordDelimiterFinal) {
        this.eof = true
      } else if (delimiter !== recordDelimiter) {
        const err = new EncodingError(
          "record ended with an unexpected delimiter",
        )
        return Promise.reject(err)
      }

      controller.enqueue(decrypted.subarray(0, decrypted.length - 1))
      this.buf = this.buf.subarray(cipher.length)
      this.sequence++
    }
  }

  /**
   * Decrypts any data remaining in the buffer and
   * enqueues it in the controller.
   * @param controller
   */
  async flush(
    controller: TransformStreamDefaultController<Uint8Array>,
  ): Promise<void> {
    if (!this.head) {
      return Promise.reject(
        new EncodingError("decoder not ready: header not available"),
      )
    }
    if (this.buf.length >= this.head.recordSize) {
      return Promise.reject(
        new EncodingError(
          "invalid buffer state: unexpected amount of data buffered",
        ),
      )
    }
    let decrypted = await this.decrypt(this.buf)
    decrypted = trimRightUint8Array(decrypted, recordPadding)

    const delimiter = decrypted.at(decrypted.length - 1)
    if (delimiter !== recordDelimiterFinal) {
      const err = new EncodingError("unexpected end of message")
      return Promise.reject(err)
    }

    controller.enqueue(decrypted.subarray(0, decrypted.length - 1))
    this.buf = new Uint8Array(0)
    this.sequence++
  }

  /**
   * Returns a new TransformStream instance with a built-in decoder.
   * @param key Master key.
   * @returns TransformStream<Uint8Array>
   */
  static transformStream(
    key: CryptoKey,
  ): TransformStream<Uint8Array, Uint8Array> {
    const dec = new Decoder(key)
    return new TransformStream(dec)
  }

  /**
   * Returns the plain version of the given cipher.
   * @param key Master key
   * @param cipher Cipher to decode.
   * @returns Plain data
   */
  static async decode(key: CryptoKey, cipher: Uint8Array): Promise<Uint8Array> {
    const dec = new Decoder(key)

    let plain = new Uint8Array()
    const controller: TransformStreamDefaultController<Uint8Array> = {
      desiredSize: null,
      enqueue: function (chunk: Uint8Array): void {
        plain = concatUint8Array(plain, chunk)
      },
      terminate: function (): void {
        return
      },
      error: function (): void {
        return
      },
    }

    await dec.transform(cipher, controller)
    await dec.flush(controller)
    return plain
  }
}

/**
 * Concatenates all the given arrays into a new one.
 */
function concatUint8Array(...items: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const size: number = items.map((v) => v.length).reduce((sum, v) => sum + v)
  const merged = new Uint8Array(size)

  let offset = 0
  for (const arr of items) {
    if (!arr.length) {
      continue
    }
    merged.set(arr, offset)
    offset += arr.length
  }

  return merged
}

/**
 * Returns a sub-slice of arr by slicing off all trailing
 * occurrences of suffix.
 * @param arr Array to edit
 * @param suffix Suffix to remove
 * @returns Sub-slice of arr.
 */
function trimRightUint8Array(arr: Uint8Array, suffix: number): Uint8Array {
  let n = 0

  while (true) {
    if (arr.at(arr.length - n - 1) !== suffix) {
      break
    }
    n++
  }
  return arr.subarray(0, arr.length - n)
}

/**
 * Returns a new Uint8Array containing all
 * the elements of arr first, then items appended.
 * at the end.
 * @param arr Original array to expand.
 * @param items uint8 values to add.
 * @returns
 */
function appendToUint8Array(arr: Uint8Array, ...items: number[]): Uint8Array {
  const newArr = new Uint8Array(arr.length + items.length)
  newArr.set(arr)
  newArr.set(items, arr.length)
  return newArr
}

/**
 * Returns a byte-array representation of n.
 * @param n Number
 * @params bits Number of bits in the representation
 * @param littleEndian Indicates if the array should use little-endian ordering
 *  instead of big-endian
 * @returns Uint8Array of size bits/8
 */
function toByteArray(n: bigint, bits = 96, littleEndian = false): Uint8Array {
  const bytes = bits >>> 3
  const out = new Uint8Array(bytes)
  for (let i = 0; i < bytes; i++) {
    const shift = BigInt(i) * 8n
    out[i] = Number((n >> shift) & 0xffn)
  }
  return littleEndian ? out : out.reverse()
}

/**
 * Returns the result of a XOR b. The length of the returned
 * array is min(a.length, b.length).
 *
 * Note: This is NOT constant-time, but is safe for nonce derivation
 * where no secret-dependent branching occurs.
 *
 * @param a Array 1
 * @param b Array 2
 */
function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const n = Math.min(a.length, b.length)
  const xor = new Uint8Array(n)
  for (let i = 0; i < n; i++) {
    xor[i] = a[i] ^ b[i]
  }
  return xor
}

// Re-export HTTP utilities
export * from "./http"

/**
 * Default export containing all public APIs.
 */
const ece: {
  readonly AES128GCM: Encoding
  readonly AES256GCM: Encoding
  readonly Decoder: typeof Decoder
  readonly detectHeaderEncoding: typeof detectHeaderEncoding
  readonly detectKeyEncoding: typeof detectKeyEncoding
  readonly Encoder: typeof Encoder
  readonly EncodingError: typeof EncodingError
  readonly Header: typeof Header
  readonly randomSalt: typeof randomSalt
} = {
  AES128GCM: AES128GCM,
  AES256GCM: AES256GCM,
  Decoder: Decoder,
  detectHeaderEncoding: detectHeaderEncoding,
  detectKeyEncoding: detectKeyEncoding,
  Encoder: Encoder,
  EncodingError: EncodingError,
  Header: Header,
  randomSalt: randomSalt,
}

export default ece
