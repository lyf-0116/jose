/**
 * Default JWE decryption resource limits, the single source of truth for the defaults documented on
 * `DecryptOptions` in src/types.d.ts. Keep the documentation in sync when changing these.
 *
 * Raising a default weakens the out-of-the-box protection (CPU exhaustion via PBKDF2 iterations,
 * memory exhaustion via decompression bombs); lowering one rejects JWEs whose larger values are
 * still legitimate.
 */

/** Default for `maxPBES2Count`: maximum accepted "p2c" (PBES2 Count) Header Parameter value. */
export const defaultMaxPBES2Count = 10_000

/** Default for `maxDecompressedLength`: maximum decompressed plaintext size in bytes. */
export const defaultMaxDecompressedLength = 250_000
