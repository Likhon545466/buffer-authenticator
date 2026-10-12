/**
 * Web Crypto API primitives for vault encryption and key derivation.
 * Conforms to strict security constraints:
 * - AES-256-GCM encryption
 * - PBKDF2-HMAC-SHA256 with 250,000 iterations and 16-byte cryptographically secure random salt
 * - 12-byte cryptographically secure random IV for AES-GCM
 */

export const PBKDF2_ITERATIONS = 250000;
export const SALT_BYTE_LENGTH = 16;
export const IV_BYTE_LENGTH = 12;

/**
 * Base64 encoding and decoding helpers using Uint8Array
 */
export function bufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToBuffer(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Generate cryptographically secure random salt
 */
export function generateSalt(length = SALT_BYTE_LENGTH): Uint8Array {
  const salt = new Uint8Array(length);
  crypto.getRandomValues(salt);
  return salt;
}

/**
 * Generate cryptographically secure random IV for AES-GCM
 */
export function generateIV(length = IV_BYTE_LENGTH): Uint8Array {
  const iv = new Uint8Array(length);
  crypto.getRandomValues(iv);
  return iv;
}

/**
 * Derive AES-256-GCM CryptoKey from password and salt using PBKDF2-HMAC-SHA256
 */
export async function deriveKeyFromPassword(
  password: string,
  salt: Uint8Array,
  iterations = PBKDF2_ITERATIONS
): Promise<CryptoKey> {
  if (!password || password.length === 0) {
    throw new Error('Password cannot be empty');
  }

  const encoder = new TextEncoder();
  const passwordBytes = encoder.encode(password);

  // Import raw password as key derivation material
  const baseKey = await crypto.subtle.importKey(
    'raw',
    passwordBytes,
    'PBKDF2',
    false,
    ['deriveKey']
  );

  // Derive AES-GCM 256-bit key
  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as unknown as BufferSource,
      iterations,
      hash: 'SHA-256',
    },
    baseKey,
    {
      name: 'AES-GCM',
      length: 256,
    },
    true, // Extractable so the ephemeral key can be serialized to session storage
    ['encrypt', 'decrypt']
  );

  return derivedKey;
}

/**
 * Encrypt plaintext string using AES-256-GCM with a new random IV
 */
export async function encryptData(
  data: string,
  key: CryptoKey,
  iv?: Uint8Array
): Promise<{ ciphertext: string; iv: string }> {
  const actualIV = iv || generateIV();
  const encoder = new TextEncoder();
  const plaintextBytes = encoder.encode(data);

  const encryptedBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: actualIV as unknown as BufferSource,
    },
    key,
    plaintextBytes
  );

  return {
    ciphertext: bufferToBase64(encryptedBuffer),
    iv: bufferToBase64(actualIV),
  };
}

/**
 * Decrypt ciphertext string using AES-256-GCM and IV
 */
export async function decryptData(
  ciphertextBase64: string,
  ivBase64: string,
  key: CryptoKey
): Promise<string> {
  const ciphertextBytes = base64ToBuffer(ciphertextBase64);
  const ivBytes = base64ToBuffer(ivBase64);

  const decryptedBuffer = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: ivBytes as unknown as BufferSource,
    },
    key,
    ciphertextBytes as unknown as BufferSource
  );

  const decoder = new TextDecoder();
  return decoder.decode(decryptedBuffer);
}

/**
 * Export a CryptoKey to raw Base64 bytes (for transient chrome.storage.session)
 */
export async function exportKeyRaw(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey('raw', key);
  return bufferToBase64(raw);
}

/**
 * Import a CryptoKey from raw Base64 bytes
 */
export async function importKeyRaw(rawBase64: string): Promise<CryptoKey> {
  const rawBytes = base64ToBuffer(rawBase64);
  return crypto.subtle.importKey(
    'raw',
    rawBytes as unknown as BufferSource,
    {
      name: 'AES-GCM',
      length: 256,
    },
    true,
    ['encrypt', 'decrypt']
  );
}
