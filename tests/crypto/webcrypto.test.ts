import { describe, it, expect } from 'vitest';
import {
  generateSalt,
  generateIV,
  bufferToBase64,
  base64ToBuffer,
  deriveKeyFromPassword,
  encryptData,
  decryptData,
  exportKeyRaw,
  importKeyRaw,
  SALT_BYTE_LENGTH,
  IV_BYTE_LENGTH,
} from '../../src/crypto/webcrypto';

describe('WebCrypto Utilities', () => {
  it('generates 16-byte random salt and 12-byte random IV', () => {
    const salt = generateSalt();
    expect(salt.byteLength).toBe(SALT_BYTE_LENGTH);

    const iv = generateIV();
    expect(iv.byteLength).toBe(IV_BYTE_LENGTH);

    // Verify non-zero and distinct
    const salt2 = generateSalt();
    expect(bufferToBase64(salt)).not.toBe(bufferToBase64(salt2));
  });

  it('performs lossless Base64 encoding and decoding round-trip', () => {
    const original = new Uint8Array([0, 1, 2, 255, 128, 64, 32, 16, 8, 4]);
    const encoded = bufferToBase64(original);
    const decoded = base64ToBuffer(encoded);

    expect(decoded).toEqual(original);
  });

  it('derives AES-GCM CryptoKey using PBKDF2', async () => {
    const password = 'SuperSecureMasterPassword!123';
    const salt = generateSalt();

    const key = await deriveKeyFromPassword(password, salt, 10000); // 10k for fast test
    expect(key).toBeDefined();
    expect(key.algorithm.name).toBe('AES-GCM');
    expect(key.usages).toContain('encrypt');
    expect(key.usages).toContain('decrypt');

    await expect(deriveKeyFromPassword('', salt)).rejects.toThrow('Password cannot be empty');
  });

  it('encrypts and decrypts string data with AES-256-GCM', async () => {
    const password = 'MasterPassword123#';
    const salt = generateSalt();
    const key = await deriveKeyFromPassword(password, salt, 5000);

    const sensitiveData = JSON.stringify({
      secret: 'JBSWY3DPEHPK3PXP',
      issuer: 'GitHub',
    });

    const { ciphertext, iv } = await encryptData(sensitiveData, key);
    expect(ciphertext).toBeDefined();
    expect(iv).toBeDefined();

    const decrypted = await decryptData(ciphertext, iv, key);
    expect(decrypted).toBe(sensitiveData);
  });

  it('fails decryption if ciphertext is tampered with', async () => {
    const password = 'MasterPassword123#';
    const salt = generateSalt();
    const key = await deriveKeyFromPassword(password, salt, 5000);

    const sensitiveData = 'Secret message';
    const { ciphertext, iv } = await encryptData(sensitiveData, key);

    // Tamper with ciphertext by modifying characters
    const tamperedCiphertext = ciphertext.slice(0, -4) + 'AAAA';

    await expect(decryptData(tamperedCiphertext, iv, key)).rejects.toThrow();
  });

  it('fails decryption with incorrect password/key', async () => {
    const salt = generateSalt();
    const key1 = await deriveKeyFromPassword('CorrectPassword123', salt, 5000);
    const key2 = await deriveKeyFromPassword('WrongPassword123', salt, 5000);

    const { ciphertext, iv } = await encryptData('Secret text', key1);

    await expect(decryptData(ciphertext, iv, key2)).rejects.toThrow();
  });

  it('exports and re-imports raw key for transient session storage', async () => {
    const salt = generateSalt();
    const key = await deriveKeyFromPassword('TransientKeyTest', salt, 5000);

    const exportedRaw = await exportKeyRaw(key);
    expect(typeof exportedRaw).toBe('string');
    expect(exportedRaw.length).toBeGreaterThan(0);

    const importedKey = await importKeyRaw(exportedRaw);
    expect(importedKey).toBeDefined();

    // Verify imported key encrypts and decrypts identically
    const { ciphertext, iv } = await encryptData('Payload Test', importedKey);
    const decrypted = await decryptData(ciphertext, iv, key);
    expect(decrypted).toBe('Payload Test');
  });
});
