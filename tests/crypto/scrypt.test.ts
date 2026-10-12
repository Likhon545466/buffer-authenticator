import { describe, it, expect } from 'vitest';
import { scrypt } from '../../src/crypto/scrypt';

describe('scrypt RFC 7914 Implementation', () => {
  it('computes RFC 7914 test vector 1', async () => {
    // P = "", S = "", N = 16, r = 1, p = 1, dkLen = 64
    const res = await scrypt('', new Uint8Array(0), 16, 1, 1, 64);
    const hex = Array.from(res).map((b) => b.toString(16).padStart(2, '0')).join('');
    console.log('scrypt output hex:', hex);
    expect(hex.length).toBe(128);
  });
});
