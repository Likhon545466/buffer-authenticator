import { describe, it, expect } from 'vitest';
import {
  sanitizeSecret,
  validateSecret,
  parseOtpAuthUri,
  generateTOTPCode,
  formatOTPCode,
} from '../../src/crypto/totp';
import type { TOTPAccount } from '../../src/types';

describe('TOTP Core & RFC Compliance', () => {
  it('sanitizes and validates Base32 secrets properly', () => {
    expect(sanitizeSecret('jbsw y3dp - ehpk 3pxp')).toBe('JBSWY3DPEHPK3PXP');

    expect(validateSecret('JBSWY3DPEHPK3PXP')).toBe(true);
    expect(validateSecret('JBSWY3DPEHPK3PXP====')).toBe(true);
    // Invalid characters (e.g., 0, 1, 8, 9, special chars)
    expect(validateSecret('INVALID0189')).toBe(false);
    expect(validateSecret('SHORT')).toBe(false); // Too short
  });

  it('parses standard otpauth:// URIs accurately', () => {
    const uri =
      'otpauth://totp/GitHub:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30';

    const parsed = parseOtpAuthUri(uri);
    expect(parsed.type).toBe('totp');
    expect(parsed.issuer).toBe('GitHub');
    expect(parsed.account).toBe('alice@example.com');
    expect(parsed.secret).toBe('JBSWY3DPEHPK3PXP');
    expect(parsed.algorithm).toBe('SHA1');
    expect(parsed.digits).toBe(6);
    expect(parsed.period).toBe(30);
  });

  it('parses HOTP URI with counter', () => {
    const uri =
      'otpauth://hotp/Acme:bob?secret=JBSWY3DPEHPK3PXP&issuer=Acme&counter=5&digits=8';

    const parsed = parseOtpAuthUri(uri);
    expect(parsed.type).toBe('hotp');
    expect(parsed.issuer).toBe('Acme');
    expect(parsed.counter).toBe(5);
    expect(parsed.digits).toBe(8);
  });

  it('generates predictable 6-digit TOTP codes for standard secret', () => {
    const account: TOTPAccount = {
      id: 'test-1',
      issuer: 'Test',
      account: 'test@example.com',
      secret: 'JBSWY3DPEHPK3PXP', // Base32 for 'Hello!\xde\xad\xbe\xef'
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      type: 'totp',
      createdAt: 0,
      updatedAt: 0,
    };

    // Epoch 1700000000000 ms (2023-11-14T22:13:20Z)
    const result1 = generateTOTPCode(account, 1700000000000);
    expect(result1.code).toMatch(/^\d{6}$/);
    expect(result1.secondsRemaining).toBeGreaterThanOrEqual(1);
    expect(result1.secondsRemaining).toBeLessThanOrEqual(30);

    // After 30 seconds, code changes
    const result2 = generateTOTPCode(account, 1700000030000);
    expect(result2.code).toMatch(/^\d{6}$/);
    expect(result2.code).not.toBe(result1.code);
  });

  it('generates 8-digit codes with SHA256 when configured', () => {
    const account: TOTPAccount = {
      id: 'test-2',
      issuer: 'Acme',
      account: 'acme@example.com',
      secret: 'JBSWY3DPEHPK3PXP',
      algorithm: 'SHA256',
      digits: 8,
      period: 60,
      type: 'totp',
      createdAt: 0,
      updatedAt: 0,
    };

    const result = generateTOTPCode(account, 1700000000000);
    expect(result.code).toMatch(/^\d{8}$/);
    expect(result.secondsRemaining).toBeGreaterThanOrEqual(1);
    expect(result.secondsRemaining).toBeLessThanOrEqual(60);
  });

  it('formats OTP codes with clean spacing', () => {
    expect(formatOTPCode('123456')).toBe('123 456');
    expect(formatOTPCode('12345678')).toBe('1234 5678');
    expect(formatOTPCode('123')).toBe('123');
  });
});
