/**
 * TOTP & HOTP generation and URI parsing (RFC 6238 / RFC 4226)
 * Utilizes 'otpauth' for strict RFC compliance and robust parsing.
 */

import * as OTPAuth from 'otpauth';
import type { HashAlgorithm, OTPType, TOTPAccount } from '../types';

/**
 * Remove whitespace, hyphens, and convert secret to uppercase Base32
 */
export function sanitizeSecret(secret: string): string {
  return secret.replace(/[\s\-]/g, '').toUpperCase();
}

/**
 * Validate Base32 secret string (RFC 4648 Base32 alphabet A-Z, 2-7, optional '=' padding)
 */
export function validateSecret(secret: string): boolean {
  const sanitized = sanitizeSecret(secret);
  if (!sanitized || sanitized.length < 8) {
    return false;
  }
  const base32Regex = /^[A-Z2-7]+=*$/;
  return base32Regex.test(sanitized);
}

/**
 * Parse standard otpauth:// URI into account fields
 */
export function parseOtpAuthUri(uriString: string): {
  type: OTPType;
  issuer: string;
  account: string;
  secret: string;
  algorithm: HashAlgorithm;
  digits: number;
  period: number;
  counter?: number;
} {
  const parsed = OTPAuth.URI.parse(uriString.trim());
  const type: OTPType = parsed instanceof OTPAuth.HOTP ? 'hotp' : 'totp';

  // Normalize algorithm
  let algorithm: HashAlgorithm = 'SHA1';
  const algoStr = (parsed.algorithm || 'SHA1').toUpperCase();
  if (algoStr === 'SHA256' || algoStr === 'SHA512') {
    algorithm = algoStr;
  }

  const digits = parsed.digits || 6;
  const issuer = parsed.issuer || '';
  const account = parsed.label || '';
  const secret = parsed.secret.base32;

  let period = 30;
  let counter: number | undefined;

  if (parsed instanceof OTPAuth.TOTP) {
    period = parsed.period || 30;
  } else if (parsed instanceof OTPAuth.HOTP) {
    counter = parsed.counter || 0;
  }

  return {
    type,
    issuer: issuer.trim(),
    account: account.trim(),
    secret: sanitizeSecret(secret),
    algorithm,
    digits,
    period,
    counter,
  };
}

/**
 * Create an OTPAuth object for an account
 */
export function createOTPInstance(account: Pick<TOTPAccount, 'secret' | 'algorithm' | 'digits' | 'period' | 'type' | 'counter' | 'issuer' | 'account'>) {
  const secret = OTPAuth.Secret.fromBase32(sanitizeSecret(account.secret));

  if (account.type === 'hotp') {
    return new OTPAuth.HOTP({
      issuer: account.issuer,
      label: account.account,
      algorithm: account.algorithm,
      digits: account.digits,
      counter: account.counter ?? 0,
      secret,
    });
  }

  return new OTPAuth.TOTP({
    issuer: account.issuer,
    label: account.account,
    algorithm: account.algorithm,
    digits: account.digits,
    period: account.period || 30,
    secret,
  });
}

/**
 * Generate current code and remaining seconds for a TOTP account
 */
export function generateTOTPCode(
  account: TOTPAccount,
  timestampMs = Date.now()
): { code: string; nextCode: string; secondsRemaining: number } {
  const period = account.period || 30;
  const epochSeconds = Math.floor(timestampMs / 1000);
  const secondsRemaining = period - (epochSeconds % period);

  const otp = createOTPInstance(account);
  const code = otp.generate({ timestamp: timestampMs });
  let nextCode = code;
  try {
    if (account.type === 'hotp') {
      const nextOtp = createOTPInstance({ ...account, counter: (account.counter ?? 0) + 1 });
      nextCode = nextOtp.generate();
    } else {
      nextCode = otp.generate({ timestamp: timestampMs + period * 1000 });
    }
  } catch {
    nextCode = code;
  }

  return {
    code,
    nextCode,
    secondsRemaining: secondsRemaining === 0 ? period : secondsRemaining,
  };
}

/**
 * Format OTP code with space separation for readability (e.g., '123 456' or '1234 5678')
 */
export function formatOTPCode(code: string): string {
  if (code.length === 6) {
    return `${code.slice(0, 3)} ${code.slice(3)}`;
  }
  if (code.length === 8) {
    return `${code.slice(0, 4)} ${code.slice(4)}`;
  }
  return code;
}
