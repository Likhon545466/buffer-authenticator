/**
 * Universal Backup Parser
 *
 * Supports:
 * - Aegis Authenticator Mobile (Plaintext JSON with db.entries or entries)
 * - Aegis Authenticator Mobile (Encrypted JSON using scrypt + AES-GCM)
 * - AegisAuth Extension Backups (aegis-auth-backup-v1)
 * - andOTP / 2FAS / Bitwarden / Authenticator JSON arrays & objects
 * - Plaintext (.txt) files containing otpauth:// URIs, CSV lines, or Key-Value pairs
 */

import * as OTPAuth from 'otpauth';
import { parseOtpAuthUri, sanitizeSecret, validateSecret } from '../crypto/totp';
import { base64ToBuffer, decryptData, deriveKeyFromPassword } from '../crypto/webcrypto';
import { scrypt } from '../crypto/scrypt';
import type { HashAlgorithm, OTPType } from '../types';

export interface ParsedEntry {
  issuer: string;
  account: string;
  secret: string;
  algorithm: HashAlgorithm;
  digits: number;
  period: number;
  type: OTPType;
  counter?: number;
}

export function parseHexOrBase64(str: string): Uint8Array {
  const cleaned = str.trim();
  if (/^[0-9a-fA-F]+$/.test(cleaned) && cleaned.length % 2 === 0) {
    const bytes = new Uint8Array(cleaned.length / 2);
    for (let i = 0; i < cleaned.length; i += 2) {
      bytes[i / 2] = parseInt(cleaned.substring(i, i + 2), 16);
    }
    return bytes;
  }
  return base64ToBuffer(cleaned);
}

function concatBuffers(a: Uint8Array, b: Uint8Array): Uint8Array {
  const c = new Uint8Array(a.length + b.length);
  c.set(a, 0);
  c.set(b, a.length);
  return c;
}

/**
 * Normalizes algorithm string to SHA1, SHA256, or SHA512
 */
function normalizeAlgo(algoStr?: string): HashAlgorithm {
  const upper = (algoStr || 'SHA1').toUpperCase();
  if (upper === 'SHA256' || upper === 'SHA512') return upper;
  return 'SHA1';
}

/**
 * Extract entry from an Aegis JSON object
 */
function extractAegisEntry(item: any): ParsedEntry | null {
  const info = item.info || {};
  const rawSecret = info.secret || item.secret;
  if (!rawSecret) return null;

  const secret = sanitizeSecret(rawSecret);
  if (!validateSecret(secret)) return null;

  let issuer = (item.issuer || '').trim();
  let account = (item.name || item.account || '').trim();

  // If name contains "Issuer: Account"
  if (!issuer && account.includes(':')) {
    const parts = account.split(':');
    issuer = parts[0].trim();
    account = parts.slice(1).join(':').trim();
  }

  return {
    issuer,
    account: account || 'Account',
    secret,
    algorithm: normalizeAlgo(info.algo || item.algo),
    digits: info.digits || item.digits || 6,
    period: info.period || item.period || 30,
    type: item.type === 'hotp' ? 'hotp' : 'totp',
    counter: info.counter || item.counter,
  };
}

/**
 * Decrypt an Aegis Authenticator mobile encrypted JSON backup
 */
async function decryptAegisMobileBackup(parsed: any, password?: string): Promise<any> {
  if (!password) {
    throw new Error('This is an encrypted Aegis Mobile backup. Please enter the master password you set in Aegis.');
  }

  const slots = parsed.header?.slots;
  if (!Array.isArray(slots) || slots.length === 0) {
    throw new Error('Invalid Aegis encrypted backup: No key slots found in header');
  }

  // Find password slot (type 1)
  const pwdSlot = slots.find((s: any) => s.type === 1);
  if (!pwdSlot) {
    throw new Error('No password slot found in Aegis backup. Biometric-only slots cannot be decrypted on desktop.');
  }

  const salt = parseHexOrBase64(pwdSlot.salt);
  const n = pwdSlot.n || 32768;
  const r = pwdSlot.r || 8;
  const p = pwdSlot.p || 1;

  // 1. Derive slot key using scrypt
  const slotKeyBytes = await scrypt(password, salt, n, r, p, 32);

  // 2. Decrypt master key
  const slotKey = await crypto.subtle.importKey(
    'raw',
    slotKeyBytes as unknown as BufferSource,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  const slotNonce = parseHexOrBase64(pwdSlot.key_params?.nonce);
  let slotKeyCiphertext = parseHexOrBase64(pwdSlot.key);
  if (pwdSlot.key_params?.tag) {
    const tag = parseHexOrBase64(pwdSlot.key_params.tag);
    slotKeyCiphertext = concatBuffers(slotKeyCiphertext, tag);
  }

  let masterKeyBytesBuffer: ArrayBuffer;
  try {
    masterKeyBytesBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: slotNonce as unknown as BufferSource,
      },
      slotKey,
      slotKeyCiphertext as unknown as BufferSource
    );
  } catch {
    throw new Error('Incorrect Aegis master password');
  }

  // 3. Decrypt db payload
  const masterKey = await crypto.subtle.importKey(
    'raw',
    masterKeyBytesBuffer,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  const dbNonce = parseHexOrBase64(parsed.header.params?.nonce);
  let dbCiphertext = base64ToBuffer(parsed.db);
  if (parsed.header.params?.tag) {
    const tag = parseHexOrBase64(parsed.header.params.tag);
    dbCiphertext = concatBuffers(dbCiphertext, tag);
  }

  const decryptedDbBuffer = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: dbNonce as unknown as BufferSource,
    },
    masterKey,
    dbCiphertext as unknown as BufferSource
  );

  const decoder = new TextDecoder();
  const dbJson = decoder.decode(decryptedDbBuffer);
  return JSON.parse(dbJson);
}

function readVarint(buf: Uint8Array, offset: number): { value: number; nextIndex: number } {
  let res = 0;
  let shift = 0;
  let cur = offset;
  while (cur < buf.length) {
    const b = buf[cur++];
    res |= (b & 0x7f) << shift;
    if ((b & 0x80) === 0) break;
    shift += 7;
  }
  return { value: res, nextIndex: cur };
}

function skipField(buf: Uint8Array, offset: number, wireType: number): number {
  if (wireType === 0) {
    return readVarint(buf, offset).nextIndex;
  }
  if (wireType === 1) return offset + 8;
  if (wireType === 2) {
    const len = readVarint(buf, offset);
    return len.nextIndex + len.value;
  }
  if (wireType === 5) return offset + 4;
  return offset;
}

function parseOtpParameters(bytes: Uint8Array): ParsedEntry | null {
  let index = 0;
  let rawSecret: Uint8Array | null = null;
  let name = '';
  let issuer = '';
  let algorithm: HashAlgorithm = 'SHA1';
  let digits = 6;
  let type: OTPType = 'totp';
  let counter = 0;

  while (index < bytes.length) {
    const key = readVarint(bytes, index);
    index = key.nextIndex;
    const fieldNumber = key.value >> 3;
    const wireType = key.value & 0x07;

    if (wireType === 2) {
      const len = readVarint(bytes, index);
      index = len.nextIndex;
      const valBytes = bytes.subarray(index, index + len.value);
      index += len.value;

      if (fieldNumber === 1) {
        rawSecret = valBytes;
      } else if (fieldNumber === 2) {
        name = new TextDecoder().decode(valBytes);
      } else if (fieldNumber === 3) {
        issuer = new TextDecoder().decode(valBytes);
      }
    } else if (wireType === 0) {
      const val = readVarint(bytes, index);
      index = val.nextIndex;

      if (fieldNumber === 4) {
        if (val.value === 2) algorithm = 'SHA256';
        else if (val.value === 3) algorithm = 'SHA512';
        else algorithm = 'SHA1';
      } else if (fieldNumber === 5) {
        digits = val.value === 2 ? 8 : 6;
      } else if (fieldNumber === 6) {
        type = val.value === 1 ? 'hotp' : 'totp';
      } else if (fieldNumber === 7) {
        counter = val.value;
      }
    } else {
      index = skipField(bytes, index, wireType);
    }
  }

  if (!rawSecret || rawSecret.length === 0) return null;

  const base32Secret = new OTPAuth.Secret({
    buffer: rawSecret.buffer.slice(rawSecret.byteOffset, rawSecret.byteOffset + rawSecret.byteLength),
  }).base32;

  if (!validateSecret(base32Secret)) return null;

  let account = name.trim();
  if (!issuer && account.includes(':')) {
    const parts = account.split(':');
    issuer = parts[0].trim();
    account = parts.slice(1).join(':').trim();
  }

  return {
    issuer: issuer.trim(),
    account: account || 'Account',
    secret: base32Secret,
    algorithm,
    digits,
    period: 30,
    type,
    counter,
  };
}

/**
 * Parse Google Authenticator Migration URI (otpauth-migration://offline?data=...)
 */
export function parseGoogleAuthMigration(uriString: string): ParsedEntry[] {
  try {
    const url = new URL(uriString.trim());
    const dataParam = url.searchParams.get('data');
    if (!dataParam) return [];

    let base64 = decodeURIComponent(dataParam).replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4 !== 0) {
      base64 += '=';
    }
    const bytes = base64ToBuffer(base64);
    const results: ParsedEntry[] = [];

    let index = 0;
    while (index < bytes.length) {
      const key = readVarint(bytes, index);
      index = key.nextIndex;
      const fieldNumber = key.value >> 3;
      const wireType = key.value & 0x07;

      if (fieldNumber === 1 && wireType === 2) {
        const len = readVarint(bytes, index);
        index = len.nextIndex;
        const paramBytes = bytes.subarray(index, index + len.value);
        index += len.value;

        const entry = parseOtpParameters(paramBytes);
        if (entry) results.push(entry);
      } else {
        index = skipField(bytes, index, wireType);
      }
    }

    return results;
  } catch {
    return [];
  }
}

/**
 * Parse plain text string line by line (.txt file format)
 */
export function parsePlainTextBackup(text: string): ParsedEntry[] {
  const lines = text.split(/\r?\n/);
  const results: ParsedEntry[] = [];

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) {
      continue;
    }

    // Check if Google Authenticator Migration URI
    if (line.startsWith('otpauth-migration://')) {
      const migrationResults = parseGoogleAuthMigration(line);
      if (migrationResults.length > 0) {
        results.push(...migrationResults);
        continue;
      }
    }

    // Check if line is an otpauth:// URI
    if (line.startsWith('otpauth://')) {
      try {
        const parsed = parseOtpAuthUri(line);
        if (parsed.secret && validateSecret(parsed.secret)) {
          results.push({
            issuer: parsed.issuer || '',
            account: parsed.account || 'Account',
            secret: parsed.secret,
            algorithm: parsed.algorithm,
            digits: parsed.digits,
            period: parsed.period,
            type: parsed.type,
            counter: parsed.counter,
          });
        }
      } catch {
        // Skip invalid line
      }
      continue;
    }

    // Check if CSV: Issuer, Account, Secret, [Algorithm], [Digits], [Period]
    if (line.includes(',')) {
      const parts = line.split(',').map((p) => p.trim());
      if (parts.length >= 2) {
        // Find which part is the base32 secret
        const secretIdx = parts.findIndex((p) => validateSecret(sanitizeSecret(p)));
        if (secretIdx !== -1) {
          const secret = sanitizeSecret(parts[secretIdx]);
          const issuer = secretIdx > 0 ? parts[0] : (parts[1] || '');
          const account = secretIdx > 1 ? parts[1] : (parts[secretIdx + 1] || 'Account');
          results.push({
            issuer,
            account,
            secret,
            algorithm: 'SHA1',
            digits: 6,
            period: 30,
            type: 'totp',
          });
          continue;
        }
      }
    }

    // Check if Key-Value: "GitHub: JBSWY3DPEHPK3PXP" or "GitHub - JBSWY3DPEHPK3PXP"
    const kvMatch = line.match(/^([^:\-]+)[:\-]\s*([A-Za-z2-7\s=]+)$/);
    if (kvMatch) {
      const label = kvMatch[1].trim();
      const secret = sanitizeSecret(kvMatch[2].trim());
      if (validateSecret(secret)) {
        let issuer = label;
        let account = 'Account';
        if (label.includes('(') && label.includes(')')) {
          const m = label.match(/^(.*?)\s*\((.*?)\)$/);
          if (m) {
            issuer = m[1].trim();
            account = m[2].trim();
          }
        }
        results.push({
          issuer,
          account,
          secret,
          algorithm: 'SHA1',
          digits: 6,
          period: 30,
          type: 'totp',
        });
        continue;
      }
    }

    // Check if line is a standalone raw Base32 secret (standard secrets are >= 16 Base32 characters)
    const standaloneSecret = sanitizeSecret(line);
    if (!line.includes(' ') && standaloneSecret.length >= 16 && validateSecret(standaloneSecret)) {
      results.push({
        issuer: 'Imported',
        account: `Key-${results.length + 1}`,
        secret: standaloneSecret,
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        type: 'totp',
      });
    }
  }

  return results;
}

/**
 * Universal backup parser handling JSON (Aegis, AegisAuth, 2FAS, andOTP, Bitwarden) and TXT
 */
export async function parseBackup(
  dataString: string,
  password?: string
): Promise<ParsedEntry[]> {
  const trimmed = dataString.trim();

  // Try Google Authenticator Migration URI
  if (trimmed.startsWith('otpauth-migration://')) {
    const migrationResults = parseGoogleAuthMigration(trimmed);
    if (migrationResults.length > 0) return migrationResults;
  }

  // Try parsing as JSON first
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const parsed = JSON.parse(trimmed);

      // Format 1: AegisAuth Extension Encrypted Backup
      if (parsed.format === 'aegis-auth-backup-v1') {
        if (!password) {
          throw new Error('Master password required to decrypt backup file');
        }
        const salt = base64ToBuffer(parsed.salt);
        const backupKey = await deriveKeyFromPassword(password, salt, parsed.iterations || 250000);
        const decryptedJson = await decryptData(parsed.ciphertext, parsed.iv, backupKey);
        const decrypted = JSON.parse(decryptedJson);
        const rawAccounts = decrypted.accounts || [];
        return rawAccounts
          .map((a: any) => ({
            issuer: a.issuer || '',
            account: a.account || 'Account',
            secret: sanitizeSecret(a.secret),
            algorithm: normalizeAlgo(a.algorithm),
            digits: a.digits || 6,
            period: a.period || 30,
            type: a.type || 'totp',
            counter: a.counter,
          }))
          .filter((a: any) => validateSecret(a.secret));
      }

      // Format 2: Aegis Mobile Encrypted Backup (header.slots and db as string ciphertext)
      if (parsed.header && parsed.header.slots && typeof parsed.db === 'string') {
        const decryptedDb = await decryptAegisMobileBackup(parsed, password);
        const entries = decryptedDb.entries || [];
        const results = entries.map(extractAegisEntry).filter(Boolean) as ParsedEntry[];
        if (results.length === 0) {
          throw new Error('Aegis backup decrypted successfully, but no valid entries were found');
        }
        return results;
      }

      // Format 3: Aegis Mobile Plaintext Backup (db.entries array)
      if (parsed.db && Array.isArray(parsed.db.entries)) {
        const results = parsed.db.entries.map(extractAegisEntry).filter(Boolean) as ParsedEntry[];
        if (results.length === 0) {
          throw new Error('Aegis backup recognized, but contains 0 valid TOTP entries');
        }
        return results;
      }

      // Format 4: Aegis Mobile entries array at root
      if (Array.isArray(parsed.entries)) {
        const results = parsed.entries.map(extractAegisEntry).filter(Boolean) as ParsedEntry[];
        if (results.length > 0) return results;
      }

      // Format 5: 2FAS format ({ services: [ { name, secret, otp } ] })
      if (Array.isArray(parsed.services)) {
        const results: ParsedEntry[] = [];
        for (const s of parsed.services) {
          const secret = sanitizeSecret(s.secret || s.otp?.secret || '');
          if (!validateSecret(secret)) continue;
          results.push({
            issuer: s.name || '',
            account: s.otp?.account || 'Account',
            secret,
            algorithm: normalizeAlgo(s.otp?.algorithm),
            digits: s.otp?.digits || 6,
            period: s.otp?.period || 30,
            type: (s.otp?.tokenType?.toLowerCase() === 'hotp' ? 'hotp' : 'totp') as OTPType,
          });
        }
        if (results.length > 0) return results;
      }

      // Format 6: Plain array of accounts (e.g. andOTP or generic array)
      if (Array.isArray(parsed)) {
        const results: ParsedEntry[] = [];
        for (const item of parsed) {
          // Could be Aegis item or generic item
          const aegis = extractAegisEntry(item);
          if (aegis) {
            results.push(aegis);
            continue;
          }
          const rawSecret = item.secret || item.key;
          if (!rawSecret) continue;
          const secret = sanitizeSecret(rawSecret);
          if (!validateSecret(secret)) continue;
          results.push({
            issuer: item.issuer || item.label || '',
            account: item.account || item.name || 'Account',
            secret,
            algorithm: normalizeAlgo(item.algorithm || item.algo),
            digits: item.digits || 6,
            period: item.period || 30,
            type: item.type === 'hotp' ? 'hotp' : 'totp',
            counter: item.counter,
          });
        }
        if (results.length > 0) return results;
      }

      // Format 7: Wrapper object { accounts: [...] }
      if (Array.isArray(parsed.accounts)) {
        const results: ParsedEntry[] = [];
        for (const item of parsed.accounts) {
          const aegis = extractAegisEntry(item);
          if (aegis) {
            results.push(aegis);
            continue;
          }
          const rawSecret = item.secret || item.key;
          if (!rawSecret) continue;
          const secret = sanitizeSecret(rawSecret);
          if (!validateSecret(secret)) continue;
          results.push({
            issuer: item.issuer || '',
            account: item.account || 'Account',
            secret,
            algorithm: normalizeAlgo(item.algorithm),
            digits: item.digits || 6,
            period: item.period || 30,
            type: item.type === 'hotp' ? 'hotp' : 'totp',
            counter: item.counter,
          });
        }
        if (results.length > 0) return results;
      }

      // Format 8: Bitwarden export ({ items: [ { name, login: { totp } } ] })
      if (Array.isArray(parsed.items)) {
        const results: ParsedEntry[] = [];
        for (const item of parsed.items) {
          const totpStr = item.login?.totp;
          if (totpStr && totpStr.startsWith('otpauth://')) {
            try {
              const u = parseOtpAuthUri(totpStr);
              if (u.secret && validateSecret(u.secret)) {
                results.push({
                  issuer: u.issuer || item.name || '',
                  account: u.account || 'Account',
                  secret: u.secret,
                  algorithm: u.algorithm,
                  digits: u.digits,
                  period: u.period,
                  type: u.type,
                });
              }
            } catch {}
          }
        }
        if (results.length > 0) return results;
      }
    } catch (err: any) {
      // If error message indicates wrong password or specific backup error, rethrow
      if (err.message.includes('password') || err.message.includes('Aegis')) {
        throw err;
      }
      // If it wasn't valid JSON, fallback to plain text parsing below
    }
  }

  // Fallback: Parse as Plain Text (.txt file or lines of URIs/secrets)
  const textResults = parsePlainTextBackup(trimmed);
  if (textResults.length > 0) {
    return textResults;
  }

  throw new Error(
    'Unrecognized backup format. Please ensure your file is a valid Aegis JSON export, AegisAuth backup, or a TXT file containing otpauth:// URIs.'
  );
}
