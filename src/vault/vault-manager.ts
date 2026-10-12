/**
 * Vault Manager
 * Coordinates encrypted storage, key derivation, auto-locking, and account CRUD.
 * Strict offline invariants:
 * - Encrypted at rest using AES-256-GCM.
 * - PBKDF2-HMAC-SHA256 (250k+ iterations, 16-byte random salt).
 * - Fresh random 12-byte IV on every single write operation.
 * - In-memory key wiped on lock; transient session key stored only in chrome.storage.session.
 * - Never returns raw secrets to UI or content scripts.
 */

import {
  deriveKeyFromPassword,
  encryptData,
  decryptData,
  generateSalt,
  exportKeyRaw,
  importKeyRaw,
  base64ToBuffer,
  bufferToBase64,
} from '../crypto/webcrypto';
import { generateTOTPCode, sanitizeSecret, validateSecret } from '../crypto/totp';
import { parseBackup } from '../utils/backup-parser';
import type {
  DecryptedVault,
  EncryptedVaultRecord,
  PublicAccount,
  TOTPAccount,
  VaultSettings,
  VaultStatus,
  DomainAutofillAccount,
  DomainMatchResult,
} from '../types';

export interface StorageAreaLike {
  get(keys?: string | string[] | Record<string, any>): Promise<Record<string, any>>;
  set(items: Record<string, any>): Promise<void>;
  remove(keys: string | string[]): Promise<void>;
  clear?(): Promise<void>;
}

export interface StorageProvider {
  local: StorageAreaLike;
  session: StorageAreaLike;
  sync?: StorageAreaLike;
}

export const DEFAULT_SETTINGS: VaultSettings = {
  autoLockMinutes: 5,
  lockOnIdle: true,
  theme: 'dark',
  clipboardClearSeconds: 30,
  biometricEnabled: false,
};

/**
 * Default browser extension storage provider
 */
export function getExtensionStorage(): StorageProvider {
  const getArea = (area: 'local' | 'session' | 'sync'): StorageAreaLike => {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage[area]) {
      return {
        get: (keys) => chrome.storage[area].get(keys),
        set: (items) => chrome.storage[area].set(items),
        remove: (keys) => chrome.storage[area].remove(keys),
        clear: () => chrome.storage[area].clear(),
      };
    }
    // Fallback in-memory map for non-extension environments (e.g. testing)
    const store = new Map<string, any>();
    return {
      async get(keys) {
        if (!keys) {
          return Object.fromEntries(store.entries());
        }
        if (typeof keys === 'string') {
          return store.has(keys) ? { [keys]: store.get(keys) } : {};
        }
        if (Array.isArray(keys)) {
          const res: Record<string, any> = {};
          for (const k of keys) {
            if (store.has(k)) res[k] = store.get(k);
          }
          return res;
        }
        const res: Record<string, any> = { ...keys };
        for (const k of Object.keys(keys)) {
          if (store.has(k)) res[k] = store.get(k);
        }
        return res;
      },
      async set(items) {
        for (const [k, v] of Object.entries(items)) {
          store.set(k, v);
        }
      },
      async remove(keys) {
        const keyList = Array.isArray(keys) ? keys : [keys];
        for (const k of keyList) {
          store.delete(k);
        }
      },
      async clear() {
        store.clear();
      },
    };
  };

  return {
    local: getArea('local'),
    session: getArea('session'),
    sync: getArea('sync'),
  };
}

export class VaultManager {
  private storage: StorageProvider;
  private currentKey: CryptoKey | null = null;
  private vaultData: DecryptedVault | null = null;
  private cachedSalt: Uint8Array | null = null;

  constructor(storageProvider?: StorageProvider) {
    this.storage = storageProvider || getExtensionStorage();
  }

  /**
   * Determine if the vault has been initialized with a master password
   */
  async isInitialized(): Promise<boolean> {
    const res = await this.storage.local.get('vault');
    return Boolean(res.vault && res.vault.ciphertext && res.vault.salt);
  }

  /**
   * Determine if the vault is currently locked
   */
  async isLocked(): Promise<boolean> {
    if (this.currentKey && this.vaultData) {
      return false;
    }
    // Attempt session restoration if key is in session storage
    const restored = await this.tryRestoreSession();
    return !restored;
  }

  /**
   * Attempt to restore decrypted session from ephemeral session storage
   */
  async tryRestoreSession(): Promise<boolean> {
    try {
      const sessionRes = await this.storage.session.get('sessionKey');
      if (!sessionRes.sessionKey) {
        return false;
      }

      const key = await importKeyRaw(sessionRes.sessionKey);
      const localRes = await this.storage.local.get('vault');
      const vaultRecord = localRes.vault as EncryptedVaultRecord;

      if (!vaultRecord || !vaultRecord.ciphertext || !vaultRecord.iv || !vaultRecord.salt) {
        return false;
      }

      const plaintext = await decryptData(vaultRecord.ciphertext, vaultRecord.iv, key);
      const parsed = JSON.parse(plaintext) as DecryptedVault;

      this.currentKey = key;
      this.vaultData = parsed;
      this.cachedSalt = base64ToBuffer(vaultRecord.salt);
      return true;
    } catch {
      // If decryption fails, clear invalid session key
      await this.storage.session.remove('sessionKey');
      this.currentKey = null;
      this.vaultData = null;
      return false;
    }
  }

  /**
   * Initialize a new vault with master password
   */
  async initVault(masterPassword: string): Promise<void> {
    if (await this.isInitialized()) {
      throw new Error('Vault is already initialized');
    }
    if (!masterPassword || masterPassword.length < 8) {
      throw new Error('Master password must be at least 8 characters long');
    }

    const salt = generateSalt();
    const key = await deriveKeyFromPassword(masterPassword, salt);

    const initialVault: DecryptedVault = {
      version: 1,
      accounts: [],
      updatedAt: Date.now(),
    };

    const serialized = JSON.stringify(initialVault);
    const { ciphertext, iv } = await encryptData(serialized, key);

    const record: EncryptedVaultRecord = {
      ciphertext,
      salt: bufferToBase64(salt),
      iv,
    };

    await this.storage.local.set({ vault: record });

    // Store transient session key
    const rawKeyBase64 = await exportKeyRaw(key);
    await this.storage.session.set({ sessionKey: rawKeyBase64 });

    this.currentKey = key;
    this.vaultData = initialVault;
    this.cachedSalt = salt;
  }

  /**
   * Unlock existing vault with master password
   */
  async unlockVault(masterPassword: string): Promise<boolean> {
    const localRes = await this.storage.local.get('vault');
    const record = localRes.vault as EncryptedVaultRecord;

    if (!record || !record.salt || !record.ciphertext || !record.iv) {
      throw new Error('No vault found to unlock');
    }

    const salt = base64ToBuffer(record.salt);
    const key = await deriveKeyFromPassword(masterPassword, salt);

    try {
      const plaintext = await decryptData(record.ciphertext, record.iv, key);
      const parsed = JSON.parse(plaintext) as DecryptedVault;

      this.currentKey = key;
      this.vaultData = parsed;
      this.cachedSalt = salt;

      // Store in transient session storage
      const rawKeyBase64 = await exportKeyRaw(key);
      await this.storage.session.set({ sessionKey: rawKeyBase64 });
      return true;
    } catch {
      throw new Error('Incorrect master password');
    }
  }

  /**
   * Instantly lock vault, clearing memory and session storage
   */
  async lockVault(): Promise<void> {
    if (this.cachedSalt) {
      this.cachedSalt.fill(0);
      this.cachedSalt = null;
    }
    if (this.vaultData) {
      if (Array.isArray(this.vaultData.accounts)) {
        this.vaultData.accounts.forEach((acc) => {
          acc.secret = '';
        });
        this.vaultData.accounts.length = 0;
      }
      this.vaultData = null;
    }
    this.currentKey = null;
    await this.storage.session.remove('sessionKey');
  }

  /**
   * Internal helper: persist in-memory vault to encrypted storage
   */
  private async persistVault(): Promise<void> {
    if (!this.currentKey || !this.vaultData) {
      throw new Error('Vault is locked');
    }

    let salt = this.cachedSalt;
    if (!salt) {
      const localRes = await this.storage.local.get('vault');
      if (localRes.vault?.salt) {
        salt = base64ToBuffer(localRes.vault.salt);
        this.cachedSalt = salt;
      } else {
        salt = generateSalt();
        this.cachedSalt = salt;
      }
    }

    this.vaultData.updatedAt = Date.now();
    const serialized = JSON.stringify(this.vaultData);
    // encryptData automatically generates a fresh 12-byte random IV
    const { ciphertext, iv } = await encryptData(serialized, this.currentKey);

    const record: EncryptedVaultRecord = {
      ciphertext,
      salt: bufferToBase64(salt),
      iv,
    };

    await this.storage.local.set({ vault: record });
  }

  /**
   * Get public account list (includes generated codes, NEVER secrets)
   */
  async getPublicAccounts(): Promise<PublicAccount[]> {
    if (await this.isLocked()) {
      throw new Error('Vault is locked');
    }
    if (!this.vaultData) {
      return [];
    }

    const now = Date.now();
    const mapped: PublicAccount[] = this.vaultData.accounts.map((acc) => {
      const { code, nextCode, secondsRemaining } = generateTOTPCode(acc, now);
      return {
        id: acc.id,
        issuer: acc.issuer,
        account: acc.account,
        digits: acc.digits,
        period: acc.period,
        code,
        nextCode,
        secondsRemaining,
        type: acc.type,
        pinned: !!acc.pinned,
        category: acc.category || 'General',
        createdAt: acc.createdAt || 0,
      };
    });

    // Pinned accounts sort to the top
    return mapped.sort((a, b) => {
      if (a.pinned !== b.pinned) {
        return (b.pinned ? 1 : 0) - (a.pinned ? 1 : 0);
      }
      return 0;
    });
  }

  /**
   * Toggle pinned/favorite status of an account
   */
  async togglePin(id: string): Promise<boolean> {
    if (await this.isLocked()) {
      throw new Error('Vault is locked');
    }
    if (!this.vaultData) {
      throw new Error('Vault data unavailable');
    }

    const account = this.vaultData.accounts.find((a) => a.id === id);
    if (!account) {
      throw new Error('Account not found');
    }

    account.pinned = !account.pinned;
    account.updatedAt = Date.now();
    await this.persistVault();
    return account.pinned;
  }

  /**
   * Get full details of an account by ID
   */
  async getAccount(id: string): Promise<TOTPAccount | null> {
    if (await this.isLocked()) {
      throw new Error('Vault is locked');
    }
    if (!this.vaultData) {
      return null;
    }
    const acc = this.vaultData.accounts.find((a) => a.id === id);
    return acc ? { ...acc } : null;
  }

  /**
   * Add a new 2FA account to the vault
   */
  async addAccount(accountData: Omit<TOTPAccount, 'id' | 'createdAt' | 'updatedAt'>): Promise<PublicAccount> {
    if (await this.isLocked()) {
      throw new Error('Vault is locked');
    }
    if (!this.vaultData) {
      throw new Error('Vault data unavailable');
    }

    const sanitizedSecret = sanitizeSecret(accountData.secret);
    if (!validateSecret(sanitizedSecret)) {
      throw new Error('Invalid Base32 secret key');
    }

    const now = Date.now();
    const id = typeof crypto.randomUUID === 'function' ? crypto.randomUUID() : `${now}-${Math.random().toString(36).slice(2, 9)}`;

    const newAccount: TOTPAccount = {
      ...accountData,
      id,
      secret: sanitizedSecret,
      digits: accountData.digits || 6,
      period: accountData.period || 30,
      algorithm: accountData.algorithm || 'SHA1',
      type: accountData.type || 'totp',
      pinned: !!accountData.pinned,
      category: accountData.category || 'General',
      createdAt: now,
      updatedAt: now,
    };

    this.vaultData.accounts.push(newAccount);
    await this.persistVault();

    const { code, nextCode, secondsRemaining } = generateTOTPCode(newAccount, now);
    return {
      id: newAccount.id,
      issuer: newAccount.issuer,
      account: newAccount.account,
      digits: newAccount.digits,
      period: newAccount.period,
      code,
      nextCode,
      secondsRemaining,
      type: newAccount.type,
      pinned: newAccount.pinned,
      category: newAccount.category,
      createdAt: newAccount.createdAt,
    };
  }

  /**
   * Update an existing account
   */
  async updateAccount(
    id: string,
    updates: Partial<Omit<TOTPAccount, 'id' | 'createdAt'>>
  ): Promise<void> {
    if (await this.isLocked()) {
      throw new Error('Vault is locked');
    }
    if (!this.vaultData) {
      throw new Error('Vault data unavailable');
    }

    const index = this.vaultData.accounts.findIndex((a) => a.id === id);
    if (index === -1) {
      throw new Error('Account not found');
    }

    const current = this.vaultData.accounts[index];
    let secret = current.secret;
    if (updates.secret) {
      const sanitized = sanitizeSecret(updates.secret);
      if (!validateSecret(sanitized)) {
        throw new Error('Invalid Base32 secret key');
      }
      secret = sanitized;
    }

    this.vaultData.accounts[index] = {
      ...current,
      ...updates,
      secret,
      updatedAt: Date.now(),
    };

    await this.persistVault();
  }

  /**
   * Delete an account from the vault
   */
  async deleteAccount(id: string): Promise<void> {
    if (await this.isLocked()) {
      throw new Error('Vault is locked');
    }
    if (!this.vaultData) {
      throw new Error('Vault data unavailable');
    }

    const initialLen = this.vaultData.accounts.length;
    this.vaultData.accounts = this.vaultData.accounts.filter((a) => a.id !== id);

    if (this.vaultData.accounts.length === initialLen) {
      throw new Error('Account not found');
    }

    await this.persistVault();
  }

  /**
   * Common service aliases for accurate website-to-issuer matching
   */
  private static readonly DOMAIN_ALIASES: Record<string, string[]> = {
    github: ['github', 'gh'],
    google: ['google', 'gmail', 'gsuite', 'youtube', 'alphabet'],
    facebook: ['facebook', 'meta', 'fb', 'instagram', 'whatsapp'],
    instagram: ['instagram', 'meta', 'facebook'],
    microsoft: ['microsoft', 'live', 'outlook', 'office', 'ms', 'xbox', 'azure'],
    twitter: ['twitter', 'x'],
    x: ['twitter', 'x'],
    amazon: ['amazon', 'aws'],
    apple: ['apple', 'icloud'],
    binance: ['binance'],
    discord: ['discord'],
    dropbox: ['dropbox'],
    gitlab: ['gitlab'],
    bitbucket: ['bitbucket', 'atlassian'],
    steam: ['steam', 'valvesoftware'],
    reddit: ['reddit'],
    twitch: ['twitch'],
    paypal: ['paypal'],
    uber: ['uber'],
    linkedin: ['linkedin'],
    slack: ['slack'],
    zoom: ['zoom'],
    proton: ['proton', 'protonmail'],
  };

  /**
   * Score an account against a host domain.
   * Prevents false positives (e.g. empty strings, single letters)
   */
  scoreAccountForDomain(acc: Pick<TOTPAccount, 'issuer' | 'account'>, domain: string): number {
    if (!domain) return 0;
    const clean = domain.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0].split(':')[0];
    const parts = clean.split('.');

    let baseDomain = parts[0];
    if (parts.length >= 3 && ['accounts', 'login', 'auth', 'signin', 'id', 'm', 'secure', 'my'].includes(parts[0])) {
      baseDomain = parts[1];
    }
    const cleanDomain = parts.slice(-2).join('.');

    const issuer = (acc.issuer || '').toLowerCase().trim();
    const account = (acc.account || '').toLowerCase().trim();
    const aliases = VaultManager.DOMAIN_ALIASES[baseDomain] || [baseDomain];

    if (!issuer && !account) return 0;

    // 1. Exact issuer matches (Highest priority)
    if (issuer === baseDomain) return 100;
    if (aliases.includes(issuer)) return 95;
    if (issuer.length >= 3 && issuer === cleanDomain) return 90;

    // 2. Contains matching with length guard (prevent empty string / short match bugs)
    if (issuer.length >= 3 && issuer.includes(baseDomain)) return 80;
    if (issuer.length >= 3 && baseDomain.includes(issuer)) return 75;
    if (aliases.some((a) => a.length >= 3 && issuer.includes(a))) return 70;

    // 3. Account label contains base domain (e.g. likhon@github.com)
    if (account.length >= 4 && account.includes(baseDomain)) return 40;

    return 0;
  }

  /**
   * Lookup code matching domain or issuer for inline autofill
   */
  async getCodeForDomain(domain: string): Promise<DomainMatchResult | null> {
    if (await this.isLocked()) {
      return null;
    }
    if (!this.vaultData || this.vaultData.accounts.length === 0) {
      return null;
    }

    const now = Date.now();
    const scoredAccounts = this.vaultData.accounts.map((acc) => {
      const score = this.scoreAccountForDomain(acc, domain);
      const { code, nextCode, secondsRemaining } = generateTOTPCode(acc, now);
      const account: DomainAutofillAccount = {
        id: acc.id,
        issuer: acc.issuer,
        account: acc.account,
        code,
        nextCode,
        secondsRemaining,
        period: acc.period || 30,
        digits: acc.digits || 6,
      };
      return { account, score };
    });

    const matched = scoredAccounts
      .filter((s) => s.score > 0)
      .sort((a, b) => b.score - a.score)
      .map((s) => s.account);

    const all = scoredAccounts.map((s) => s.account);

    if (matched.length === 0) {
      return null;
    }

    const primary = matched[0];
    return {
      code: primary.code,
      issuer: primary.issuer,
      account: primary.account,
      matched,
      all,
    };
  }

  /**
   * Change master password
   */
  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    if (!newPassword || newPassword.length < 8) {
      throw new Error('New master password must be at least 8 characters long');
    }

    // Ensure we are unlocked and verify current password
    const isLocked = await this.isLocked();
    if (isLocked) {
      await this.unlockVault(currentPassword);
    } else {
      // Re-verify current password
      const localRes = await this.storage.local.get('vault');
      const salt = base64ToBuffer(localRes.vault.salt);
      const testKey = await deriveKeyFromPassword(currentPassword, salt);
      await decryptData(localRes.vault.ciphertext, localRes.vault.iv, testKey);
    }

    if (!this.vaultData) {
      throw new Error('Vault data unavailable');
    }

    // Derive new key with new random salt
    const newSalt = generateSalt();
    const newKey = await deriveKeyFromPassword(newPassword, newSalt);

    const serialized = JSON.stringify(this.vaultData);
    const { ciphertext, iv } = await encryptData(serialized, newKey);

    const record: EncryptedVaultRecord = {
      ciphertext,
      salt: bufferToBase64(newSalt),
      iv,
    };

    await this.storage.local.set({ vault: record });

    // Update transient key in session storage
    const rawKeyBase64 = await exportKeyRaw(newKey);
    await this.storage.session.set({ sessionKey: rawKeyBase64 });

    this.currentKey = newKey;
    this.cachedSalt = newSalt;
  }

  /**
   * Get Settings
   */
  async getSettings(): Promise<VaultSettings> {
    const syncArea = this.storage.sync || this.storage.local;
    const res = await syncArea.get('settings');
    return { ...DEFAULT_SETTINGS, ...(res.settings || {}) };
  }

  /**
   * Save Settings
   */
  async updateSettings(settings: Partial<VaultSettings>): Promise<VaultSettings> {
    const current = await this.getSettings();
    const updated = { ...current, ...settings };
    const syncArea = this.storage.sync || this.storage.local;
    await syncArea.set({ settings: updated });
    return updated;
  }

  /**
   * Get comprehensive status for UI
   */
  async getStatus(): Promise<VaultStatus> {
    const initialized = await this.isInitialized();
    const locked = initialized ? await this.isLocked() : true;
    const settings = await this.getSettings();
    const count = !locked && this.vaultData ? this.vaultData.accounts.length : 0;

    return {
      isInitialized: initialized,
      isLocked: locked,
      accountCount: count,
      settings,
    };
  }

  /**
   * Export vault as encrypted backup JSON string
   */
  async exportVault(password: string): Promise<string> {
    if (await this.isLocked()) {
      await this.unlockVault(password);
    }
    if (!this.vaultData) {
      throw new Error('Vault data unavailable');
    }

    // Create an encrypted backup bundle using the password and new salt
    const backupSalt = generateSalt();
    const backupKey = await deriveKeyFromPassword(password, backupSalt);
    const payload = JSON.stringify({
      version: 1,
      exportedAt: Date.now(),
      accounts: this.vaultData.accounts,
    });

    const { ciphertext, iv } = await encryptData(payload, backupKey);

    return JSON.stringify({
      format: 'aegis-auth-backup-v1',
      salt: bufferToBase64(backupSalt),
      iv,
      ciphertext,
      iterations: 250000,
    }, null, 2);
  }

  /**
   * Import vault from JSON or TXT backup string
   */
  async importVault(dataString: string, password?: string): Promise<{ importedCount: number }> {
    if (await this.isLocked()) {
      throw new Error('Vault must be unlocked to import accounts');
    }
    if (!this.vaultData) {
      throw new Error('Vault data unavailable');
    }

    const parsedEntries = await parseBackup(dataString, password);

    let importedCount = 0;
    const now = Date.now();

    for (const acc of parsedEntries) {
      if (!acc.secret || !acc.account) continue;
      const sanitized = sanitizeSecret(acc.secret);
      if (!validateSecret(sanitized)) continue;

      // Avoid exact duplicate secret + account + issuer
      const exists = this.vaultData.accounts.some(
        (a) => a.secret === sanitized && a.account === acc.account && a.issuer === acc.issuer
      );

      if (!exists) {
        this.vaultData.accounts.push({
          id: typeof crypto.randomUUID === 'function' ? crypto.randomUUID() : `${now}-${Math.random().toString(36).slice(2, 9)}`,
          issuer: acc.issuer || '',
          account: acc.account || '',
          secret: sanitized,
          digits: acc.digits || 6,
          period: acc.period || 30,
          algorithm: acc.algorithm || 'SHA1',
          type: acc.type || 'totp',
          counter: acc.counter,
          createdAt: now,
          updatedAt: now,
        });
        importedCount++;
      }
    }

    await this.persistVault();
    return { importedCount };
  }
}
