import { describe, it, expect, beforeEach } from 'vitest';
import { VaultManager, type StorageProvider } from '../../src/vault/vault-manager';

function createMockStorage(): StorageProvider {
  const storeLocal = new Map<string, any>();
  const storeSession = new Map<string, any>();
  const storeSync = new Map<string, any>();

  const makeArea = (store: Map<string, any>) => ({
    async get(keys?: any) {
      if (!keys) return Object.fromEntries(store.entries());
      if (typeof keys === 'string') return store.has(keys) ? { [keys]: store.get(keys) } : {};
      if (Array.isArray(keys)) {
        const res: Record<string, any> = {};
        for (const k of keys) {
          if (store.has(k)) res[k] = store.get(k);
        }
        return res;
      }
      return {};
    },
    async set(items: Record<string, any>) {
      for (const [k, v] of Object.entries(items)) {
        store.set(k, v);
      }
    },
    async remove(keys: any) {
      const list = Array.isArray(keys) ? keys : [keys];
      for (const k of list) store.delete(k);
    },
    async clear() {
      store.clear();
    },
  });

  return {
    local: makeArea(storeLocal),
    session: makeArea(storeSession),
    sync: makeArea(storeSync),
  };
}

describe('VaultManager', () => {
  let storage: StorageProvider;
  let vaultManager: VaultManager;
  const masterPassword = 'MasterPassword2026!';

  beforeEach(() => {
    storage = createMockStorage();
    vaultManager = new VaultManager(storage);
  });

  it('initializes a new vault properly', async () => {
    expect(await vaultManager.isInitialized()).toBe(false);
    expect(await vaultManager.isLocked()).toBe(true);

    await vaultManager.initVault(masterPassword);

    expect(await vaultManager.isInitialized()).toBe(true);
    expect(await vaultManager.isLocked()).toBe(false);

    // Verify storage has encrypted ciphertext, salt, and iv
    const local = await storage.local.get('vault');
    expect(local.vault).toBeDefined();
    expect(local.vault.ciphertext).toBeDefined();
    expect(local.vault.salt).toBeDefined();
    expect(local.vault.iv).toBeDefined();

    // Verify session storage holds transient sessionKey
    const session = await storage.session.get('sessionKey');
    expect(session.sessionKey).toBeDefined();

    // Disallow re-initializing
    await expect(vaultManager.initVault('AnotherPassword123')).rejects.toThrow(
      'Vault is already initialized'
    );
  });

  it('rejects master passwords shorter than 8 characters', async () => {
    await expect(vaultManager.initVault('short')).rejects.toThrow(
      'Master password must be at least 8 characters long'
    );
  });

  it('locks vault and clears transient memory and session storage', async () => {
    await vaultManager.initVault(masterPassword);
    expect(await vaultManager.isLocked()).toBe(false);

    await vaultManager.lockVault();
    expect(await vaultManager.isLocked()).toBe(true);

    const session = await storage.session.get('sessionKey');
    expect(session.sessionKey).toBeUndefined();

    // Operations should fail while locked
    await expect(vaultManager.getPublicAccounts()).rejects.toThrow('Vault is locked');
  });

  it('unlocks vault with correct password and rejects incorrect password', async () => {
    await vaultManager.initVault(masterPassword);
    await vaultManager.lockVault();

    await expect(vaultManager.unlockVault('WrongPassword')).rejects.toThrow(
      'Incorrect master password'
    );
    expect(await vaultManager.isLocked()).toBe(true);

    const unlocked = await vaultManager.unlockVault(masterPassword);
    expect(unlocked).toBe(true);
    expect(await vaultManager.isLocked()).toBe(false);
  });

  it('adds an account and produces public accounts with NO raw secrets', async () => {
    await vaultManager.initVault(masterPassword);

    const added = await vaultManager.addAccount({
      issuer: 'GitHub',
      account: 'octocat@github.com',
      secret: 'JBSWY3DPEHPK3PXP',
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      type: 'totp',
    });

    expect(added.id).toBeDefined();
    expect(added.issuer).toBe('GitHub');
    expect(added.code).toMatch(/^\d{6}$/);
    expect((added as any).secret).toBeUndefined();

    const publicAccounts = await vaultManager.getPublicAccounts();
    expect(publicAccounts.length).toBe(1);
    expect(publicAccounts[0].issuer).toBe('GitHub');
    expect(publicAccounts[0].code).toMatch(/^\d{6}$/);
    // CRITICAL SECURITY INVARIANT: Secret must NEVER be present in public representation
    expect((publicAccounts[0] as any).secret).toBeUndefined();
  });

  it('updates and deletes accounts', async () => {
    await vaultManager.initVault(masterPassword);

    const added = await vaultManager.addAccount({
      issuer: 'AWS',
      account: 'admin@aws.com',
      secret: 'JBSWY3DPEHPK3PXP',
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      type: 'totp',
    });

    await vaultManager.updateAccount(added.id, {
      issuer: 'AWS Production',
    });

    let accounts = await vaultManager.getPublicAccounts();
    expect(accounts[0].issuer).toBe('AWS Production');

    await vaultManager.deleteAccount(added.id);
    accounts = await vaultManager.getPublicAccounts();
    expect(accounts.length).toBe(0);
  });

  it('retrieves full account details including secret when unlocked', async () => {
    await vaultManager.initVault(masterPassword);

    const added = await vaultManager.addAccount({
      issuer: 'GitHub',
      account: 'test@example.com',
      secret: 'JBSWY3DPEHPK3PXP',
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      type: 'totp',
    });

    const detailed = await vaultManager.getAccount(added.id);
    expect(detailed).not.toBeNull();
    expect(detailed?.id).toBe(added.id);
    expect(detailed?.issuer).toBe('GitHub');
    expect(detailed?.secret).toBe('JBSWY3DPEHPK3PXP');

    // Reject when locked
    await vaultManager.lockVault();
    await expect(vaultManager.getAccount(added.id)).rejects.toThrow('Vault is locked');
  });

  it('matches domain for inline autofill with precise ranking and multi-account support', async () => {
    await vaultManager.initVault(masterPassword);

    await vaultManager.addAccount({
      issuer: '1xbet/1713633405',
      account: '1713633405',
      secret: 'JBSWY3DPEHPK3PXP',
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      type: 'totp',
    });

    await vaultManager.addAccount({
      issuer: 'GitHub',
      account: 'Likhon545466',
      secret: 'JBSWY3DPEHPK3PXP',
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      type: 'totp',
    });

    await vaultManager.addAccount({
      issuer: 'Google',
      account: 'user1@gmail.com',
      secret: 'JBSWY3DPEHPK3PXP',
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      type: 'totp',
    });

    await vaultManager.addAccount({
      issuer: 'Google',
      account: 'user2@gmail.com',
      secret: 'JBSWY3DPEHPK3PXP',
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      type: 'totp',
    });

    // 1. Precise GitHub match (does NOT accidentally match 1xbet or Google)
    const githubMatch = await vaultManager.getCodeForDomain('github.com');
    expect(githubMatch).not.toBeNull();
    expect(githubMatch?.issuer).toBe('GitHub');
    expect(githubMatch?.account).toBe('Likhon545466');
    expect(githubMatch?.matched.length).toBe(1);
    expect(githubMatch?.code).toMatch(/^\d{6}$/);

    // 2. Google multi-account match on accounts.google.com
    const googleMatch = await vaultManager.getCodeForDomain('accounts.google.com');
    expect(googleMatch).not.toBeNull();
    expect(googleMatch?.issuer).toBe('Google');
    expect(googleMatch?.matched.length).toBe(2);
    expect(googleMatch?.matched.map((m) => m.account)).toEqual(['user1@gmail.com', 'user2@gmail.com']);

    // 3. Unmatched domain
    const unmatched = await vaultManager.getCodeForDomain('randomwebsite.org');
    expect(unmatched).toBeNull();
  });

  it('changes master password and re-encrypts vault with new salt', async () => {
    await vaultManager.initVault(masterPassword);

    await vaultManager.addAccount({
      issuer: 'Cloudflare',
      account: 'ops@cloudflare.com',
      secret: 'JBSWY3DPEHPK3PXP',
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      type: 'totp',
    });

    const oldRecord = (await storage.local.get('vault')).vault;

    const newPassword = 'BrandNewMasterPassword2026!';
    await vaultManager.changePassword(masterPassword, newPassword);

    const newRecord = (await storage.local.get('vault')).vault;
    // Salt, IV, and ciphertext must all be freshly generated
    expect(newRecord.salt).not.toBe(oldRecord.salt);
    expect(newRecord.iv).not.toBe(oldRecord.iv);
    expect(newRecord.ciphertext).not.toBe(oldRecord.ciphertext);

    // Verify lock and unlock with new password
    await vaultManager.lockVault();
    await expect(vaultManager.unlockVault(masterPassword)).rejects.toThrow();

    await vaultManager.unlockVault(newPassword);
    const accounts = await vaultManager.getPublicAccounts();
    expect(accounts.length).toBe(1);
    expect(accounts[0].issuer).toBe('Cloudflare');
  });

  it('exports encrypted backup and imports it', async () => {
    await vaultManager.initVault(masterPassword);

    await vaultManager.addAccount({
      issuer: 'Stripe',
      account: 'finance@stripe.com',
      secret: 'JBSWY3DPEHPK3PXP',
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      type: 'totp',
    });

    const backupJson = await vaultManager.exportVault(masterPassword);
    expect(backupJson).toContain('aegis-auth-backup-v1');
    expect(backupJson).not.toContain('JBSWY3DPEHPK3PXP'); // Must be encrypted!

    // Create a new vault in fresh storage
    const freshStorage = createMockStorage();
    const freshVault = new VaultManager(freshStorage);
    await freshVault.initVault('NewPassword999!');

    const { importedCount } = await freshVault.importVault(backupJson, masterPassword);
    expect(importedCount).toBe(1);

    const accounts = await freshVault.getPublicAccounts();
    expect(accounts.length).toBe(1);
    expect(accounts[0].issuer).toBe('Stripe');
  });

  it('restores decrypted session automatically from session storage', async () => {
    await vaultManager.initVault(masterPassword);
    await vaultManager.addAccount({
      issuer: 'GitHub',
      account: 'octo',
      secret: 'JBSWY3DPEHPK3PXP',
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      type: 'totp',
    });

    // Simulate service worker waking up with fresh instance pointing to same storage
    const newVaultInstance = new VaultManager(storage);
    expect(await newVaultInstance.isLocked()).toBe(false);

    const publicAccounts = await newVaultInstance.getPublicAccounts();
    expect(publicAccounts.length).toBe(1);
    expect(publicAccounts[0].issuer).toBe('GitHub');
  });

  it('handles getStatus and settings updates', async () => {
    let status = await vaultManager.getStatus();
    expect(status.isInitialized).toBe(false);
    expect(status.isLocked).toBe(true);
    expect(status.accountCount).toBe(0);

    await vaultManager.initVault(masterPassword);
    await vaultManager.addAccount({
      issuer: 'GitLab',
      account: 'alice',
      secret: 'JBSWY3DPEHPK3PXP',
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      type: 'totp',
    });

    status = await vaultManager.getStatus();
    expect(status.isInitialized).toBe(true);
    expect(status.isLocked).toBe(false);
    expect(status.accountCount).toBe(1);

    const updatedSettings = await vaultManager.updateSettings({
      autoLockMinutes: 15,
      theme: 'light',
    });
    expect(updatedSettings.autoLockMinutes).toBe(15);
    expect(updatedSettings.theme).toBe('light');

    const fetched = await vaultManager.getSettings();
    expect(fetched.autoLockMinutes).toBe(15);
  });

  it('imports raw account array or accounts object backup', async () => {
    await vaultManager.initVault(masterPassword);

    const rawArray = JSON.stringify([
      {
        issuer: 'Bitbucket',
        account: 'dev@bitbucket.org',
        secret: 'JBSWY3DPEHPK3PXP',
      },
    ]);

    const res = await vaultManager.importVault(rawArray);
    expect(res.importedCount).toBe(1);

    const accounts = await vaultManager.getPublicAccounts();
    expect(accounts.some((a) => a.issuer === 'Bitbucket')).toBe(true);
  });

  it('rejects invalid backup formats and missing password for encrypted backups', async () => {
    await vaultManager.initVault(masterPassword);

    await expect(vaultManager.importVault('invalid json')).rejects.toThrow('Unrecognized backup format');

    const encryptedWithoutPassword = JSON.stringify({
      format: 'aegis-auth-backup-v1',
      ciphertext: 'abc',
      salt: 'salt',
      iv: 'iv',
    });
    await expect(vaultManager.importVault(encryptedWithoutPassword)).rejects.toThrow(
      /password required/i
    );
  });

  it('supports togglePin, categories, nextCode, and sorts pinned accounts to the top', async () => {
    await vaultManager.initVault(masterPassword);

    const a1 = await vaultManager.addAccount({
      issuer: 'Alpha',
      account: 'alpha@test.com',
      secret: 'JBSWY3DPEHPK3PXP',
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      type: 'totp',
      category: 'Work',
    });

    const a2 = await vaultManager.addAccount({
      issuer: 'Beta',
      account: 'beta@test.com',
      secret: 'JBSWY3DPEHPK3PXP',
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      type: 'totp',
      category: 'Personal',
    });

    // Check nextCode exists
    expect(a1.nextCode).toBeTruthy();

    // Initially neither is pinned
    let list = await vaultManager.getPublicAccounts();
    expect(list[0].issuer).toBe('Alpha');
    expect(list[1].issuer).toBe('Beta');

    // Pin Beta
    const isPinned = await vaultManager.togglePin(a2.id);
    expect(isPinned).toBe(true);

    // Now Beta should be at index 0 because it is pinned
    list = await vaultManager.getPublicAccounts();
    expect(list[0].issuer).toBe('Beta');
    expect(list[0].pinned).toBe(true);
    expect(list[0].category).toBe('Personal');
    expect(list[1].issuer).toBe('Alpha');
    expect(list[1].pinned).toBe(false);
  });
});

