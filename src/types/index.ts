/**
 * Core Type Definitions for Buffer Authenticator TOTP Authenticator
 */

export type HashAlgorithm = 'SHA1' | 'SHA256' | 'SHA512';
export type OTPType = 'totp' | 'hotp';

export interface TOTPAccount {
  id: string;
  issuer: string;
  account: string;
  secret: string; // Base32 encoded string
  algorithm: HashAlgorithm;
  digits: number;
  period: number;
  type: OTPType;
  counter?: number;
  pinned?: boolean;
  category?: string;
  createdAt: number;
  updatedAt: number;
}

export interface DecryptedVault {
  version: number;
  accounts: TOTPAccount[];
  updatedAt: number;
}

export interface EncryptedVaultRecord {
  ciphertext: string; // Base64
  salt: string;       // Base64 (16 bytes random salt for PBKDF2)
  iv: string;         // Base64 (12 bytes random IV for AES-GCM)
}

export interface PublicAccount {
  id: string;
  issuer: string;
  account: string;
  digits: number;
  period: number;
  code: string;
  nextCode?: string;
  secondsRemaining: number;
  type: OTPType;
  pinned?: boolean;
  category?: string;
  createdAt?: number;
}

export interface VaultSettings {
  autoLockMinutes: number; // e.g. 1, 5, 15, 30, 0 (never)
  lockOnIdle: boolean;
  theme: 'dark' | 'light' | 'system';
  clipboardClearSeconds: number; // e.g. 30, 60, 0 (never)
  biometricEnabled?: boolean;
}

export interface VaultStatus {
  isInitialized: boolean;
  isLocked: boolean;
  accountCount: number;
  settings: VaultSettings;
}

export type MessageRequest =
  | { type: 'GET_STATUS' }
  | { type: 'INIT_VAULT'; payload: { password: string } }
  | { type: 'UNLOCK_VAULT'; payload: { password: string } }
  | { type: 'LOCK_VAULT' }
  | { type: 'GET_ACCOUNTS' }
  | { type: 'ADD_ACCOUNT'; payload: Omit<TOTPAccount, 'id' | 'createdAt' | 'updatedAt'> }
  | { type: 'UPDATE_ACCOUNT'; payload: { id: string } & Partial<Omit<TOTPAccount, 'id' | 'createdAt'>> }
  | { type: 'DELETE_ACCOUNT'; payload: { id: string } }
  | { type: 'TOGGLE_PIN'; payload: { id: string } }
  | { type: 'GET_CODE_FOR_DOMAIN'; payload: { domain: string } }
  | { type: 'UPDATE_SETTINGS'; payload: Partial<VaultSettings> }
  | { type: 'GET_ACCOUNT_DETAIL'; payload: { id: string } }
  | { type: 'CHANGE_PASSWORD'; payload: { currentPassword: string; newPassword: string } }
  | { type: 'EXPORT_VAULT'; payload: { password: string } }
  | { type: 'IMPORT_VAULT'; payload: { data: string; password?: string } };

export interface MessageResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
}
