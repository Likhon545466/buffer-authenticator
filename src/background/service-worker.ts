/**
 * Background Service Worker for Buffer Authenticator
 *
 * Responsibilities:
 * - Sole surface that decrypts the vault, holds in-memory CryptoKey, and generates TOTP codes.
 * - Handles auto-lock via chrome.alarms and screen lock via chrome.idle.
 * - Validates message senders and ensures no raw secrets ever leak to content scripts or UI.
 * - Full offline operation: zero external network requests.
 */

import { VaultManager } from '../vault/vault-manager';
import type { MessageRequest, MessageResponse } from '../types';

const vaultManager = new VaultManager();

// Ephemeral activity tracking in session storage
const AUTO_LOCK_ALARM_NAME = 'buffer_auto_lock_alarm';

/**
 * Schedule or refresh auto-lock timer only when vault is actively unlocked.
 * When locked, clears all alarms so the Service Worker can completely hibernate and use 0 RAM.
 */
async function scheduleAutoLock(): Promise<void> {
  const isLocked = await vaultManager.isLocked();
  if (isLocked) {
    await chrome.alarms.clear(AUTO_LOCK_ALARM_NAME);
    return;
  }

  const settings = await vaultManager.getSettings();
  const minutes = settings.autoLockMinutes ?? 5;
  if (minutes <= 0) {
    await chrome.alarms.clear(AUTO_LOCK_ALARM_NAME);
    return;
  }

  // Set timestamp and schedule one-shot alarm for exact expiry duration
  await chrome.storage.session.set({ lastActivity: Date.now() });
  chrome.alarms.create(AUTO_LOCK_ALARM_NAME, { delayInMinutes: minutes });
}

/**
 * Handle auto-lock alarm trigger
 */
async function checkAutoLock(): Promise<void> {
  const isLocked = await vaultManager.isLocked();
  if (isLocked) {
    await chrome.alarms.clear(AUTO_LOCK_ALARM_NAME);
    return;
  }

  const settings = await vaultManager.getSettings();
  if (!settings.autoLockMinutes || settings.autoLockMinutes <= 0) {
    await chrome.alarms.clear(AUTO_LOCK_ALARM_NAME);
    return;
  }

  const res = await chrome.storage.session.get('lastActivity');
  const lastActivity = (res.lastActivity as number) || 0;
  const idleMs = Date.now() - lastActivity;
  const thresholdMs = settings.autoLockMinutes * 60 * 1000;

  if (idleMs >= thresholdMs) {
    await vaultManager.lockVault();
    await chrome.alarms.clear(AUTO_LOCK_ALARM_NAME);
    try {
      await chrome.action.setBadgeText({ text: '🔒' });
      await chrome.action.setBadgeBackgroundColor({ color: '#ef4444' });
    } catch {
      // Ignored if action API unavailable
    }
  } else {
    // Re-schedule for remaining time
    const remainingMinutes = Math.max(0.5, (thresholdMs - idleMs) / 60000);
    chrome.alarms.create(AUTO_LOCK_ALARM_NAME, { delayInMinutes: remainingMinutes });
  }
}

// Alarm listener
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === AUTO_LOCK_ALARM_NAME) {
    await checkAutoLock();
  }
});

// Setup idle listener for system/OS screen lock
chrome.idle.onStateChanged.addListener(async (newState) => {
  if (newState === 'locked') {
    const settings = await vaultManager.getSettings();
    if (settings.lockOnIdle) {
      await vaultManager.lockVault();
      await chrome.alarms.clear(AUTO_LOCK_ALARM_NAME);
      try {
        await chrome.action.setBadgeText({ text: '🔒' });
        await chrome.action.setBadgeBackgroundColor({ color: '#ef4444' });
      } catch {
        // Ignored
      }
    }
  }
});

// Setup lifecycle listeners
chrome.runtime.onInstalled.addListener(async () => {
  const isLocked = await vaultManager.isLocked();
  if (!isLocked) {
    await scheduleAutoLock();
  } else {
    await chrome.alarms.clear(AUTO_LOCK_ALARM_NAME);
  }
});

/**
 * External message listener with strict sender whitelist
 */
const EXTENSION_ID_WHITELIST = new Set<string>([
  // Any approved enterprise extension IDs can be placed here
]);

chrome.runtime.onMessageExternal.addListener((_message, sender, sendResponse) => {
  if (!sender.id || !EXTENSION_ID_WHITELIST.has(sender.id)) {
    sendResponse({ success: false, error: 'Unauthorized external sender' });
    return false;
  }
  // If whitelisted in future, process here
  sendResponse({ success: false, error: 'External messages currently disabled' });
  return false;
});

/**
 * Internal message router
 */
chrome.runtime.onMessage.addListener((message: MessageRequest, _sender, sendResponse) => {
  // Async handling wrapper
  (async () => {
    try {
      // Touch activity if unlocked
      scheduleAutoLock().catch(() => {});

      switch (message.type) {
        case 'GET_STATUS': {
          const status = await vaultManager.getStatus();
          sendResponse({ success: true, data: status });
          break;
        }

        case 'INIT_VAULT': {
          await vaultManager.initVault(message.payload.password);
          await chrome.action.setBadgeText({ text: '' });
          await scheduleAutoLock();
          const status = await vaultManager.getStatus();
          sendResponse({ success: true, data: status });
          break;
        }

        case 'UNLOCK_VAULT': {
          await vaultManager.unlockVault(message.payload.password);
          await chrome.action.setBadgeText({ text: '' });
          await scheduleAutoLock();
          const status = await vaultManager.getStatus();
          sendResponse({ success: true, data: status });
          break;
        }

        case 'LOCK_VAULT': {
          await vaultManager.lockVault();
          await chrome.alarms.clear(AUTO_LOCK_ALARM_NAME);
          try {
            await chrome.action.setBadgeText({ text: '🔒' });
            await chrome.action.setBadgeBackgroundColor({ color: '#ef4444' });
          } catch {
            // Ignored
          }
          const status = await vaultManager.getStatus();
          sendResponse({ success: true, data: status });
          break;
        }

        case 'GET_ACCOUNTS': {
          const accounts = await vaultManager.getPublicAccounts();
          sendResponse({ success: true, data: accounts });
          break;
        }

        case 'ADD_ACCOUNT': {
          const newAccount = await vaultManager.addAccount(message.payload);
          sendResponse({ success: true, data: newAccount });
          break;
        }

        case 'UPDATE_ACCOUNT': {
          const { id, ...updates } = message.payload;
          await vaultManager.updateAccount(id, updates);
          sendResponse({ success: true });
          break;
        }

        case 'GET_ACCOUNT_DETAIL': {
          const account = await vaultManager.getAccount(message.payload.id);
          if (!account) {
            sendResponse({ success: false, error: 'Account not found' });
          } else {
            sendResponse({ success: true, data: account });
          }
          break;
        }

        case 'DELETE_ACCOUNT': {
          await vaultManager.deleteAccount(message.payload.id);
          sendResponse({ success: true });
          break;
        }

        case 'TOGGLE_PIN': {
          const isPinned = await vaultManager.togglePin(message.payload.id);
          sendResponse({ success: true, data: { isPinned } });
          break;
        }

        case 'GET_CODE_FOR_DOMAIN': {
          const match = await vaultManager.getCodeForDomain(message.payload.domain);
          sendResponse({ success: true, data: match });
          break;
        }

        case 'UPDATE_SETTINGS': {
          const updated = await vaultManager.updateSettings(message.payload);
          await scheduleAutoLock();
          sendResponse({ success: true, data: updated });
          break;
        }

        case 'CHANGE_PASSWORD': {
          await vaultManager.changePassword(
            message.payload.currentPassword,
            message.payload.newPassword
          );
          sendResponse({ success: true });
          break;
        }

        case 'EXPORT_VAULT': {
          const backupJson = await vaultManager.exportVault(message.payload.password);
          sendResponse({ success: true, data: backupJson });
          break;
        }

        case 'IMPORT_VAULT': {
          const result = await vaultManager.importVault(
            message.payload.data,
            message.payload.password
          );
          sendResponse({ success: true, data: result });
          break;
        }

        default: {
          sendResponse({ success: false, error: 'Unknown message type' });
          break;
        }
      }
    } catch (err: any) {
      sendResponse({
        success: false,
        error: err?.message || 'An unexpected error occurred in background service worker',
      } as MessageResponse);
    }
  })();

  return true; // Keep message channel open for asynchronous sendResponse
});
