# Chrome Web Store Listing: Buffer Authenticator

## 1. Extension Information
- **Name:** Buffer Authenticator
- **Version:** 1.0.0
- **Category:** Developer Tools / Security & Privacy
- **Default Language:** English (en)
- **Short Description (max 132 chars):**
  Offline, privacy-first 2FA authenticator with AES-256-GCM encrypted vault, auto-lock protection, and seamless inline autofill.

---

## 2. Detailed Store Description

Buffer Authenticator is an offline, security-focused two-factor authentication (2FA) authenticator for your browser. It generates time-based one-time passwords (TOTP, RFC 6238) directly on your device without relying on external cloud servers, third-party sync, or mobile phones.

### Key Features
- **AES-256-GCM Vault Encryption:** All 2FA secrets are encrypted locally using authenticated AES-256-GCM encryption.
- **Industry-Standard Key Derivation:** Your master password derives the encryption key using PBKDF2-HMAC-SHA256 with 250,000 iterations and a cryptographically random 16-byte salt.
- **100% Offline & Private:** Zero external network calls, zero telemetry, and zero third-party tracking. All operations happen in-memory and in local storage.
- **Contextual Inline Autofill:** Automatically detects 2FA verification code input fields on login screens and provides a clean autofill chip.
- **Universal Import & Export:** Add accounts manually, paste `otpauth://` URIs, import directly from Aegis Authenticator Mobile (.json), 2FAS, or plain text (.txt) URI lists, and export AES-256-GCM encrypted backups.
- **Configurable Auto-Lock:** Vault automatically locks after a customizable period of idle inactivity or when your system screen locks.

---

## 3. Permissions Justification

| Permission | Plain-English Justification for Chrome Web Store Reviewers |
| :--- | :--- |
| `storage` | Required to store the AES-256-GCM encrypted vault record at rest in `chrome.storage.local` and maintain ephemeral session keys in `chrome.storage.session` while unlocked. |
| `activeTab` | Required to detect the active website domain context when the user clicks the inline autofill chip. |
| `alarms` | Required to run the periodic idle auto-lock timer to lock the vault when inactivity thresholds are reached. |
| `idle` | Required to detect operating system screen lock events to immediately lock the vault and purge decrypted session keys. |
| `scripting` | Required to inject the secure inline autofill helper into web page 2FA forms on user interaction. |

*Note: No broad permissions (such as `<all_urls>`, `tabs`, `cookies`, or `webRequest`) are requested.*

---

## 4. Privacy & Data Use Disclosures

- **Does this extension collect or transmit user data?** No.
- **Does this extension use remote code or external scripts?** No. All code is bundled locally.
- **Single Purpose Compliance:** The extension's sole purpose is local two-factor authentication code generation and autofill.

---

## 5. Version History
- **1.0.0 (2026-10-12):** Initial release featuring AES-256-GCM local vault, RFC 6238/4226 support, auto-lock policies, encrypted backup export/import, and Shadow DOM inline autofill chip.
