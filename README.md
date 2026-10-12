# Buffer Authenticator

[![CI Build & Security Audit](https://github.com/Likhon545466/buffer-authenticator/actions/workflows/build.yml/badge.svg)](https://github.com/Likhon545466/buffer-authenticator/actions/workflows/build.yml)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Manifest V3](https://img.shields.io/badge/Manifest-V3-success.svg)](manifest.json)
[![Security: AES--256--GCM](https://img.shields.io/badge/Vault-AES--256--GCM-green.svg)](docs/security-audit.md)
[![Zero Network Calls](https://img.shields.io/badge/Telemetry-None%20(100%25%20Offline)-brightgreen.svg)](docs/security-audit.md)

**Buffer Authenticator** is a modern, privacy-first, 100% offline two-factor authentication (2FA) Chrome extension designed with Google Material 3 aesthetics and uncompromising security.

---

## ✨ Features

- 🔒 **Authenticated Vault Encryption**: All 2FA secrets are encrypted locally with **AES-256-GCM** using keys derived via **PBKDF2-HMAC-SHA256** (250,000 iterations + cryptographically random 16-byte salt).
- 🛡️ **100% Offline & Zero Telemetry**: Zero external network requests, zero tracking scripts, and zero cloud storage. No `<all_urls>` permission requested.
- 🎨 **Material 3 Dark UI**: Sleek, responsive interface with instant search, category filtering (*General*, *Work*, *Personal*, *Finance*, *Social*), and top-pinning for frequent accounts.
- ⏱️ **Minimal Progress Bar Chips**: Elegant OTP chips featuring an integrated countdown progress bar that seamlessly warns at 10s and 5s without cluttering the screen.
- 📷 **Built-in QR Code Scanner**: Add 2FA accounts instantly by scanning QR codes directly from the active tab or dragging & dropping image files.
- 🔄 **Universal Import & Export**:
  - Supports **Aegis Authenticator** (both encrypted and plaintext JSON backups).
  - Supports **Google Authenticator** (`otpauth-migration://` QR exports).
  - Supports **2FAS**, **Bitwarden**, and standard `otpauth://` URI lists.
  - Export password-protected encrypted backups anytime.
- ⚡ **Contextual Inline Autofill**: Detects 2FA verification inputs on login forms and provides a secure, one-click autofill chip.
- ⏳ **Configurable Auto-Lock**: Automatically locks the vault after customizable periods of inactivity or when the operating system screen locks.

---

## 🚀 Quick Installation

### Option 1: Load Pre-built Extension (Fastest)

1. Download or clone this repository:
   ```bash
   git clone https://github.com/Likhon545466/buffer-authenticator.git
   ```
2. Unpack the included [`buffer-authenticator.zip`](./buffer-authenticator.zip) or use the repository directory after building.
3. Open Google Chrome (or any Chromium browser like Brave, Edge, Opera) and navigate to:
   ```text
   chrome://extensions/
   ```
4. Enable **Developer mode** in the top-right corner.
5. Click **Load unpacked** and select the extracted extension folder (or the `dist/` directory after running `npm run build`).

---

## 🛠️ Development & Building from Source

### Prerequisites
- [Node.js](https://nodejs.org/) v20+ or v22+
- `npm`

### Setup

```bash
# Clone the repository
git clone https://github.com/Likhon545466/buffer-authenticator.git
cd buffer-authenticator

# Install dependencies
npm install

# Run automated test suite (44 unit & security checklist tests)
npm test

# Build production bundle (outputs to dist/)
npm run build

# Package into shareable zip
npm run export
```

---

## 🧪 Security & Verification

Buffer Authenticator is rigorously verified with automated tests covering cryptographic primitives and security boundaries:

```bash
npm run test:coverage
```

- **RFC 6238 (TOTP) & RFC 4226 (HOTP)**: Verified against official RFC test vectors.
- **RFC 7914 (Scrypt)**: Verified against RFC 7914 test vectors.
- **WebCrypto AES-GCM**: Verified against authenticated encryption and tamper detection tests.
- **Aegis / Google Auth Migration Parsers**: Verified against encrypted and protobuf migration payloads.

See [docs/security-audit.md](docs/security-audit.md) for full architecture and threat model analysis.

---

## 📜 Permissions Breakdown

| Permission | Justification |
| :--- | :--- |
| `storage` | Stores the AES-256-GCM encrypted vault in local storage and ephemeral session keys in memory while unlocked. |
| `activeTab` | Allows domain detection and scanning QR codes from the active browser tab upon user action. |
| `alarms` | Drives the background idle auto-lock countdown timer. |
| `idle` | Detects screen locking events to immediately wipe in-memory keys and lock the vault. |
| `scripting` | Injects the inline autofill badge into 2FA code input fields when interacting with web forms. |

---

## 📄 License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
