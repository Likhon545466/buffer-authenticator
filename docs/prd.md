# Product Requirements Document (PRD)

## Product Name: Buffer Authenticator (Secure TOTP Authenticator)

### 1. Problem Statement
Users need a secure, offline, privacy-first way to generate TOTP (RFC 6238) codes directly in the browser without relying on cloud services, external servers, or mobile devices. Existing browser solutions frequently suffer from poor encryption, remote telemetry, or lack seamless autofill integration.

### 2. Target Users
- Security-conscious individuals
- Software engineers and DevOps professionals
- Enterprise users needing local-only 2FA with zero data exfiltration risks

### 3. Core Features (MVP)
1. **Encrypted Vault at Rest:**
   - AES-256-GCM encryption.
   - Master password key derivation via PBKDF2-HMAC-SHA256 (≥250,000 iterations, 16-byte random salt).
   - Stored in `chrome.storage.local`.
   - Ephemeral session key in `chrome.storage.session` (cleared immediately on lock).

2. **RFC 6238 / RFC 4226 Compliance:**
   - Generates 6- or 8-digit codes every 30 seconds (configurable interval & digit count).
   - SHA1, SHA256, and SHA512 HMAC algorithms supported.
   - Real-time countdown timer with visual progress indicator.

3. **Account Management & Import/Export:**
   - Manual entry (secret, account/issuer, algorithm, digits, period).
   - `otpauth://` URI parsing and import.
   - Universal backup import supporting Aegis Authenticator Mobile JSON (both plaintext and password-encrypted), AegisAuth backups, and Plain Text (`.txt`) URI/key lists.
   - Direct text paste box or file upload for `.json` and `.txt` backups.
   - Encrypted backup export and restoration with master password authentication.

4. **Contextual Inline Autofill:**
   - Content script detects 2FA / OTP input fields on web pages (`autocomplete="one-time-code"`, OTP input types, numeric patterns).
   - Renders an inline autofill chip in Shadow DOM.
   - Communicates domain to background service worker to fetch matching code on user click.
   - Secrets are never exposed to content scripts.

5. **Auto-Lock Security:**
   - Configurable idle timeout (e.g., 1 min, 5 min, 15 min, 30 min, or on browser close).
   - Integration with `chrome.alarms` and `chrome.idle` for OS lock screen detection.
   - Instant manual vault lock.

6. **Zero Telemetry & Offline Guarantee:**
   - No external network calls (`fetch`, `XMLHttpRequest`, WebSockets, WebRTC).
   - Strictly client-side operations.
   - All assets bundled locally.

### 4. Non-Goals
- Cloud backup or multi-device sync in v1.
- General password management.
- Support for Manifest V2.
