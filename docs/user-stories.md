# User Stories

### US-01: Vault Initialization
**As a** new user,  
**I want to** set a master password upon first opening the extension,  
**So that** my TOTP secrets are securely encrypted with high-iteration PBKDF2 and AES-256-GCM.

### US-02: Account Addition
**As a** user,  
**I want to** add a 2FA account either by manually pasting the secret or by entering an `otpauth://` URI,  
**So that** I can generate codes for my accounts.

### US-03: View & Copy TOTP Codes
**As a** user,  
**I want to** view my accounts with remaining seconds and copy the current 6/8-digit code in one click,  
**So that** I can authenticate quickly into websites.

### US-04: Inline Autofill
**As a** user browsing a website with a 2FA prompt,  
**I want to** see an autofill chip next to the OTP input field that fills the current code when clicked,  
**So that** I don't need to manually open the popup and copy-paste.

### US-05: Vault Locking & Auto-Lock
**As a** security-conscious user,  
**I want** the vault to automatically lock after 5 minutes of inactivity or when my screen locks,  
**So that** unauthorized persons using my browser cannot access my 2FA codes.

### US-06: Encrypted Backup & Restore
**As a** user,  
**I want to** export an encrypted JSON backup of my vault and restore it later,  
**So that** I don't lose access to my 2FA secrets if I reinstall the extension.

### US-07: Aegis Mobile & TXT Backup Import
**As a** user migrating from Aegis Authenticator mobile or an external 2FA app,  
**I want to** import an Aegis JSON export or a plain text (.txt) file containing otpauth URIs,  
**So that** all my accounts are recognized and restored seamlessly without manual re-entry.
