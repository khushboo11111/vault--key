# VaultKey – Secure Personal Password Manager

> **Zero-Knowledge, Client-Side Encrypted Personal Password & Credential Vault**  
> Built with HTML5, CSS3, Vanilla JavaScript, and the W3C Web Crypto API.

---

## 1. Overview & Architecture Philosophy

**VaultKey** is a personal password manager engineered with a strict **Zero-Knowledge Architecture**. Sensitive records—including passwords, usernames, URLs, notes, and metadata—are encrypted locally in your browser using authenticated **AES-256-GCM** before touching persistent storage.

### Core Tenets
1. **Never Plaintext at Rest**: No password, note, or credential is ever stored in plaintext.
2. **Never Stored in Storage**: The Master Password and raw derived encryption keys are **never** stored in `localStorage`, cookies, or persistent database fields.
3. **In-Memory Ephemeral Session**: When unlocked, the master key exists solely as an unextractable `CryptoKey` in JavaScript heap memory and is immediately evicted upon locking, inactivity timeout, or browser closure.
4. **Standard Cryptography**: Exclusively relies on standard, non-proprietary W3C Web Crypto API algorithms (`PBKDF2`, `HMAC-SHA-256`, `AES-GCM`).

---

## 2. Cryptographic Security Architecture

```
[ Master Password ]
        │
        ▼ (PBKDF2-HMAC-SHA-256, 310,000 iterations, 16-byte random salt)
[ 256-bit AES-GCM Master Key ] (Held only in RAM as CryptoKey)
        │
        ├─► Decrypts Canary Token (Verifies Master Password validity)
        │
        ├─► For each Vault Item:
        │     ├─► Generates fresh 96-bit CSPRNG IV
        │     └─► AES-256-GCM Encrypt(Payload, IV) ──► Stored in IndexedDB
        │
        └─► On Auto-Lock / Manual Lock / Inactivity:
              └─► Master Key & Decrypted Array wiped from RAM
```

### A. Key Derivation (PBKDF2-SHA-256)
- **Algorithm**: PBKDF2 with HMAC-SHA-256.
- **Iterations**: `310,000` iterations (meeting OWASP and NIST password-storage recommendations to defend against brute-force and GPU/FPGA dictionary attacks).
- **Salt**: 16 cryptographically secure random bytes generated via `crypto.getRandomValues(new Uint8Array(16))`.

### B. Authenticated Vault Encryption (AES-256-GCM)
- **Algorithm**: AES-GCM (Galois/Counter Mode) with 256-bit key length.
- **Initialization Vector (IV)**: A unique, fresh 96-bit (12-byte) random IV is generated for **every single encryption operation** (`crypto.getRandomValues(new Uint8Array(12))`). IV reuse is strictly prohibited.
- **Integrity & Authenticity**: AES-GCM generates a 128-bit authentication tag. Any unauthorized bit modification or data corruption in storage triggers a decryption failure (`OperationError`), preventing ciphertext tampering.

### C. Zero-Knowledge Verification Canary
To verify the master password without saving it or hashing it into an insecure lookup table:
- A canary token payload (`{"canary":"VAULTKEY_AUTH_OK"}`) is encrypted using the master key.
- Upon login, the client attempts to decrypt this canary with the derived candidate key.
- If the authentication tag matches and decryption succeeds, the master password is authenticated.
- If decryption fails, the candidate key is wrong. Neither the password nor the key is ever transmitted or stored.

### D. Cryptographic Recovery Architecture
Zero-knowledge applications cannot offer an "email my password" link. VaultKey provides a **Cryptographic Emergency Sheet / Recovery Key**:
- A 32-character high-entropy Base32 recovery key is generated at vault creation (`VK-XXXX-XXXX-XXXX-XXXX`).
- An independent cryptographic key is derived from the recovery key with an independent salt.
- An emergency canary verifies recovery key validity.
- The user can restore their vault and establish a new master passphrase without creating backdoors.

---

## 3. Threat Model & Security Controls

| Threat | VaultKey Defense |
|---|---|
| **Storage snooping / Local file inspection** | IndexedDB holds only ciphertext and random IVs. Plaintext is inaccessible without the master passphrase. |
| **XSS token stealing** | No credentials or keys are written to `localStorage` or `sessionStorage`. Keys are non-extractable CryptoKey references. |
| **Tampered ciphertexts** | Authenticated encryption (AES-256-GCM) detects bit manipulation via Galois message authentication tags. |
| **Device left unattended** | Configurable auto-lock timer (default 5 minutes) evicts the encryption key from RAM on idle. |
| **Clipboard scraping** | Configurable clipboard auto-clear (15s, 30s, 60s) clears copied credentials from the OS clipboard. |
| **Master password change** | Atomic re-encryption: decrypts memory records, generates a new salt, derives a new key, re-encrypts all items, and commits to IndexedDB. |

---

## 4. Production Roadmap: Client vs Production-Ready Backend

VaultKey is implemented as a standalone, zero-knowledge browser-based manager. In a full production SaaS deployment across mobile, desktop, and web, the following architecture applies:

| Component | Client-Side Demo / Local (Current) | Production Cloud Architecture |
|---|---|---|
| **Encryption** | Client-Side (AES-256-GCM + PBKDF2) | Client-Side (Zero-Knowledge, keys never leave client device) |
| **Storage at Rest** | Local IndexedDB | Encrypted Cloud Database (PostgreSQL / DynamoDB) storing encrypted blobs |
| **Syncing** | Manual JSON export / import | Conflict-free Replicated Data Types (CRDTs) or WebSockets with encrypted delta sync |
| **Authentication** | Local Canary Decryption | SRP-6a (Secure Remote Password) or OPAQUE protocol + Argon2id |
| **Multi-Factor Auth** | Emergency Sheet | FIDO2 / WebAuthn Hardware Keys (YubiKey) + TOTP |
| **Transport** | Browser Sandbox | TLS 1.3 with strict HSTS, Certificate Pinning, CSP Headers |

---

## 5. Feature Highlights

- **Visual Dashboard**:
  - Total credentials, favorites, secure notes, and security health score.
  - Recent vault activity with 1-click username/password copy.
  - Quick action links and one-click item creation.
- **Vault Management**:
  - Instant live search (press `/` anywhere).
  - Category filters: *Social Media, Email, Banking, Shopping, Education, Entertainment, Wi-Fi, Other*.
  - Star / unstar favorites.
  - Masked password display with toggle reveal.
  - Grid view and Table/List view toggles.
- **CSPRNG Password Generator**:
  - Custom length slider (8 to 64 characters).
  - Toggles for Uppercase, Lowercase, Numbers, Symbols, Avoid Ambiguous characters.
  - Presets for PINs, Standard, Strong, and Max Defense (64-char).
  - Real-time Shannon entropy calculation and estimated crack-time gauge.
- **Security Health & Vulnerability Audit**:
  - Automatic detection of weak passwords (< 12 characters or low entropy).
  - Reused password detection across multiple accounts.
  - Vault health scoring (0–100%) with direct remediation actions.
- **Settings & Portability**:
  - Re-encrypt vault on Master Password change.
  - Configurable inactivity auto-lock (1m, 5m, 15m, 30m, 1h, Never).
  - Configurable clipboard auto-clear timeout.
  - Export encrypted backup (`.json`) with PBKDF2 salt and metadata.
  - Import encrypted or unencrypted vault backups.
  - Download printable HTML Emergency Kit.
  - Light and Dark Mode toggle with preference persistence.

---

## 6. Project File Structure

```
vaultkey/
├── index.html        # Clean semantic HTML5 layout & accessible modals
├── style.css         # Dark navy & purple design system, light/dark mode, CSS variables
├── script.js         # Web Crypto API engine, IndexedDB operations, audit scanner, UI
└── README.md         # Comprehensive security documentation & architecture guide
```

---

## 7. How to Run VaultKey

Because VaultKey utilizes the standard **Web Crypto API** (`window.crypto.subtle`), modern browsers require a **Secure Context** (`https://`, `http://localhost`, or `file://` in Chrome/Firefox/Edge).

### Option A: Open directly in your browser
Simply double-click `index.html` or drag it into any modern web browser (Chrome, Edge, Firefox, Brave, Safari).

### Option B: Run via a local static server

#### Using Python 3:
```bash
cd C:\Users\a\.gemini\antigravity\scratch\vaultkey
python -m http.server 8080
```
Open [http://localhost:8080](http://localhost:8080) in your browser.

#### Using Node.js:
```bash
npx serve C:\Users\a\.gemini\antigravity\scratch\vaultkey
```

---

## 8. Keyboard Shortcuts

- `Ctrl + L` / `Cmd + L` — Lock Vault immediately
- `/` — Focus universal live search bar
- `Escape` — Close active modal dialog

---

## 9. Security Statement

VaultKey uses standard cryptographic primitives provided directly by your operating system and browser engine through the W3C Web Crypto standard. No external tracking scripts, CDNs, or advertising beacons are loaded. All encryption keys remain exclusively on your device.
