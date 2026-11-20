# 🔐 VAULT KEY — Futuristic Zero-Knowledge Digital Vault

**VAULT KEY** is a premium, client-side encrypted password manager and digital vault application with modern 3D graphics, real-time cryptographic operations, password generation, and zero-knowledge privacy.

---

## ✨ Features & Architecture

### 1. 🛡️ Real Zero-Knowledge Cryptography (Web Crypto API)
- **Key Derivation (PBKDF2)**: Derives an AES-GCM 256-bit encryption key using `PBKDF2`, `SHA-256`, a fresh 16-byte random salt, and 100,000 iterations.
- **Authenticated Encryption (AES-256-GCM)**: Galois/Counter Mode guarantees both confidentiality and ciphertext integrity. Every encryption generates a unique 12-byte initialization vector (IV).
- **Zero-Knowledge Principle**: The master password is never stored or sent across a network. Only the user's master key can decrypt the data in browser memory.
- **Canary Verifier**: Validates master password accuracy without storing the master key.
- **Auto-Lock Security**: Automatically zeroes out encryption keys and decrypted credentials from memory after 5 minutes of inactivity or upon clicking **Lock Vault**.

### 2. 🌀 Interactive 3D Vault Lock (Three.js)
- **3D Mechanical Safe Dial**: Rotating combination ring with metallic PBR materials, tick marks, and rim bolts.
- **Kinematic Unlock Animation**: Combination dial cycles through angles, retractable locking pins slide inward, and the core aperture shifts from neon cyan (`#00F0FF`) to glowing emerald (`#00FF9D`).
- **Interactive Parallax**: Reacts dynamically to mouse coordinates with smooth inertia.

### 3. 🔑 Cryptographic Password Engine & Analyzer
- **Entropy Generation**: Uses `window.crypto.getRandomValues()` with Fisher-Yates shuffling.
- **Customizable**: Configurable length (8 to 64 chars), character set toggles (uppercase, lowercase, numbers, symbols), and ambiguous character exclusion.
- **Shannon Entropy Calculation**: Computes exact bits of entropy.
- **Brute-Force Offline Estimator**: Realistic time-to-crack estimates based on a 100-billion hash/sec GPU cluster.
- **Live Password Auditor**: Interactive test field allowing users to test existing passwords.

### 4. 🗃️ Secure Vault Dashboard
- **Credential Categories**: Logins, Secure Notes & Recovery Phrases, Payment Cards, API Keys & Secrets, Favorites.
- **Real-Time Search & Filtering**: Instant filter across titles, usernames, URLs, and tags.
- **Masked Password Field**: One-click reveal toggle (`eye`/`eye-off`) and 1-click clipboard copy with auto-clear toasts.
- **Audit Health Indicator**: Live detection of weak or reused passwords across stored entries.
- **Backup & Restore**: Export encrypted JSON backups and import them on other machines.

### 5. ⏱️ 2FA Authenticator Simulator
- Simulated rotating TOTP 6-digit codes with a 30-second circular countdown timer ring.

---

## 🚀 How to Run the Website

### Direct Browser Launch (No Node.js or Setup Required):
Simply double-click `index.html` or open it with any modern web browser:
- Google Chrome
- Microsoft Edge
- Mozilla Firefox
- Brave / Safari

### Local Development Server (Optional):
If you have any local HTTP server:
```bash
# Using Python (if installed)
python -m http.server 3000

# Using Node http-server or npx (if installed)
npx serve .
```

---

## 🎨 Color Palette & Design System
- **Midnight Blue**: `#080D19`
- **Royal Deep Purple**: `#111020`
- **Cyber Cyan**: `#00F0FF`
- **Cyber Emerald**: `#00FF9D`
- **Electric Violet**: `#8A2BE2`
- **Glassmorphism**: 16px backdrop blur with translucent borders (`rgba(255, 255, 255, 0.08)`)

---

## 📂 Project Structure
```
vault-key/
├── index.html            # Main semantic markup, sections, modals
├── README.md             # Documentation & cryptographic guide
├── css/
│   └── styles.css        # Cyberpunk & glassmorphism theme, layout & animations
└── js/
    ├── crypto-vault.js   # Web Crypto API zero-knowledge engine (PBKDF2 + AES-GCM)
    ├── generator.js      # Password generation, entropy, and crack time analysis
    ├── vault-3d.js       # Three.js 3D mechanical safe dial & animation
    └── app.js            # App controller, audio FX, dashboard CRUD, TOTP simulator
```
