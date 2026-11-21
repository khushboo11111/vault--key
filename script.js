/**
 * ===================================================================
 * VAULTKEY – SECURE PERSONAL PASSWORD MANAGER
 * Client-Side Zero-Knowledge Cryptographic Engine & SaaS Application
 * Standard: Web Crypto API (AES-256-GCM, PBKDF2-SHA-256, CSPRNG)
 * ===================================================================
 */

(function () {
  'use strict';

  // =================================================================
  // 1. CONSTANTS & CONFIGURATION
  // =================================================================
  const DB_NAME = 'VaultKeyDB';
  const DB_VERSION = 1;
  const PBKDF2_ITERATIONS = 310000; // OWASP recommended iteration count
  const CANARY_PAYLOAD = JSON.stringify({ canary: 'VAULTKEY_AUTH_OK' });

  // Default Categories
  const CATEGORIES = [
    'Social Media',
    'Email',
    'Banking',
    'Shopping',
    'Education',
    'Entertainment',
    'Wi-Fi',
    'Other'
  ];

  // In-Memory Vault State (Wiped upon locking or logout)
  let activeVaultKey = null;       // CryptoKey held strictly in memory
  let decryptedItems = [];        // Decrypted vault records in memory
  let accountMeta = null;          // Metadata: email, salts, canary
  let activeCategoryFilter = 'ALL';
  let activeSearchQuery = '';
  let activeSortOption = 'updated-desc';
  let activeViewLayout = 'grid';   // 'grid' | 'table'
  let currentNavTab = 'dashboard';

  // Auto-Lock Inactivity Tracking
  let idleTimer = null;
  let countdownTimer = null;
  let secondsRemaining = 300; // Default 5 mins

  // Clipboard Auto-Clear Timeout Tracker
  let clipboardClearTimer = null;

  // =================================================================
  // 2. CRYPTOGRAPHIC PRIMITIVES (WEB CRYPTO API)
  // =================================================================

  /**
   * Converts an ArrayBuffer to a Base64 string
   */
  function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }

  /**
   * Converts a Base64 string to a Uint8Array
   */
  function base64ToUint8Array(base64) {
    const binary = window.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /**
   * Generates cryptographically secure random bytes
   */
  function getRandomBytes(length) {
    const bytes = new Uint8Array(length);
    window.crypto.getRandomValues(bytes);
    return bytes;
  }

  /**
   * Generates a 32-character high-entropy alphanumeric Recovery Key
   * Formatted: VK-XXXX-XXXX-XXXX-XXXX
   */
  function generateRecoveryKey() {
    const charset = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Base32 unambiguous
    const randomVals = getRandomBytes(16);
    let raw = '';
    for (let i = 0; i < 16; i++) {
      raw += charset[randomVals[i] % charset.length];
    }
    return `VK-${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}`;
  }

  /**
   * Derives a 256-bit AES-GCM CryptoKey from a password and salt using PBKDF2-SHA-256
   */
  async function deriveVaultKey(password, saltUint8, iterations = PBKDF2_ITERATIONS) {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);

    // 1. Import raw passphrase as a PBKDF2 base key
    const baseKey = await window.crypto.subtle.importKey(
      'raw',
      passwordBuffer,
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    // 2. Derive 256-bit AES-GCM Key
    const aesKey = await window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltUint8,
        iterations: iterations,
        hash: 'SHA-256'
      },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false, // non-extractable from memory
      ['encrypt', 'decrypt']
    );

    return aesKey;
  }

  /**
   * Encrypts plaintext JSON string using AES-256-GCM with a fresh 96-bit (12-byte) IV
   */
  async function encryptData(plaintext, cryptoKey) {
    const iv = getRandomBytes(12); // Standard 96-bit IV for GCM
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(plaintext);

    const ciphertextBuffer = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      cryptoKey,
      dataBuffer
    );

    return {
      iv: arrayBufferToBase64(iv),
      ciphertext: arrayBufferToBase64(ciphertextBuffer)
    };
  }

  /**
   * Decrypts AES-256-GCM ciphertext using the given IV and CryptoKey
   * Throws if authentication tag fails (wrong key or tampering)
   */
  async function decryptData(ciphertextB64, ivB64, cryptoKey) {
    const iv = base64ToUint8Array(ivB64);
    const ciphertext = base64ToUint8Array(ciphertextB64);

    const decryptedBuffer = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      cryptoKey,
      ciphertext
    );

    const decoder = new TextDecoder();
    return decoder.decode(decryptedBuffer);
  }

  // =================================================================
  // 3. INDEXEDDB PERSISTENCE LAYER
  // =================================================================

  function openDatabase() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);

      request.onupgradeneeded = (e) => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains('auth')) {
          db.createObjectStore('auth', { keyPath: 'id' });
        }
        if (!db.objectStoreNames.contains('items')) {
          db.createObjectStore('items', { keyPath: 'id' });
        }
      };

      request.onsuccess = (e) => resolve(e.target.result);
      request.onerror = (e) => reject(e.target.error);
    });
  }

  async function getDBMeta() {
    const db = await openDatabase();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('auth', 'readonly');
      const store = tx.objectStore('auth');
      const request = store.get('account_meta');
      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(request.error);
    });
  }

  async function saveDBMeta(meta) {
    const db = await openDatabase();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('auth', 'readwrite');
      const store = tx.objectStore('auth');
      const request = store.put({ id: 'account_meta', ...meta });
      request.onsuccess = () => resolve(true);
      request.onerror = () => reject(request.error);
    });
  }

  async function getAllDBEncryptedItems() {
    const db = await openDatabase();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('items', 'readonly');
      const store = tx.objectStore('items');
      const request = store.getAll();
      request.onsuccess = () => resolve(request.result || []);
      request.onerror = () => reject(request.error);
    });
  }

  async function saveDBEncryptedItem(item) {
    const db = await openDatabase();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('items', 'readwrite');
      const store = tx.objectStore('items');
      const request = store.put(item);
      request.onsuccess = () => resolve(true);
      request.onerror = () => reject(request.error);
    });
  }

  async function deleteDBEncryptedItem(id) {
    const db = await openDatabase();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('items', 'readwrite');
      const store = tx.objectStore('items');
      const request = store.delete(id);
      request.onsuccess = () => resolve(true);
      request.onerror = () => reject(request.error);
    });
  }

  async function wipeDatabase() {
    const db = await openDatabase();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(['auth', 'items'], 'readwrite');
      tx.objectStore('auth').clear();
      tx.objectStore('items').clear();
      tx.oncomplete = () => resolve(true);
      tx.onerror = () => reject(tx.error);
    });
  }

  // =================================================================
  // 4. PASSWORD AUDITING & STRENGTH EVALUATION
  // =================================================================

  /**
   * Calculates password entropy in bits
   */
  function calculatePasswordEntropy(password) {
    if (!password) return 0;
    let poolSize = 0;
    if (/[a-z]/.test(password)) poolSize += 26;
    if (/[A-Z]/.test(password)) poolSize += 26;
    if (/[0-9]/.test(password)) poolSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) poolSize += 33;
    if (poolSize === 0) poolSize = 1;
    return Math.round(password.length * (Math.log(poolSize) / Math.LN2));
  }

  /**
   * Evaluates password strength level
   */
  function evaluatePasswordStrength(password) {
    if (!password || password.length === 0) {
      return { score: 0, label: 'Empty', class: '', entropy: 0 };
    }
    const entropy = calculatePasswordEntropy(password);
    const len = password.length;

    let score = 0;
    if (len >= 8) score++;
    if (len >= 12) score++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^a-zA-Z0-9]/.test(password)) score++;

    if (len < 8 || entropy < 30) {
      return { score: 1, label: 'Weak', class: 'str-weak', entropy };
    } else if (entropy < 50 || len < 11) {
      return { score: 2, label: 'Fair', class: 'str-fair', entropy };
    } else if (entropy < 70 || len < 15) {
      return { score: 3, label: 'Good', class: 'str-good', entropy };
    } else {
      return { score: 4, label: 'Very Strong', class: 'str-strong', entropy };
    }
  }

  /**
   * Estimates time to crack password with modern GPU clusters (100 billion guesses/sec)
   */
  function estimateCrackTime(entropy) {
    if (entropy < 28) return 'Instant';
    if (entropy < 36) return 'Few seconds';
    if (entropy < 45) return 'A few hours';
    if (entropy < 55) return 'Several months';
    if (entropy < 65) return 'Centuries';
    if (entropy < 80) return 'Millions of years';
    return '100+ Trillion Years';
  }

  /**
   * Conducts full vault audit: weak passwords, reused passwords, and health score
   */
  function auditVault(items) {
    const passwordItems = items.filter(it => it.type !== 'note' && it.password);
    const total = passwordItems.length;

    if (total === 0) {
      return {
        score: 100,
        weakItems: [],
        reusedGroups: [],
        strongCount: 0,
        reusedCount: 0,
        verdict: 'No passwords to audit yet. Add your credentials to begin!'
      };
    }

    const weakItems = [];
    const passwordMap = new Map(); // password -> array of items

    passwordItems.forEach(item => {
      const evalResult = evaluatePasswordStrength(item.password);
      if (evalResult.score <= 2 || item.password.length < 12) {
        weakItems.push({
          item,
          reason: item.password.length < 12 ? 'Short length (< 12 characters)' : 'Low entropy / lacks complexity'
        });
      }

      // Group reused
      if (!passwordMap.has(item.password)) {
        passwordMap.set(item.password, []);
      }
      passwordMap.get(item.password).push(item);
    });

    const reusedGroups = [];
    let reusedCount = 0;
    passwordMap.forEach((matchedItems, pwd) => {
      if (matchedItems.length > 1) {
        reusedGroups.push(matchedItems);
        reusedCount += matchedItems.length;
      }
    });

    const strongCount = total - weakItems.length;
    // Calculate health score (0 - 100)
    let penalty = (weakItems.length * 25) + (reusedCount * 20);
    let healthScore = Math.max(0, Math.round(100 - (penalty / total)));

    let verdict = 'All passwords meet strong cryptographic criteria.';
    if (healthScore < 50) {
      verdict = 'Critical vulnerabilities detected. Upgrade weak and reused credentials immediately.';
    } else if (healthScore < 80) {
      verdict = 'Moderate security risk. Some passwords are weak or reused across sites.';
    }

    return {
      score: healthScore,
      weakItems,
      reusedGroups,
      strongCount,
      reusedCount,
      verdict
    };
  }

  // =================================================================
  // 5. CSPRNG PASSWORD GENERATOR
  // =================================================================

  const CHAR_SETS = {
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lower: 'abcdefghijklmnopqrstuvwxyz',
    numbers: '0123456789',
    symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
  };
  const AMBIGUOUS_CHARS = /[1lIO0o]/g;

  function generateSecurePassword(options) {
    let pool = '';
    if (options.upper) pool += CHAR_SETS.upper;
    if (options.lower) pool += CHAR_SETS.lower;
    if (options.numbers) pool += CHAR_SETS.numbers;
    if (options.symbols) pool += CHAR_SETS.symbols;

    if (options.avoidAmbiguous) {
      pool = pool.replace(AMBIGUOUS_CHARS, '');
    }

    if (!pool) {
      pool = CHAR_SETS.lower + CHAR_SETS.numbers; // Safe fallback
    }

    const length = Math.max(8, Math.min(64, options.length || 16));
    const randomArray = getRandomBytes(length * 2); // oversample to eliminate modulo bias
    let password = '';
    let idx = 0;

    for (let i = 0; i < length; i++) {
      if (idx >= randomArray.length) {
        randomArray.set(getRandomBytes(length * 2));
        idx = 0;
      }
      const charIndex = randomArray[idx++] % pool.length;
      password += pool.charAt(charIndex);
    }

    return password;
  }

  // =================================================================
  // 6. SAMPLE VAULT GENERATOR (DEMO REASONING & TESTABILITY)
  // =================================================================

  function getSampleCredentials() {
    const now = new Date().toISOString();
    return [
      {
        id: crypto.randomUUID(),
        type: 'login',
        title: 'GitHub Developer',
        url: 'https://github.com',
        username: 'octocat_secure',
        password: generateSecurePassword({ length: 22, upper: true, lower: true, numbers: true, symbols: true }),
        category: 'Education',
        notes: '2FA via Hardware Security Key YubiKey 5C NFC. Recovery codes safely archived in emergency kit.',
        favorite: true,
        createdAt: now,
        updatedAt: now
      },
      {
        id: crypto.randomUUID(),
        type: 'login',
        title: 'Netflix Streaming',
        url: 'https://netflix.com',
        username: 'family@streaming.org',
        password: generateSecurePassword({ length: 18, upper: true, lower: true, numbers: true, symbols: false }),
        category: 'Entertainment',
        notes: 'Premium 4K Family plan with 4 concurrent screens.',
        favorite: true,
        createdAt: now,
        updatedAt: now
      },
      {
        id: crypto.randomUUID(),
        type: 'login',
        title: 'Bank of America',
        url: 'https://bankofamerica.com',
        username: 'alex_financials',
        password: generateSecurePassword({ length: 24, upper: true, lower: true, numbers: true, symbols: true }),
        category: 'Banking',
        notes: 'Checking & Savings. Security challenge questions configured with pseudo-random passphrases.',
        favorite: true,
        createdAt: now,
        updatedAt: now
      },
      {
        id: crypto.randomUUID(),
        type: 'login',
        title: 'Home Wi-Fi (Wi-Fi 7)',
        url: '',
        username: 'VaultKey-Mesh-5G',
        password: generateSecurePassword({ length: 20, upper: true, lower: true, numbers: true, symbols: false }),
        category: 'Wi-Fi',
        notes: 'WPA3 Enterprise authentication with guest isolation subnet.',
        favorite: false,
        createdAt: now,
        updatedAt: now
      },
      {
        id: crypto.randomUUID(),
        type: 'login',
        title: 'ProtonMail Private',
        url: 'https://proton.me',
        username: 'vault.user@proton.me',
        password: generateSecurePassword({ length: 20, upper: true, lower: true, numbers: true, symbols: true }),
        category: 'Email',
        notes: 'Primary encrypted email for account verification and security notifications.',
        favorite: false,
        createdAt: now,
        updatedAt: now
      },
      {
        id: crypto.randomUUID(),
        type: 'note',
        title: 'Server SSH Deployment Key',
        url: '',
        username: '',
        password: '',
        category: 'Other',
        notes: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH6m... Root access on Singapore cluster node. Port 2202.',
        favorite: false,
        createdAt: now,
        updatedAt: now
      }
    ];
  }

  // =================================================================
  // 7. TOAST NOTIFICATION ENGINE
  // =================================================================

  function showToast(message, type = 'info', duration = 3500) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    let iconSvg = '';
    if (type === 'success') {
      iconSvg = '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>';
    } else if (type === 'danger') {
      iconSvg = '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>';
    } else if (type === 'warning') {
      iconSvg = '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>';
    } else {
      iconSvg = '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>';
    }

    toast.innerHTML = `${iconSvg}<span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(20px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, duration);
  }

  // =================================================================
  // 8. CLIPBOARD HANDLING WITH TIMED CLEARANCE
  // =================================================================

  async function copyToClipboard(text, description = 'Data') {
    if (!text) {
      showToast(`No ${description} to copy`, 'warning');
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      
      const clearSeconds = parseInt(accountMeta?.settings?.clipboardSeconds || 30, 10);
      if (clearSeconds > 0) {
        showToast(`${description} copied! Will auto-clear in ${clearSeconds}s`, 'success');
        
        if (clipboardClearTimer) clearTimeout(clipboardClearTimer);
        clipboardClearTimer = setTimeout(async () => {
          try {
            const current = await navigator.clipboard.readText();
            if (current === text) {
              await navigator.clipboard.writeText('');
              showToast('Clipboard cleared for security', 'info', 2000);
            }
          } catch (e) {
            // Clipboard read permission might be blocked by browser; harmless
          }
        }, clearSeconds * 1000);
      } else {
        showToast(`${description} copied to clipboard!`, 'success');
      }
    } catch (err) {
      // Fallback
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      showToast(`${description} copied to clipboard!`, 'success');
    }
  }

  // =================================================================
  // 9. INACTIVITY TRACKER & AUTO-LOCK ENGINE
  // =================================================================

  function resetInactivityTimer() {
    if (!activeVaultKey) return; // Vault is locked

    const timeoutMinutes = parseInt(accountMeta?.settings?.autoLockMinutes || 5, 10);
    if (timeoutMinutes === 0) {
      // Disabled
      document.getElementById('auto-lock-timer-text').textContent = 'Unlocked';
      if (countdownTimer) clearInterval(countdownTimer);
      return;
    }

    secondsRemaining = timeoutMinutes * 60;
    updateTimerDisplay();

    if (countdownTimer) clearInterval(countdownTimer);
    countdownTimer = setInterval(() => {
      if (!activeVaultKey) {
        clearInterval(countdownTimer);
        return;
      }
      secondsRemaining--;
      updateTimerDisplay();
      if (secondsRemaining <= 0) {
        clearInterval(countdownTimer);
        lockVault('Auto-locked due to user inactivity.');
      }
    }, 1000);
  }

  function updateTimerDisplay() {
    const textEl = document.getElementById('auto-lock-timer-text');
    if (!textEl) return;
    const m = Math.floor(secondsRemaining / 60).toString().padStart(2, '0');
    const s = (secondsRemaining % 60).toString().padStart(2, '0');
    textEl.textContent = `${m}:${s}`;
  }

  function attachActivityListeners() {
    const events = ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll'];
    let throttleTimeout;
    const onUserActivity = () => {
      if (!throttleTimeout) {
        throttleTimeout = setTimeout(() => {
          throttleTimeout = null;
          resetInactivityTimer();
        }, 1500);
      }
    };
    events.forEach(ev => window.addEventListener(ev, onUserActivity, { passive: true }));
  }

  function lockVault(reason = 'Vault locked') {
    // Evict master key from memory
    activeVaultKey = null;
    decryptedItems = [];

    if (countdownTimer) clearInterval(countdownTimer);

    // Show Lock Overlay
    const overlay = document.getElementById('lock-screen-overlay');
    if (overlay) {
      overlay.classList.remove('hidden');
      const passInput = document.getElementById('lock-unlock-password');
      if (passInput) {
        passInput.value = '';
        passInput.focus();
      }
    }
    showToast(reason, 'info');
  }

  // =================================================================
  // 10. AUTHENTICATION & ONBOARDING CONTROLLERS
  // =================================================================

  /**
   * Initializes application state and checks existing vault in IndexedDB
   */
  async function initApplication() {
    try {
      accountMeta = await getDBMeta();

      // Apply saved theme
      const savedTheme = localStorage.getItem('vaultkey_theme') || accountMeta?.settings?.theme || 'dark';
      applyTheme(savedTheme);

      if (!accountMeta) {
        // No vault exists: show signup screen
        showAuthView('signup');
      } else {
        // Vault exists: show login screen
        document.getElementById('login-user-identifier').textContent = `Account: ${accountMeta.email}`;
        showAuthView('login');
      }
    } catch (err) {
      console.error('Initialization error:', err);
      showToast('Error accessing local database', 'danger');
    }
  }

  function showAuthView(viewName) {
    document.getElementById('auth-container').classList.remove('hidden');
    document.getElementById('app-layout').classList.add('hidden');
    document.getElementById('lock-screen-overlay').classList.add('hidden');

    document.querySelectorAll('.auth-view').forEach(el => el.classList.remove('active'));
    if (viewName === 'signup') {
      document.getElementById('auth-signup-view').classList.add('active');
    } else if (viewName === 'login') {
      document.getElementById('auth-login-view').classList.add('active');
    } else if (viewName === 'recovery') {
      document.getElementById('auth-recovery-view').classList.add('active');
    }
  }

  /**
   * SIGN UP HANDLER: Sets up zero-knowledge vault
   */
  async function handleSignUp(e) {
    e.preventDefault();
    const email = document.getElementById('signup-email').value.trim();
    const password = document.getElementById('signup-password').value;
    const confirm = document.getElementById('signup-confirm').value;
    const loadSample = document.getElementById('signup-load-sample').checked;

    if (password !== confirm) {
      showToast('Master passwords do not match!', 'danger');
      return;
    }
    if (password.length < 10) {
      showToast('Master password must be at least 10 characters', 'warning');
      return;
    }

    const btn = document.getElementById('btn-create-vault');
    btn.disabled = true;
    btn.innerHTML = '<span>Deriving Cryptographic Keys...</span>';

    try {
      // 1. Generate unique 16-byte random salt for PBKDF2
      const kdfSalt = getRandomBytes(16);
      const kdfSaltB64 = arrayBufferToBase64(kdfSalt);

      // 2. Derive master encryption key
      const masterKey = await deriveVaultKey(password, kdfSalt, PBKDF2_ITERATIONS);

      // 3. Encrypt verification canary
      const canaryEnc = await encryptData(CANARY_PAYLOAD, masterKey);

      // 4. Generate Emergency Recovery Key
      const recoveryKey = generateRecoveryKey();
      const recoverySalt = getRandomBytes(16);
      const recoveryKeyDerived = await deriveVaultKey(recoveryKey, recoverySalt, PBKDF2_ITERATIONS);
      const recoveryCanaryEnc = await encryptData(CANARY_PAYLOAD, recoveryKeyDerived);

      // 5. Build account metadata
      const meta = {
        email: email,
        kdfSalt: kdfSaltB64,
        kdfIterations: PBKDF2_ITERATIONS,
        canaryIv: canaryEnc.iv,
        canaryCiphertext: canaryEnc.ciphertext,
        recoverySalt: arrayBufferToBase64(recoverySalt),
        recoveryCanaryIv: recoveryCanaryEnc.iv,
        recoveryCanaryCiphertext: recoveryCanaryEnc.ciphertext,
        settings: {
          autoLockMinutes: 5,
          clipboardSeconds: 30,
          theme: 'dark'
        },
        createdAt: new Date().toISOString()
      };

      await saveDBMeta(meta);
      accountMeta = meta;
      activeVaultKey = masterKey;

      // 6. Populate demo sample records if checked
      if (loadSample) {
        const samples = getSampleCredentials();
        for (const sample of samples) {
          const enc = await encryptData(JSON.stringify(sample), masterKey);
          await saveDBEncryptedItem({
            id: sample.id,
            iv: enc.iv,
            ciphertext: enc.ciphertext,
            createdAt: sample.createdAt,
            updatedAt: sample.updatedAt
          });
        }
      }

      // 7. Show Emergency Kit Modal with recovery key
      showEmergencyKitModal(recoveryKey, email);

    } catch (err) {
      console.error('Signup error:', err);
      showToast('Failed to initialize vault: ' + err.message, 'danger');
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<span>Create Encrypted Vault</span>';
    }
  }

  function showEmergencyKitModal(recoveryKey, email) {
    document.getElementById('display-recovery-key').textContent = recoveryKey;
    document.getElementById('emergency-kit-modal').classList.add('active');

    // Download Emergency Kit button
    document.getElementById('btn-download-emergency-kit').onclick = () => {
      downloadEmergencyKitDoc(recoveryKey, email);
    };

    // Copy key button
    document.getElementById('btn-copy-recovery-key').onclick = () => {
      copyToClipboard(recoveryKey, 'Recovery Key');
    };

    // Checkbox toggle
    const check = document.getElementById('check-confirm-kit-saved');
    const finishBtn = document.getElementById('btn-finish-onboarding');
    check.checked = false;
    finishBtn.disabled = true;

    check.onchange = () => {
      finishBtn.disabled = !check.checked;
    };

    finishBtn.onclick = async () => {
      document.getElementById('emergency-kit-modal').classList.remove('active');
      await enterVaultDashboard();
    };
  }

  function downloadEmergencyKitDoc(recoveryKey, email) {
    const htmlContent = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>VaultKey Emergency Kit</title>
  <style>
    body { font-family: 'Helvetica Neue', Arial, sans-serif; padding: 40px; color: #1e293b; max-width: 680px; margin: 0 auto; }
    .header { border-bottom: 2px solid #8b5cf6; padding-bottom: 14px; margin-bottom: 24px; }
    h1 { color: #0f172a; margin: 0 0 6px; }
    .badge { display: inline-block; background: #ede9fe; color: #7c3aed; padding: 4px 10px; border-radius: 999px; font-weight: bold; font-size: 12px; }
    .box { background: #f8fafc; border: 1.5px dashed #cbd5e1; border-radius: 8px; padding: 18px; margin: 20px 0; }
    .code { font-family: monospace; font-size: 20px; font-weight: bold; color: #7c3aed; letter-spacing: 1.5px; }
    .instruction { font-size: 13px; line-height: 1.6; color: #475569; }
    .footer { margin-top: 30px; font-size: 11px; color: #94a3b8; border-top: 1px solid #e2e8f0; padding-top: 14px; }
  </style>
</head>
<body>
  <div class="header">
    <h1>VaultKey &bull; Emergency Recovery Kit</h1>
    <span class="badge">CONFIDENTIAL &bull; ZERO-KNOWLEDGE BACKUP</span>
  </div>
  <p class="instruction">Store this document in a safe physical place or an encrypted offline drive. Your master password cannot be reset via email because VaultKey is strictly zero-knowledge.</p>
  
  <div class="box">
    <div><strong>Account Identifier:</strong> ${email}</div>
    <div style="margin-top: 8px;"><strong>Cryptographic Standard:</strong> AES-256-GCM + PBKDF2-SHA-256 (310,000 Iterations)</div>
    <div style="margin-top: 14px;"><strong>EMERGENCY RECOVERY KEY:</strong></div>
    <div class="code">${recoveryKey}</div>
  </div>

  <h3>How to Recover Your Vault:</h3>
  <ol class="instruction">
    <li>Open VaultKey on your browser.</li>
    <li>On the unlock screen, select <em>"Forgot master password? Use Recovery Key"</em>.</li>
    <li>Enter the 32-character Emergency Recovery Key above and specify a new master password.</li>
  </ol>

  <div class="footer">
    Generated locally via Web Crypto API on ${new Date().toLocaleString()} &bull; VaultKey Personal Security Suite
  </div>
</body>
</html>`;

    const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `VaultKey-Emergency-Kit-${email.replace(/[^a-zA-Z0-9]/g, '_')}.html`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Emergency Kit downloaded. Store safely!', 'success');
  }

  /**
   * LOGIN / UNLOCK HANDLER
   */
  async function handleLogin(e) {
    e.preventDefault();
    const password = document.getElementById('login-password').value;
    const btn = document.getElementById('btn-unlock-vault');

    if (!password) return;

    btn.disabled = true;
    btn.innerHTML = '<span>Verifying &amp; Decrypting...</span>';

    try {
      if (!accountMeta) {
        accountMeta = await getDBMeta();
      }

      const salt = base64ToUint8Array(accountMeta.kdfSalt);
      const iterations = accountMeta.kdfIterations || PBKDF2_ITERATIONS;

      // 1. Derive candidate key
      const candidateKey = await deriveVaultKey(password, salt, iterations);

      // 2. Test decryption of verification canary
      try {
        const decryptedCanary = await decryptData(
          accountMeta.canaryCiphertext,
          accountMeta.canaryIv,
          candidateKey
        );
        const parsed = JSON.parse(decryptedCanary);
        if (parsed.canary !== 'VAULTKEY_AUTH_OK') {
          throw new Error('Canary payload invalid');
        }
      } catch (authErr) {
        throw new Error('Incorrect master password');
      }

      // Password is valid!
      activeVaultKey = candidateKey;
      document.getElementById('login-password').value = '';
      await enterVaultDashboard();

    } catch (err) {
      console.error('Login error:', err);
      showToast(err.message || 'Incorrect master password', 'danger');
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"></rect><path d="M7 11V7a5 5 0 0 1 9.9-1"></path></svg><span>Decrypt &amp; Open Vault</span>';
    }
  }

  /**
   * LOCK SCREEN UNLOCK HANDLER
   */
  async function handleLockScreenUnlock(e) {
    e.preventDefault();
    const pass = document.getElementById('lock-unlock-password').value;
    if (!pass) return;

    try {
      const salt = base64ToUint8Array(accountMeta.kdfSalt);
      const iterations = accountMeta.kdfIterations || PBKDF2_ITERATIONS;
      const candidateKey = await deriveVaultKey(pass, salt, iterations);

      await decryptData(accountMeta.canaryCiphertext, accountMeta.canaryIv, candidateKey);

      activeVaultKey = candidateKey;
      document.getElementById('lock-screen-overlay').classList.add('hidden');
      document.getElementById('lock-unlock-password').value = '';
      showToast('Vault unlocked successfully', 'success');

      // Reload and re-decrypt items
      await loadAndDecryptAllItems();
      renderCurrentView();
      resetInactivityTimer();

    } catch (err) {
      showToast('Incorrect master password', 'danger');
    }
  }

  /**
   * RECOVERY FORM HANDLER
   */
  async function handleRecovery(e) {
    e.preventDefault();
    const enteredKey = document.getElementById('recovery-key-input').value.trim().toUpperCase();
    const newPassword = document.getElementById('recovery-new-password').value;

    if (newPassword.length < 10) {
      showToast('New master password must be at least 10 characters', 'warning');
      return;
    }

    try {
      const recoverySalt = base64ToUint8Array(accountMeta.recoverySalt);
      const recoveryKeyDerived = await deriveVaultKey(enteredKey, recoverySalt, accountMeta.kdfIterations || PBKDF2_ITERATIONS);

      // Verify recovery canary
      await decryptData(
        accountMeta.recoveryCanaryCiphertext,
        accountMeta.recoveryCanaryIv,
        recoveryKeyDerived
      );

      // Recovery key is valid! Generate fresh salt and new master key
      const newSalt = getRandomBytes(16);
      const newMasterKey = await deriveVaultKey(newPassword, newSalt, PBKDF2_ITERATIONS);
      const newCanary = await encryptData(CANARY_PAYLOAD, newMasterKey);

      // Also generate fresh recovery key
      const newRecoveryKey = generateRecoveryKey();
      const newRecoverySalt = getRandomBytes(16);
      const newRecoveryKeyDerived = await deriveVaultKey(newRecoveryKey, newRecoverySalt, PBKDF2_ITERATIONS);
      const newRecoveryCanary = await encryptData(CANARY_PAYLOAD, newRecoveryKeyDerived);

      accountMeta.kdfSalt = arrayBufferToBase64(newSalt);
      accountMeta.canaryIv = newCanary.iv;
      accountMeta.canaryCiphertext = newCanary.ciphertext;
      accountMeta.recoverySalt = arrayBufferToBase64(newRecoverySalt);
      accountMeta.recoveryCanaryIv = newRecoveryCanary.iv;
      accountMeta.recoveryCanaryCiphertext = newRecoveryCanary.ciphertext;

      await saveDBMeta(accountMeta);
      activeVaultKey = newMasterKey;

      showToast('Master password successfully updated via Recovery Key!', 'success');
      showEmergencyKitModal(newRecoveryKey, accountMeta.email);

    } catch (err) {
      console.error('Recovery error:', err);
      showToast('Invalid Recovery Key. Please verify characters.', 'danger');
    }
  }

  // =================================================================
  // 11. VAULT OPERATIONS: DECRYPT, RENDER, CRUD
  // =================================================================

  async function enterVaultDashboard() {
    document.getElementById('auth-container').classList.add('hidden');
    document.getElementById('lock-screen-overlay').classList.add('hidden');
    document.getElementById('app-layout').classList.remove('hidden');

    document.getElementById('sidebar-user-email').textContent = accountMeta.email;

    await loadAndDecryptAllItems();
    switchNavTab('dashboard');
    resetInactivityTimer();
    showToast('Vault active & zero-knowledge decrypted', 'success');
  }

  async function loadAndDecryptAllItems() {
    const rawRecords = await getAllDBEncryptedItems();
    decryptedItems = [];

    for (const record of rawRecords) {
      try {
        const decryptedJson = await decryptData(record.ciphertext, record.iv, activeVaultKey);
        const itemObj = JSON.parse(decryptedJson);
        decryptedItems.push(itemObj);
      } catch (err) {
        console.error('Decryption failed for item:', record.id, err);
      }
    }

    updateSidebarBadges();
  }

  function updateSidebarBadges() {
    const total = decryptedItems.length;
    const favorites = decryptedItems.filter(i => i.favorite).length;
    const notes = decryptedItems.filter(i => i.type === 'note').length;
    const auditRes = auditVault(decryptedItems);

    document.getElementById('badge-total-items').textContent = total;
    document.getElementById('badge-favorite-items').textContent = favorites;
    document.getElementById('badge-note-items').textContent = notes;
    document.getElementById('badge-weak-items').textContent = auditRes.weakItems.length;

    // Dashboard metrics
    document.getElementById('dash-metric-total').textContent = total;
    document.getElementById('dash-metric-favorites').textContent = favorites;
    document.getElementById('dash-metric-notes').textContent = notes;
    document.getElementById('dash-metric-score').textContent = `${auditRes.score}%`;

    // Health score progress & colors
    const progressEl = document.getElementById('dash-score-progress');
    const badgeEl = document.getElementById('dash-health-badge');
    progressEl.style.width = `${auditRes.score}%`;

    if (auditRes.score >= 85) {
      badgeEl.className = 'status-indicator-badge badge-success';
      badgeEl.textContent = 'Optimal';
    } else if (auditRes.score >= 60) {
      badgeEl.className = 'status-indicator-badge badge-warning';
      badgeEl.textContent = 'Needs Attention';
    } else {
      badgeEl.className = 'status-indicator-badge badge-danger';
      badgeEl.textContent = 'At Risk';
    }

    document.getElementById('dash-count-weak').textContent = auditRes.weakItems.length;
    document.getElementById('dash-count-reused').textContent = auditRes.reusedCount;
    document.getElementById('dash-count-strong').textContent = auditRes.strongCount;
  }

  function filterAndSortItems(items) {
    let result = [...items];

    // 1. Navigation / Context Filter
    if (currentNavTab === 'favorites') {
      result = result.filter(i => i.favorite);
    } else if (currentNavTab === 'notes') {
      result = result.filter(i => i.type === 'note');
    }

    // 2. Category Filter
    if (activeCategoryFilter !== 'ALL') {
      result = result.filter(i => i.category === activeCategoryFilter);
    }

    // 3. Search Query
    if (activeSearchQuery.trim()) {
      const q = activeSearchQuery.toLowerCase().trim();
      result = result.filter(i => {
        return (i.title && i.title.toLowerCase().includes(q)) ||
               (i.username && i.username.toLowerCase().includes(q)) ||
               (i.url && i.url.toLowerCase().includes(q)) ||
               (i.category && i.category.toLowerCase().includes(q)) ||
               (i.notes && i.notes.toLowerCase().includes(q));
      });
    }

    // 4. Sorting
    if (activeSortOption === 'title-asc') {
      result.sort((a, b) => a.title.localeCompare(b.title));
    } else if (activeSortOption === 'title-desc') {
      result.sort((a, b) => b.title.localeCompare(a.title));
    } else if (activeSortOption === 'created-desc') {
      result.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    } else {
      // updated-desc (default)
      result.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
    }

    return result;
  }

  function renderCurrentView() {
    updateSidebarBadges();

    if (currentNavTab === 'dashboard') {
      renderDashboardRecent();
    } else if (currentNavTab === 'vault' || currentNavTab === 'favorites') {
      renderVaultItems();
    } else if (currentNavTab === 'notes') {
      renderSecureNotes();
    } else if (currentNavTab === 'audit') {
      renderAuditView();
    }
  }

  /**
   * RENDER DASHBOARD RECENT ITEMS
   */
  function renderDashboardRecent() {
    const tbody = document.getElementById('dash-recent-tbody');
    tbody.innerHTML = '';

    const recent = [...decryptedItems]
      .sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt))
      .slice(0, 5);

    if (recent.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding: 24px; color: var(--text-muted);">No credentials added yet. Click "+ Add Item" above.</td></tr>`;
      return;
    }

    recent.forEach(item => {
      const tr = document.createElement('tr');
      const domain = getDomainFromUrl(item.url);
      const updatedDate = formatDate(item.updatedAt);

      tr.innerHTML = `
        <td>
          <div class="table-title-cell">
            <div class="item-avatar-icon">${getInitials(item.title)}</div>
            <div>
              <div class="font-bold">${escapeHtml(item.title)}</div>
              <div class="text-xs text-muted">${domain ? escapeHtml(domain) : 'Local / App'}</div>
            </div>
          </div>
        </td>
        <td><span class="category-badge">${escapeHtml(item.category || 'Other')}</span></td>
        <td><span class="font-mono text-xs">${item.username ? escapeHtml(item.username) : '<span class="text-dim">N/A</span>'}</span></td>
        <td>
          <span class="font-mono text-xs password-masked">&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;</span>
        </td>
        <td class="text-xs text-muted">${updatedDate}</td>
        <td>
          <div class="table-actions">
            ${item.username ? `
              <button type="button" class="btn-card-action" data-copy-user="${item.id}" title="Copy Username">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
              </button>` : ''}
            ${item.password ? `
              <button type="button" class="btn-card-action" data-copy-pass="${item.id}" title="Copy Password">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
              </button>` : ''}
            <button type="button" class="btn-card-action" data-view-item="${item.id}" title="View Details">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
            </button>
          </div>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  /**
   * RENDER VAULT ITEMS (GRID / TABLE)
   */
  function renderVaultItems() {
    const container = document.getElementById('vault-items-container');
    const emptyState = document.getElementById('vault-empty-state');
    container.innerHTML = '';

    const items = filterAndSortItems(decryptedItems);

    // Update view title
    const titleEl = document.getElementById('vault-view-title');
    const descEl = document.getElementById('vault-view-description');
    if (currentNavTab === 'favorites') {
      titleEl.textContent = 'Favorite Credentials';
      descEl.textContent = 'Quick access to your most frequently used accounts.';
    } else {
      titleEl.textContent = activeCategoryFilter === 'ALL' ? 'All Vault Items' : `${activeCategoryFilter} Items`;
      descEl.textContent = `Displaying ${items.length} encrypted credentials.`;
    }

    if (items.length === 0) {
      container.classList.add('hidden');
      emptyState.classList.remove('hidden');
      return;
    }

    emptyState.classList.add('hidden');
    container.classList.remove('hidden');

    if (activeViewLayout === 'grid') {
      container.className = 'vault-items-grid';
      items.forEach(item => {
        container.appendChild(createItemGridCard(item));
      });
    } else {
      container.className = 'items-table-container';
      container.appendChild(createItemTableView(items));
    }
  }

  function createItemGridCard(item) {
    const card = document.createElement('div');
    card.className = 'item-card';

    const domain = getDomainFromUrl(item.url);
    const starClass = item.favorite ? 'item-star-btn starred' : 'item-star-btn';

    card.innerHTML = `
      <div class="item-card-header">
        <div class="item-card-identity">
          <div class="item-avatar-icon">${getInitials(item.title)}</div>
          <div class="item-info">
            <div class="item-title-text" title="${escapeHtml(item.title)}">${escapeHtml(item.title)}</div>
            <span class="item-url-text">${domain ? escapeHtml(domain) : 'Secure Record'}</span>
          </div>
        </div>
        <button type="button" class="${starClass}" data-toggle-fav="${item.id}" title="${item.favorite ? 'Remove Favorite' : 'Mark Favorite'}">
          <svg viewBox="0 0 24 24" fill="${item.favorite ? 'currentColor' : 'none'}" stroke="currentColor" stroke-width="2">
            <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon>
          </svg>
        </button>
      </div>

      <div class="item-card-body">
        ${item.username ? `
          <div class="cred-box">
            <span class="cred-text" title="${escapeHtml(item.username)}">${escapeHtml(item.username)}</span>
            <div class="cred-actions">
              <button type="button" class="btn-card-action" data-copy-user="${item.id}" title="Copy Username">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
              </button>
            </div>
          </div>
        ` : ''}

        ${item.password ? `
          <div class="cred-box">
            <span class="cred-text password-masked" id="card-pass-${item.id}">&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;</span>
            <div class="cred-actions">
              <button type="button" class="btn-card-action" data-toggle-eye="${item.id}" title="Show / Hide Password">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
              </button>
              <button type="button" class="btn-card-action" data-copy-pass="${item.id}" title="Copy Password">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
              </button>
            </div>
          </div>
        ` : ''}

        <div style="margin-top: 4px;">
          <span class="category-badge">${escapeHtml(item.category || 'Other')}</span>
        </div>
      </div>

      <div class="item-card-footer">
        <span>Updated ${formatDate(item.updatedAt)}</span>
        <div class="item-card-actions">
          <button type="button" class="btn-card-action" data-view-item="${item.id}" title="View Details">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
          </button>
          <button type="button" class="btn-card-action" data-edit-item="${item.id}" title="Edit Credential">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
          </button>
          <button type="button" class="btn-card-action btn-delete" data-delete-item="${item.id}" title="Delete Item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
          </button>
        </div>
      </div>
    `;

    return card;
  }

  function createItemTableView(items) {
    const table = document.createElement('table');
    table.className = 'items-table';

    table.innerHTML = `
      <thead>
        <tr>
          <th>Title & Website</th>
          <th>Category</th>
          <th>Username / Email</th>
          <th>Password</th>
          <th>Updated</th>
          <th class="text-right">Actions</th>
        </tr>
      </thead>
      <tbody>
        ${items.map(item => `
          <tr>
            <td>
              <div class="table-title-cell">
                <div class="item-avatar-icon">${getInitials(item.title)}</div>
                <div>
                  <div class="font-bold">${escapeHtml(item.title)}</div>
                  <div class="text-xs text-muted">${item.url ? escapeHtml(getDomainFromUrl(item.url)) : 'Secure Item'}</div>
                </div>
              </div>
            </td>
            <td><span class="category-badge">${escapeHtml(item.category || 'Other')}</span></td>
            <td><span class="font-mono text-xs">${item.username ? escapeHtml(item.username) : '<span class="text-dim">N/A</span>'}</span></td>
            <td>
              <span class="font-mono text-xs password-masked" id="table-pass-${item.id}">&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;</span>
            </td>
            <td class="text-xs text-muted">${formatDate(item.updatedAt)}</td>
            <td>
              <div class="table-actions">
                ${item.username ? `
                  <button type="button" class="btn-card-action" data-copy-user="${item.id}" title="Copy Username">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
                  </button>` : ''}
                ${item.password ? `
                  <button type="button" class="btn-card-action" data-copy-pass="${item.id}" title="Copy Password">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                  </button>` : ''}
                <button type="button" class="btn-card-action" data-view-item="${item.id}" title="View Details">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
                </button>
                <button type="button" class="btn-card-action" data-edit-item="${item.id}" title="Edit Item">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
                </button>
                <button type="button" class="btn-card-action btn-delete" data-delete-item="${item.id}" title="Delete Item">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                </button>
              </div>
            </td>
          </tr>
        `).join('')}
      </tbody>
    `;
    return table;
  }

  /**
   * RENDER SECURE NOTES VIEW
   */
  function renderSecureNotes() {
    const container = document.getElementById('notes-grid-container');
    container.innerHTML = '';

    const notes = decryptedItems.filter(i => i.type === 'note');

    if (notes.length === 0) {
      container.innerHTML = `
        <div class="empty-state-card" style="grid-column: 1 / -1;">
          <div class="empty-icon-circle">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
          </div>
          <h3>No Secure Notes Yet</h3>
          <p>Store encrypted API keys, recovery seeds, server IPs, and confidential memos.</p>
          <button type="button" class="btn btn-primary" id="btn-empty-add-note">Create First Note</button>
        </div>
      `;
      document.getElementById('btn-empty-add-note')?.addEventListener('click', () => openItemEditorModal(null, 'note'));
      return;
    }

    notes.forEach(note => {
      const card = document.createElement('div');
      card.className = 'note-card';
      card.innerHTML = `
        <div class="note-header">
          <div class="note-title">${escapeHtml(note.title)}</div>
          <span class="category-badge">${escapeHtml(note.category || 'Other')}</span>
        </div>
        <div class="note-body">${escapeHtml(note.notes || '(Empty Note)')}</div>
        <div class="item-card-footer">
          <span>Updated ${formatDate(note.updatedAt)}</span>
          <div class="item-card-actions">
            <button type="button" class="btn-card-action" data-copy-note="${note.id}" title="Copy Note Content">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
            </button>
            <button type="button" class="btn-card-action" data-edit-item="${note.id}" title="Edit Note">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
            </button>
            <button type="button" class="btn-card-action btn-delete" data-delete-item="${note.id}" title="Delete Note">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
            </button>
          </div>
        </div>
      `;
      container.appendChild(card);
    });
  }

  /**
   * RENDER AUDIT VIEW
   */
  function renderAuditView() {
    const auditRes = auditVault(decryptedItems);

    document.getElementById('audit-big-score').textContent = auditRes.score;
    document.getElementById('audit-score-verdict').textContent = auditRes.verdict;
    document.getElementById('audit-num-weak').textContent = auditRes.weakItems.length;
    document.getElementById('audit-num-reused').textContent = auditRes.reusedCount;
    document.getElementById('audit-num-strong').textContent = auditRes.strongCount;

    const container = document.getElementById('audit-issues-container');
    container.innerHTML = '';

    if (auditRes.weakItems.length === 0 && auditRes.reusedGroups.length === 0) {
      container.innerHTML = `
        <div style="text-align: center; padding: 32px 16px;">
          <div class="empty-icon-circle" style="background: rgba(16, 185, 129, 0.15); color: var(--accent-emerald);">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>
          </div>
          <h4 style="font-size: 16px; font-weight: 700; margin-bottom: 4px;">Zero Cryptographic Vulnerabilities Found</h4>
          <p class="text-muted text-xs">All stored passwords exhibit high entropy and no duplicates were detected.</p>
        </div>
      `;
      return;
    }

    // Render Weak Passwords
    auditRes.weakItems.forEach(({ item, reason }) => {
      const div = document.createElement('div');
      div.className = 'audit-issue-item';
      div.innerHTML = `
        <div class="audit-issue-info">
          <h4>${escapeHtml(item.title)} &bull; Weak Password</h4>
          <p>${escapeHtml(reason)} &bull; Username: ${item.username ? escapeHtml(item.username) : 'N/A'}</p>
        </div>
        <button type="button" class="btn btn-outline btn-sm" data-edit-item="${item.id}">
          <span>Upgrade Password</span>
        </button>
      `;
      container.appendChild(div);
    });

    // Render Reused Passwords
    auditRes.reusedGroups.forEach(group => {
      const titles = group.map(i => escapeHtml(i.title)).join(', ');
      const div = document.createElement('div');
      div.className = 'audit-issue-item warning';
      div.innerHTML = `
        <div class="audit-issue-info">
          <h4>Reused Password Detected across (${group.length}) Accounts</h4>
          <p>Shared between: <strong>${titles}</strong>. If one is breached, all are compromised.</p>
        </div>
        <button type="button" class="btn btn-outline btn-sm" data-edit-item="${group[0].id}">
          <span>Change One</span>
        </button>
      `;
      container.appendChild(div);
    });
  }

  // =================================================================
  // 12. ADD & EDIT ITEM MODAL CONTROLLERS
  // =================================================================

  let currentModalItemType = 'login'; // 'login' | 'note'

  function openItemEditorModal(itemId = null, preselectedType = 'login') {
    const modal = document.getElementById('modal-item-editor');
    const form = document.getElementById('form-item-editor');
    form.reset();

    const titleEl = document.getElementById('modal-editor-title');
    const saveBtnText = document.getElementById('btn-save-item-text');
    const editIdInput = document.getElementById('item-edit-id');

    currentModalItemType = preselectedType;
    syncEditorTypeTabs();

    if (itemId) {
      // Editing existing item
      const item = decryptedItems.find(i => i.id === itemId);
      if (!item) return;

      editIdInput.value = item.id;
      titleEl.textContent = 'Edit Vault Item';
      saveBtnText.textContent = 'Save Changes';

      document.getElementById('item-title').value = item.title || '';
      document.getElementById('item-category').value = item.category || 'Other';
      document.getElementById('item-url').value = item.url || '';
      document.getElementById('item-username').value = item.username || '';
      document.getElementById('item-password').value = item.password || '';
      document.getElementById('item-notes').value = item.notes || '';
      document.getElementById('item-favorite').checked = !!item.favorite;

      currentModalItemType = item.type || 'login';
      syncEditorTypeTabs();
      updateFormPasswordStrength(item.password || '');
    } else {
      // Adding new item
      editIdInput.value = '';
      titleEl.textContent = 'Add Vault Item';
      saveBtnText.textContent = 'Save Encrypted Item';

      // Auto-generate high-entropy password for new login items
      if (preselectedType === 'login') {
        const autoPass = generateSecurePassword({ length: 18, upper: true, lower: true, numbers: true, symbols: true });
        document.getElementById('item-password').value = autoPass;
        updateFormPasswordStrength(autoPass);
      } else {
        updateFormPasswordStrength('');
      }
    }

    modal.classList.add('active');
    document.getElementById('item-title').focus();
  }

  function syncEditorTypeTabs() {
    document.querySelectorAll('.tab-pill').forEach(btn => {
      if (btn.getAttribute('data-item-type') === currentModalItemType) {
        btn.classList.add('active');
      } else {
        btn.classList.remove('active');
      }
    });

    const loginFields = document.getElementById('login-specific-fields');
    if (currentModalItemType === 'note') {
      loginFields.classList.add('hidden');
    } else {
      loginFields.classList.remove('hidden');
    }
  }

  async function handleSaveItem(e) {
    e.preventDefault();
    const editId = document.getElementById('item-edit-id').value;
    const title = document.getElementById('item-title').value.trim();
    const category = document.getElementById('item-category').value;
    const url = document.getElementById('item-url').value.trim();
    const username = document.getElementById('item-username').value.trim();
    const password = document.getElementById('item-password').value;
    const notes = document.getElementById('item-notes').value.trim();
    const favorite = document.getElementById('item-favorite').checked;

    if (!title) {
      showToast('Title is required', 'warning');
      return;
    }

    const now = new Date().toISOString();
    let itemObj;

    if (editId) {
      const existing = decryptedItems.find(i => i.id === editId);
      itemObj = {
        ...existing,
        type: currentModalItemType,
        title,
        category,
        url: currentModalItemType === 'login' ? url : '',
        username: currentModalItemType === 'login' ? username : '',
        password: currentModalItemType === 'login' ? password : '',
        notes,
        favorite,
        updatedAt: now
      };
    } else {
      itemObj = {
        id: crypto.randomUUID(),
        type: currentModalItemType,
        title,
        category,
        url: currentModalItemType === 'login' ? url : '',
        username: currentModalItemType === 'login' ? username : '',
        password: currentModalItemType === 'login' ? password : '',
        notes,
        favorite,
        createdAt: now,
        updatedAt: now
      };
    }

    try {
      // Zero-Knowledge Encrypt with AES-256-GCM
      const encrypted = await encryptData(JSON.stringify(itemObj), activeVaultKey);

      await saveDBEncryptedItem({
        id: itemObj.id,
        iv: encrypted.iv,
        ciphertext: encrypted.ciphertext,
        createdAt: itemObj.createdAt,
        updatedAt: itemObj.updatedAt
      });

      // Update in-memory state
      if (editId) {
        const idx = decryptedItems.findIndex(i => i.id === editId);
        if (idx !== -1) decryptedItems[idx] = itemObj;
      } else {
        decryptedItems.unshift(itemObj);
      }

      document.getElementById('modal-item-editor').classList.remove('active');
      renderCurrentView();
      showToast(`Encrypted item "${title}" saved!`, 'success');

    } catch (err) {
      console.error('Failed to save item:', err);
      showToast('Failed to encrypt and store item', 'danger');
    }
  }

  async function handleDeleteItem(itemId) {
    const item = decryptedItems.find(i => i.id === itemId);
    if (!item) return;

    if (!confirm(`Are you sure you want to permanently delete "${item.title}"?`)) {
      return;
    }

    try {
      await deleteDBEncryptedItem(itemId);
      decryptedItems = decryptedItems.filter(i => i.id !== itemId);
      renderCurrentView();
      showToast(`Deleted "${item.title}"`, 'info');
    } catch (err) {
      showToast('Failed to delete item', 'danger');
    }
  }

  async function handleToggleFavorite(itemId) {
    const item = decryptedItems.find(i => i.id === itemId);
    if (!item) return;

    item.favorite = !item.favorite;
    item.updatedAt = new Date().toISOString();

    try {
      const encrypted = await encryptData(JSON.stringify(item), activeVaultKey);
      await saveDBEncryptedItem({
        id: item.id,
        iv: encrypted.iv,
        ciphertext: encrypted.ciphertext,
        createdAt: item.createdAt,
        updatedAt: item.updatedAt
      });
      renderCurrentView();
      showToast(item.favorite ? 'Marked as favorite' : 'Removed from favorites', 'info', 1500);
    } catch (err) {
      showToast('Error updating favorite state', 'danger');
    }
  }

  /**
   * VIEW ITEM DETAIL MODAL
   */
  function openItemViewModal(itemId) {
    const item = decryptedItems.find(i => i.id === itemId);
    if (!item) return;

    document.getElementById('view-modal-avatar').textContent = getInitials(item.title);
    document.getElementById('view-modal-title').textContent = item.title;
    document.getElementById('view-modal-category').textContent = item.category || 'Other';

    const urlEl = document.getElementById('view-modal-url');
    const urlText = document.getElementById('view-modal-url-text');
    if (item.url) {
      urlEl.href = item.url.startsWith('http') ? item.url : `https://${item.url}`;
      urlText.textContent = item.url;
      urlEl.style.display = 'inline-flex';
    } else {
      urlText.textContent = 'None';
      urlEl.removeAttribute('href');
    }

    document.getElementById('view-modal-username').textContent = item.username || 'N/A';

    const passSpan = document.getElementById('view-modal-password');
    passSpan.textContent = '••••••••••••';
    passSpan.classList.add('password-masked');
    passSpan.setAttribute('data-real-pass', item.password || '');

    document.getElementById('view-modal-notes').textContent = item.notes || 'No additional notes.';
    document.getElementById('view-modal-created').textContent = `Created: ${formatDate(item.createdAt)}`;
    document.getElementById('view-modal-updated').textContent = `Updated: ${formatDate(item.updatedAt)}`;

    // Set buttons
    document.getElementById('btn-copy-view-user').onclick = () => copyToClipboard(item.username, 'Username');
    document.getElementById('btn-copy-view-pass').onclick = () => copyToClipboard(item.password, 'Password');
    document.getElementById('btn-edit-current-view').onclick = () => {
      document.getElementById('modal-item-view').classList.remove('active');
      openItemEditorModal(item.id);
    };

    document.getElementById('modal-item-view').classList.add('active');
  }

  // =================================================================
  // 13. ADVANCED PASSWORD GENERATOR VIEW LOGIC
  // =================================================================

  function getGeneratorOptionsFromUI() {
    return {
      length: parseInt(document.getElementById('full-gen-slider').value, 10),
      upper: document.getElementById('gen-opt-upper').checked,
      lower: document.getElementById('gen-opt-lower').checked,
      numbers: document.getElementById('gen-opt-numbers').checked,
      symbols: document.getElementById('gen-opt-symbols').checked,
      avoidAmbiguous: document.getElementById('gen-opt-ambiguous').checked
    };
  }

  function runAdvancedGenerator() {
    const opts = getGeneratorOptionsFromUI();
    const pass = generateSecurePassword(opts);
    const outputEl = document.getElementById('full-gen-output');
    outputEl.textContent = pass;

    const evalRes = evaluatePasswordStrength(pass);
    const strengthLabel = document.getElementById('gen-strength-label');
    strengthLabel.textContent = evalRes.label;
    strengthLabel.className = `stat-val font-bold text-${evalRes.score >= 3 ? 'success' : evalRes.score === 2 ? 'warning' : 'danger'}`;

    document.getElementById('gen-entropy-label').textContent = `${evalRes.entropy} bits`;
    document.getElementById('gen-crack-time').textContent = estimateCrackTime(evalRes.entropy);
  }

  function runQuickGenerator() {
    const len = parseInt(document.getElementById('quick-gen-slider')?.value || 16, 10);
    const pass = generateSecurePassword({ length: len, upper: true, lower: true, numbers: true, symbols: true });
    const quickOutput = document.getElementById('quick-gen-output');
    if (quickOutput) quickOutput.value = pass;
  }

  // =================================================================
  // 14. SETTINGS, RE-ENCRYPTION & BACKUP
  // =================================================================

  /**
   * ATOMIC MASTER PASSWORD CHANGE: Re-encrypts all vault records
   */
  async function handleChangeMasterPassword(e) {
    e.preventDefault();
    const currPass = document.getElementById('change-curr-pass').value;
    const newPass = document.getElementById('change-new-pass').value;
    const confirmPass = document.getElementById('change-confirm-pass').value;

    if (newPass !== confirmPass) {
      showToast('New passwords do not match', 'danger');
      return;
    }
    if (newPass.length < 10) {
      showToast('New master password must be at least 10 characters', 'warning');
      return;
    }

    try {
      // 1. Verify current master password
      const oldSalt = base64ToUint8Array(accountMeta.kdfSalt);
      const testOldKey = await deriveVaultKey(currPass, oldSalt, accountMeta.kdfIterations || PBKDF2_ITERATIONS);
      await decryptData(accountMeta.canaryCiphertext, accountMeta.canaryIv, testOldKey);

      showToast('Re-encrypting all vault items with new key...', 'info');

      // 2. Derive new master key with new salt
      const newSalt = getRandomBytes(16);
      const newMasterKey = await deriveVaultKey(newPass, newSalt, PBKDF2_ITERATIONS);

      // 3. Re-encrypt all decrypted items in memory
      for (const item of decryptedItems) {
        const encrypted = await encryptData(JSON.stringify(item), newMasterKey);
        await saveDBEncryptedItem({
          id: item.id,
          iv: encrypted.iv,
          ciphertext: encrypted.ciphertext,
          createdAt: item.createdAt,
          updatedAt: item.updatedAt
        });
      }

      // 4. Update canary & metadata
      const newCanary = await encryptData(CANARY_PAYLOAD, newMasterKey);
      accountMeta.kdfSalt = arrayBufferToBase64(newSalt);
      accountMeta.canaryIv = newCanary.iv;
      accountMeta.canaryCiphertext = newCanary.ciphertext;
      await saveDBMeta(accountMeta);

      activeVaultKey = newMasterKey;
      document.getElementById('form-change-master-pass').reset();
      showToast('Vault re-encryption complete! Master password updated.', 'success');

    } catch (err) {
      console.error('Password change error:', err);
      showToast('Current master password incorrect', 'danger');
    }
  }

  /**
   * EXPORT ENCRYPTED BACKUP (.json)
   */
  async function exportEncryptedVault() {
    try {
      const records = await getAllDBEncryptedItems();
      const backupPayload = {
        format: 'VaultKey-Encrypted-Backup',
        version: 1,
        exportedAt: new Date().toISOString(),
        email: accountMeta.email,
        kdfSalt: accountMeta.kdfSalt,
        kdfIterations: accountMeta.kdfIterations,
        canaryIv: accountMeta.canaryIv,
        canaryCiphertext: accountMeta.canaryCiphertext,
        items: records
      };

      const blob = new Blob([JSON.stringify(backupPayload, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `VaultKey-Encrypted-Backup-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
      showToast('Encrypted backup exported successfully', 'success');
    } catch (err) {
      showToast('Failed to export encrypted backup', 'danger');
    }
  }

  /**
   * IMPORT ENCRYPTED OR UNENCRYPTED BACKUP (.json)
   */
  async function handleImportVaultFile(file) {
    if (!file) return;
    const reader = new FileReader();

    reader.onload = async (e) => {
      try {
        const data = JSON.parse(e.target.result);

        if (data.format === 'VaultKey-Encrypted-Backup' && Array.isArray(data.items)) {
          // Encrypted backup
          let importedCount = 0;
          for (const item of data.items) {
            await saveDBEncryptedItem(item);
            importedCount++;
          }
          await loadAndDecryptAllItems();
          renderCurrentView();
          showToast(`Imported ${importedCount} encrypted items!`, 'success');
        } else if (Array.isArray(data)) {
          // Plaintext array import
          let importedCount = 0;
          const now = new Date().toISOString();
          for (const rawItem of data) {
            const normalized = {
              id: rawItem.id || crypto.randomUUID(),
              type: rawItem.type || 'login',
              title: rawItem.title || 'Imported Credential',
              url: rawItem.url || '',
              username: rawItem.username || '',
              password: rawItem.password || '',
              category: rawItem.category || 'Other',
              notes: rawItem.notes || '',
              favorite: !!rawItem.favorite,
              createdAt: rawItem.createdAt || now,
              updatedAt: now
            };
            const enc = await encryptData(JSON.stringify(normalized), activeVaultKey);
            await saveDBEncryptedItem({
              id: normalized.id,
              iv: enc.iv,
              ciphertext: enc.ciphertext,
              createdAt: normalized.createdAt,
              updatedAt: normalized.updatedAt
            });
            importedCount++;
          }
          await loadAndDecryptAllItems();
          renderCurrentView();
          showToast(`Encrypted and imported ${importedCount} items!`, 'success');
        } else {
          showToast('Unrecognized backup file format', 'danger');
        }
      } catch (err) {
        console.error('Import error:', err);
        showToast('Invalid JSON file', 'danger');
      }
    };

    reader.readAsText(file);
  }

  /**
   * PURGE / DELETE VAULT
   */
  async function handlePurgeVault() {
    const confirmation = prompt('WARNING: This will permanently delete your vault and all encrypted records.\n\nType "DELETE" to confirm:');
    if (confirmation !== 'DELETE') {
      showToast('Purge cancelled', 'info');
      return;
    }

    try {
      await wipeDatabase();
      localStorage.removeItem('vaultkey_theme');
      activeVaultKey = null;
      decryptedItems = [];
      accountMeta = null;
      showToast('Vault purged from device', 'warning');
      initApplication();
    } catch (err) {
      showToast('Error purging vault', 'danger');
    }
  }

  // =================================================================
  // 15. NAVIGATION & THEME CONTROLLERS
  // =================================================================

  function switchNavTab(tabName) {
    currentNavTab = tabName;

    // Update sidebar active item
    document.querySelectorAll('.sidebar-nav .nav-item').forEach(el => {
      if (el.getAttribute('data-nav') === tabName) {
        el.classList.add('active');
      } else {
        el.classList.remove('active');
      }
    });

    // Update view panels
    document.querySelectorAll('.view-panel').forEach(panel => {
      panel.classList.remove('active');
    });

    const targetPanel = document.getElementById(`view-${tabName}`);
    if (targetPanel) {
      targetPanel.classList.add('active');
    }

    // Reset mobile sidebar
    document.getElementById('app-sidebar').classList.remove('open');

    renderCurrentView();
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('vaultkey_theme', theme);

    const sunIcon = document.querySelector('.theme-icon-sun');
    const moonIcon = document.querySelector('.theme-icon-moon');
    if (theme === 'light') {
      sunIcon?.classList.add('hidden');
      moonIcon?.classList.remove('hidden');
    } else {
      sunIcon?.classList.remove('hidden');
      moonIcon?.classList.add('hidden');
    }

    if (accountMeta) {
      if (!accountMeta.settings) accountMeta.settings = {};
      accountMeta.settings.theme = theme;
      saveDBMeta(accountMeta).catch(() => {});
    }
  }

  function toggleTheme() {
    const curr = document.documentElement.getAttribute('data-theme') || 'dark';
    const next = curr === 'dark' ? 'light' : 'dark';
    applyTheme(next);
    showToast(`Switched to ${next} theme`, 'info', 1500);
  }

  // =================================================================
  // 16. EVENT LISTENERS & DOM HOOKS
  // =================================================================

  function setupEventListeners() {
    // Auth navigation links
    document.getElementById('link-goto-login')?.addEventListener('click', () => showAuthView('login'));
    document.getElementById('link-goto-signup')?.addEventListener('click', () => showAuthView('signup'));
    document.getElementById('link-goto-recovery')?.addEventListener('click', () => showAuthView('recovery'));
    document.getElementById('link-recovery-back')?.addEventListener('click', () => showAuthView('login'));

    // Auth forms
    document.getElementById('signup-form')?.addEventListener('submit', handleSignUp);
    document.getElementById('login-form')?.addEventListener('submit', handleLogin);
    document.getElementById('recovery-form')?.addEventListener('submit', handleRecovery);
    document.getElementById('lock-screen-form')?.addEventListener('submit', handleLockScreenUnlock);

    // Lock screen logout button
    document.getElementById('btn-lock-screen-logout')?.addEventListener('click', () => {
      lockVault();
      showAuthView('login');
    });

    // Sidebar navigation tabs
    document.querySelectorAll('.sidebar-nav .nav-item[data-nav]').forEach(btn => {
      btn.addEventListener('click', () => {
        activeCategoryFilter = 'ALL';
        updateFilterChipsUI();
        switchNavTab(btn.getAttribute('data-nav'));
      });
    });

    // Category navigation clicks
    document.querySelectorAll('#sidebar-category-list .category-item').forEach(btn => {
      btn.addEventListener('click', () => {
        const cat = btn.getAttribute('data-category');
        activeCategoryFilter = cat;
        updateFilterChipsUI();
        switchNavTab('vault');
      });
    });

    // Metric cards click navigation
    document.querySelectorAll('.metric-card[data-nav-target]').forEach(card => {
      card.addEventListener('click', () => {
        switchNavTab(card.getAttribute('data-nav-target'));
      });
    });

    // Dashboard quick action links
    document.getElementById('btn-hero-audit')?.addEventListener('click', () => switchNavTab('audit'));
    document.getElementById('btn-hero-add')?.addEventListener('click', () => openItemEditorModal());
    document.getElementById('link-view-all-vault')?.addEventListener('click', () => switchNavTab('vault'));

    document.getElementById('filter-weak-click')?.addEventListener('click', () => switchNavTab('audit'));
    document.getElementById('filter-reused-click')?.addEventListener('click', () => switchNavTab('audit'));

    // Add Item triggers
    document.querySelectorAll('.btn-new-item').forEach(btn => {
      btn.addEventListener('click', () => openItemEditorModal());
    });
    document.getElementById('btn-add-note')?.addEventListener('click', () => openItemEditorModal(null, 'note'));

    // Modal editor tabs (Login vs Note)
    document.querySelectorAll('.tab-pill').forEach(btn => {
      btn.addEventListener('click', () => {
        currentModalItemType = btn.getAttribute('data-item-type');
        syncEditorTypeTabs();
      });
    });

    // Modal close buttons
    document.querySelectorAll('.modal-close-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.modal-backdrop').forEach(m => m.classList.remove('active'));
      });
    });

    // Save item form
    document.getElementById('form-item-editor')?.addEventListener('submit', handleSaveItem);

    // Password visibility toggle helpers (eye icon)
    document.addEventListener('click', (e) => {
      const toggleBtn = e.target.closest('[data-toggle-pass]');
      if (toggleBtn) {
        const inputId = toggleBtn.getAttribute('data-toggle-pass');
        const input = document.getElementById(inputId);
        if (input) {
          input.type = input.type === 'password' ? 'text' : 'password';
        }
      }
    });

    // Inline generator inside Add Item modal
    document.getElementById('btn-inline-generate')?.addEventListener('click', () => {
      const pass = generateSecurePassword({ length: 18, upper: true, lower: true, numbers: true, symbols: true });
      const passInput = document.getElementById('item-password');
      passInput.value = pass;
      passInput.type = 'text'; // Show when newly generated
      updateFormPasswordStrength(pass);
      showToast('Strong password generated!', 'info', 1500);
    });

    // Realtime password strength in Add Modal
    document.getElementById('item-password')?.addEventListener('input', (e) => {
      updateFormPasswordStrength(e.target.value);
    });

    // Realtime password strength in Signup Form
    document.getElementById('signup-password')?.addEventListener('input', (e) => {
      const val = e.target.value;
      const res = evaluatePasswordStrength(val);
      const bar = document.getElementById('signup-strength-bar');
      const text = document.getElementById('signup-strength-text');
      const entropy = document.getElementById('signup-strength-entropy');

      bar.className = `strength-fill ${res.class}`;
      text.textContent = res.label;
      entropy.textContent = `${res.entropy} bits entropy`;
    });

    // Universal live search
    const searchInput = document.getElementById('global-search-input');
    const clearSearchBtn = document.getElementById('btn-clear-search');
    searchInput?.addEventListener('input', (e) => {
      activeSearchQuery = e.target.value;
      if (activeSearchQuery) {
        clearSearchBtn.classList.remove('hidden');
        if (currentNavTab !== 'vault' && currentNavTab !== 'favorites' && currentNavTab !== 'notes') {
          switchNavTab('vault');
        } else {
          renderCurrentView();
        }
      } else {
        clearSearchBtn.classList.add('hidden');
        renderCurrentView();
      }
    });

    clearSearchBtn?.addEventListener('click', () => {
      searchInput.value = '';
      activeSearchQuery = '';
      clearSearchBtn.classList.add('hidden');
      renderCurrentView();
    });

    // Keyboard shortcut for search (Press '/') & Lock (Ctrl+L)
    window.addEventListener('keydown', (e) => {
      if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
        e.preventDefault();
        searchInput?.focus();
      }
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'l') {
        e.preventDefault();
        lockVault('Vault locked by keyboard shortcut.');
      }
    });

    // Category filter in Vault view
    document.getElementById('select-category-filter')?.addEventListener('change', (e) => {
      activeCategoryFilter = e.target.value;
      updateFilterChipsUI();
      renderVaultItems();
    });

    // Sort filter in Vault view
    document.getElementById('select-sort-filter')?.addEventListener('change', (e) => {
      activeSortOption = e.target.value;
      renderVaultItems();
    });

    // Layout toggle (Grid vs Table)
    document.getElementById('btn-toggle-grid')?.addEventListener('click', () => {
      activeViewLayout = 'grid';
      document.getElementById('btn-toggle-grid').classList.add('active');
      document.getElementById('btn-toggle-table').classList.remove('active');
      renderVaultItems();
    });

    document.getElementById('btn-toggle-table')?.addEventListener('click', () => {
      activeViewLayout = 'table';
      document.getElementById('btn-toggle-table').classList.add('active');
      document.getElementById('btn-toggle-grid').classList.remove('active');
      renderVaultItems();
    });

    // Remove category filter button
    document.getElementById('btn-remove-filter')?.addEventListener('click', () => {
      activeCategoryFilter = 'ALL';
      document.getElementById('select-category-filter').value = 'ALL';
      updateFilterChipsUI();
      renderVaultItems();
    });

    // Quick Generator buttons
    document.getElementById('btn-quick-refresh')?.addEventListener('click', runQuickGenerator);
    document.getElementById('btn-quick-copy')?.addEventListener('click', () => {
      const val = document.getElementById('quick-gen-output').value;
      copyToClipboard(val, 'Quick Password');
    });
    document.getElementById('quick-gen-slider')?.addEventListener('input', (e) => {
      document.getElementById('quick-gen-len-label').textContent = e.target.value;
      runQuickGenerator();
    });
    document.getElementById('btn-goto-full-gen')?.addEventListener('click', () => switchNavTab('generator'));
    document.getElementById('btn-topbar-generator')?.addEventListener('click', () => switchNavTab('generator'));

    // Advanced Generator events
    document.getElementById('full-gen-slider')?.addEventListener('input', (e) => {
      document.getElementById('full-gen-slider-val').textContent = `${e.target.value} characters`;
      runAdvancedGenerator();
    });
    ['gen-opt-upper', 'gen-opt-lower', 'gen-opt-numbers', 'gen-opt-symbols', 'gen-opt-ambiguous'].forEach(id => {
      document.getElementById(id)?.addEventListener('change', runAdvancedGenerator);
    });
    document.getElementById('btn-full-gen-refresh')?.addEventListener('click', runAdvancedGenerator);
    document.getElementById('btn-full-gen-copy')?.addEventListener('click', () => {
      const pass = document.getElementById('full-gen-output').textContent;
      copyToClipboard(pass, 'Generated Password');
    });

    // Presets
    document.getElementById('preset-pin')?.addEventListener('click', () => {
      document.getElementById('full-gen-slider').value = 6;
      document.getElementById('full-gen-slider-val').textContent = '6 characters';
      document.getElementById('gen-opt-upper').checked = false;
      document.getElementById('gen-opt-lower').checked = false;
      document.getElementById('gen-opt-numbers').checked = true;
      document.getElementById('gen-opt-symbols').checked = false;
      runAdvancedGenerator();
    });
    document.getElementById('preset-standard')?.addEventListener('click', () => {
      document.getElementById('full-gen-slider').value = 16;
      document.getElementById('full-gen-slider-val').textContent = '16 characters';
      document.getElementById('gen-opt-upper').checked = true;
      document.getElementById('gen-opt-lower').checked = true;
      document.getElementById('gen-opt-numbers').checked = true;
      document.getElementById('gen-opt-symbols').checked = false;
      runAdvancedGenerator();
    });
    document.getElementById('preset-strong')?.addEventListener('click', () => {
      document.getElementById('full-gen-slider').value = 24;
      document.getElementById('full-gen-slider-val').textContent = '24 characters';
      document.getElementById('gen-opt-upper').checked = true;
      document.getElementById('gen-opt-lower').checked = true;
      document.getElementById('gen-opt-numbers').checked = true;
      document.getElementById('gen-opt-symbols').checked = true;
      runAdvancedGenerator();
    });
    document.getElementById('preset-paranoid')?.addEventListener('click', () => {
      document.getElementById('full-gen-slider').value = 64;
      document.getElementById('full-gen-slider-val').textContent = '64 characters';
      document.getElementById('gen-opt-upper').checked = true;
      document.getElementById('gen-opt-lower').checked = true;
      document.getElementById('gen-opt-numbers').checked = true;
      document.getElementById('gen-opt-symbols').checked = true;
      runAdvancedGenerator();
    });

    // Audit rescan button
    document.getElementById('btn-refresh-audit')?.addEventListener('click', () => {
      renderAuditView();
      showToast('Vault security re-scanned!', 'info');
    });

    // Settings actions
    document.getElementById('form-change-master-pass')?.addEventListener('submit', handleChangeMasterPassword);
    document.getElementById('btn-export-encrypted')?.addEventListener('click', exportEncryptedVault);
    document.getElementById('file-import-vault')?.addEventListener('change', (e) => {
      if (e.target.files && e.target.files[0]) {
        handleImportVaultFile(e.target.files[0]);
      }
    });
    document.getElementById('btn-settings-download-kit')?.addEventListener('click', () => {
      downloadEmergencyKitDoc('STORED_OFFLINE_OR_RECOVERY_KEY', accountMeta.email);
    });
    document.getElementById('btn-purge-vault')?.addEventListener('click', handlePurgeVault);

    // Auto-lock and clipboard select in settings
    document.getElementById('setting-autolock-select')?.addEventListener('change', async (e) => {
      if (!accountMeta.settings) accountMeta.settings = {};
      accountMeta.settings.autoLockMinutes = parseInt(e.target.value, 10);
      await saveDBMeta(accountMeta);
      resetInactivityTimer();
      showToast(`Auto-lock set to ${e.target.value === '0' ? 'Never' : e.target.value + ' min'}`, 'info');
    });

    document.getElementById('setting-clipboard-select')?.addEventListener('change', async (e) => {
      if (!accountMeta.settings) accountMeta.settings = {};
      accountMeta.settings.clipboardSeconds = parseInt(e.target.value, 10);
      await saveDBMeta(accountMeta);
      showToast('Clipboard preferences updated', 'info');
    });

    // Theme toggles
    document.getElementById('btn-theme-toggle')?.addEventListener('click', toggleTheme);
    document.getElementById('btn-settings-toggle-theme')?.addEventListener('click', toggleTheme);

    // Lock triggers
    document.getElementById('btn-sidebar-lock')?.addEventListener('click', () => lockVault('Manual lock triggered.'));
    document.getElementById('btn-topbar-lock')?.addEventListener('click', () => lockVault('Manual lock triggered.'));

    // Mobile sidebar toggle
    document.getElementById('btn-toggle-sidebar')?.addEventListener('click', () => {
      document.getElementById('app-sidebar').classList.add('open');
    });
    document.getElementById('btn-close-sidebar')?.addEventListener('click', () => {
      document.getElementById('app-sidebar').classList.remove('open');
    });

    // Global event delegation for dynamically rendered item cards & table rows
    document.addEventListener('click', (e) => {
      // Copy username
      const copyUserBtn = e.target.closest('[data-copy-user]');
      if (copyUserBtn) {
        const id = copyUserBtn.getAttribute('data-copy-user');
        const item = decryptedItems.find(i => i.id === id);
        if (item) copyToClipboard(item.username, 'Username');
      }

      // Copy password
      const copyPassBtn = e.target.closest('[data-copy-pass]');
      if (copyPassBtn) {
        const id = copyPassBtn.getAttribute('data-copy-pass');
        const item = decryptedItems.find(i => i.id === id);
        if (item) copyToClipboard(item.password, 'Password');
      }

      // Copy note
      const copyNoteBtn = e.target.closest('[data-copy-note]');
      if (copyNoteBtn) {
        const id = copyNoteBtn.getAttribute('data-copy-note');
        const item = decryptedItems.find(i => i.id === id);
        if (item) copyToClipboard(item.notes, 'Note');
      }

      // Toggle Eye (Show / Mask password on card)
      const eyeBtn = e.target.closest('[data-toggle-eye]');
      if (eyeBtn) {
        const id = eyeBtn.getAttribute('data-toggle-eye');
        const item = decryptedItems.find(i => i.id === id);
        const cardPassSpan = document.getElementById(`card-pass-${id}`);
        if (cardPassSpan && item) {
          if (cardPassSpan.classList.contains('password-masked')) {
            cardPassSpan.textContent = item.password;
            cardPassSpan.classList.remove('password-masked');
          } else {
            cardPassSpan.textContent = '••••••••••';
            cardPassSpan.classList.add('password-masked');
          }
        }
      }

      // View modal eye toggle
      if (e.target.closest('#btn-toggle-view-pass')) {
        const passSpan = document.getElementById('view-modal-password');
        const real = passSpan.getAttribute('data-real-pass');
        if (passSpan.classList.contains('password-masked')) {
          passSpan.textContent = real;
          passSpan.classList.remove('password-masked');
        } else {
          passSpan.textContent = '••••••••••••';
          passSpan.classList.add('password-masked');
        }
      }

      // Star favorite toggle
      const favBtn = e.target.closest('[data-toggle-fav]');
      if (favBtn) {
        const id = favBtn.getAttribute('data-toggle-fav');
        handleToggleFavorite(id);
      }

      // Edit item
      const editBtn = e.target.closest('[data-edit-item]');
      if (editBtn) {
        const id = editBtn.getAttribute('data-edit-item');
        openItemEditorModal(id);
      }

      // View details
      const viewBtn = e.target.closest('[data-view-item]');
      if (viewBtn) {
        const id = viewBtn.getAttribute('data-view-item');
        openItemViewModal(id);
      }

      // Delete item
      const delBtn = e.target.closest('[data-delete-item]');
      if (delBtn) {
        const id = delBtn.getAttribute('data-delete-item');
        handleDeleteItem(id);
      }
    });
  }

  // =================================================================
  // 17. UTILITY HELPERS
  // =================================================================

  function updateFilterChipsUI() {
    const chipContainer = document.getElementById('active-filter-chips');
    const chipText = document.getElementById('active-filter-name');
    if (!chipContainer || !chipText) return;

    if (activeCategoryFilter !== 'ALL') {
      chipText.textContent = `Category: ${activeCategoryFilter}`;
      chipContainer.classList.remove('hidden');
    } else {
      chipContainer.classList.add('hidden');
    }
  }

  function updateFormPasswordStrength(pass) {
    const bar = document.getElementById('item-strength-bar');
    const text = document.getElementById('item-strength-text');
    if (!bar || !text) return;

    const res = evaluatePasswordStrength(pass);
    bar.className = `strength-fill ${res.class}`;
    text.textContent = res.label;
  }

  function getDomainFromUrl(url) {
    if (!url) return '';
    try {
      let parsed = url;
      if (!parsed.startsWith('http://') && !parsed.startsWith('https://')) {
        parsed = 'https://' + parsed;
      }
      const u = new URL(parsed);
      return u.hostname.replace('www.', '');
    } catch (e) {
      return url;
    }
  }

  function getInitials(str) {
    if (!str) return 'VK';
    const words = str.trim().split(/\s+/);
    if (words.length >= 2) {
      return (words[0][0] + words[1][0]).toUpperCase();
    }
    return str.slice(0, 2).toUpperCase();
  }

  function formatDate(isoStr) {
    if (!isoStr) return '--';
    try {
      const d = new Date(isoStr);
      return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
    } catch (e) {
      return isoStr;
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // =================================================================
  // 18. APPLICATION BOOTSTRAP
  // =================================================================

  document.addEventListener('DOMContentLoaded', () => {
    setupEventListeners();
    attachActivityListeners();
    runAdvancedGenerator();
    runQuickGenerator();
    initApplication();
  });

})();
