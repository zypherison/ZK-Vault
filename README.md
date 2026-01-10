# 🔐 ZK-Vault: Zero-Knowledge Password Manager

> **"Server-Blind" Architecture**: The database stores only encrypted garbage. Even the admin cannot decrypt your passwords.

![CI/CD](https://github.com/zypherison/ZK-Vault/actions/workflows/main.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue)
![Security](https://img.shields.io/badge/security-Argon2id%20%2B%20AES--256--GCM-green)

## 🎯 **Core Concept**
Most password managers encrypt data, but **ZK-Vault** ensures the server *never* sees the encryption key.
1. **Client-Side Derivation**: Your Master Password never leaves your device.
2. **Argon2 Hardening**: Keys are derived using memory-hard Argon2id (resistant to GPU cracking).
3. **AES-256-GCM**: Data is encrypted/authenticated locally before transmission.

---

## 📸 **The "Golden" Feature: Side-by-Side View**

| **User View (Client)** | **Server View (Admin/DB)** |
|------------------------|----------------------------|
| ✅ `Netflix: user1 / pass***` | ❌ `x7K9pQ2m...` (random blob) |
| ✅ `GMail: me@gmail.com` | ❌ `jL4vR9tP...` (cannot decrypt) |
| 🔓 **Decrypted in Browser** | 🔒 **Encrypted Storage Only** |

---

## 🛠️ **Tech Stack**
- **Frontend**: HTML5, Vanilla CSS (Premium Dark Mode), WebCrypto API (AES-GCM), Argon2 (WASM)
- **Backend**: Flask (Python), SQLite
- **Security**: 
    - `Argon2id` for Key Derivation & Password Hashing
    - `AES-256-GCM` for Vault Encyption
    - `HaveIBeenPwned` k-anonymity API for Breach Detection
    - `Secure Notes`: Encrypted client-side notepad
    - `Encrypted Attachments`: Securely store files inside the vault blob
    - `Import/Export`: Bulk CSV import and JSON backup support

---

## 🚀 **Quick Start**

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the App
```bash
python app.py
```

### 3. Open Browser
- Go to `http://localhost:5000`
- **Register**: Enter a username & master password. (Watch the "Deriving Keys" status).
- **Vault**: Add passwords. They are encrypted *instantly* in your browser.
- **Admin**: Go to `/admin` to see the "Garbage" the server holds.
    - **Username**: `admin`
    - **Password**: `admin123`

---

## 🔒 Security Implementation Details

### Zero-Knowledge Auth Protocol
1. **User enters Master Password**.
2. **Client**: Generates `Salt`. Calculates `AuthKey = Argon2(MP, Salt)`.
3. **Client**: Calculates `EncryptionKey = Argon2(MP, Salt')`.
4. **Client**: Sends `AuthKey` to Server. Keeps `EncryptionKey` in memory.
5. **Server**: Hashes `AuthKey` again and stores it. Verifies login without knowing `MP`.

### Vault Encryption
```javascript
// Actual Code (static/js/vault.js)
const key = await deriveKey(masterPassword, salt); // Argon2
const iv = window.crypto.getRandomValues(new Uint8Array(12));
const encrypted = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    data
);
```

---

## 🧪 Running Tests
```bash
pytest tests/
```
*Coverage: Argon2 Hashing, AES Roundtrip, Anti-Decrypt Verification, HIBP API.*

### 🛡️ **Security Strength Auditor**
We include a specialized script to verify the "Armored" state of the application.
```bash
python security_audit.py
```
**Checks performed:**
- **Security Headers**: Verifies CSP, HSTS, and Anti-Clickjacking headers.
- **WASM Integrity**: Confirms SRI (Subresource Integrity) hashes for Argon2.
- **Crypto Complexity**: Validates Argon2 memory-hard parameters.


---

## 💼 Why This Matters
- **Fintech Standard**: Uses the same logic as 1Password/LastPass Enterprise.
- **Modern Crypto**: Not just SHA-256; uses memory-hard functions.
- **Privacy First**: Demonstrates architectural understanding of "Trust No One" (TNO) models.

---

## 🌩️ **Permanent Data Persistence (Turso)**
To prevent data loss on Render's ephemeral disk, ZK-Vault supports **Turso** (Serverless SQLite).
1.  **Create a DB**: Sign up at [Turso.tech](https://turso.tech) and create a new database.
2.  **Get Credentials**: Get your `TURSO_DATABASE_URL` and `TURSO_AUTH_TOKEN`.
3.  **Deploy to Render**: Add these two as **Environment Variables** in your Render dashboard.
    *   The app will automatically switch from local SQLite to Turso Cloud!

---

*Note: This project is designed for educational purposes to demonstrate advanced Zero-Knowledge architectural principles.*
