// ZK-Vault Client-Side Crypto Engine
// Uses WebCrypto API (AES-GCM) and Argon2 (via WASM)

const CONFIG = {
    algo: {
        name: "AES-GCM",
        length: 256
    },
    argon2: {
        time: 2,
        mem: 1024 * 64, // 64MB matches server config logic
        hashLen: 32,
        parallelism: 4,
        type: (typeof argon2 !== 'undefined') ? argon2.Argon2id : 2 // Default to Argon2id if possible
    }
};

// --- Utilities ---
const strToBuf = (str) => new TextEncoder().encode(str);
const bufToStr = (buf) => new TextDecoder().decode(buf);
const bufToHex = (buf) => [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, '0')).join('');
const hexToBuf = (hex) => new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
const toBase64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const fromBase64 = (str) => Uint8Array.from(atob(str), c => c.charCodeAt(0));

function showLoading(msg) {
    const overlay = document.getElementById('loading-overlay');
    const msgEl = document.getElementById('overlay-msg');
    if (overlay) {
        if (msg) msgEl.textContent = msg;
        overlay.classList.add('visible');
    }
}

function hideLoading() {
    const overlay = document.getElementById('loading-overlay');
    if (overlay) overlay.classList.remove('visible');
}

function showToast(msg) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = `<i data-lucide="shield-check" style="color: var(--accent-color)"></i> ${msg}`;

    container.appendChild(toast);
    if (window.lucide) lucide.createIcons();

    // Auto-remove after 5 seconds (longer duration)
    setTimeout(() => {
        toast.classList.add('fade-out');
        setTimeout(() => toast.remove(), 500);
    }, 5000);
}

// --- Core Crypto ---

async function deriveKeys(password, salt) {
    // We derive ONE master key using Argon2, then split it or use it to derive subkeys?
    // User Requirement: "Master Password -> Argon2 -> Encryption Key"
    // We need: 1. Auth Hash (to send to server), 2. Encryption Key (to keep local)

    // Strategy: Derive 64 bytes. First 32 = Auth, Last 32 = Encryption Key (Simplest)
    // Actually argon2-browser returns a hash string or array.

    try {
        const result = await argon2.hash({
            pass: password,
            salt: salt,
            time: CONFIG.argon2.time,
            mem: CONFIG.argon2.mem,
            hashLen: 64, // Get 64 bytes
            parallelism: CONFIG.argon2.parallelism,
            type: CONFIG.argon2.type
        });

        const hashBytes = result.hash;

        // Split 64 bytes
        const authKeyBytes = hashBytes.slice(0, 32);
        const encKeyBytes = hashBytes.slice(32, 64);

        // Return hex strings for convenience/storage
        return {
            authHash: bufToHex(authKeyBytes),
            encryptionKey: toBase64(encKeyBytes) // Base64 for WebCrypto import
        };
    } catch (e) {
        console.error("Argon2 Error:", e);
        throw e;
    }
}

async function encryptVault(dataObj, keyBase64) {
    // Import Key
    const key = await window.crypto.subtle.importKey(
        "raw",
        fromBase64(keyBase64),
        CONFIG.algo,
        false,
        ["encrypt"]
    );

    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const dataStr = JSON.stringify(dataObj);

    const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        strToBuf(dataStr)
    );

    // Combine IV + Ciphertext
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);

    return toBase64(combined);
}

async function decryptVault(blobBase64, keyBase64) {
    if (!blobBase64) return [];

    const key = await window.crypto.subtle.importKey(
        "raw",
        fromBase64(keyBase64),
        CONFIG.algo,
        false,
        ["decrypt"]
    );

    const combined = fromBase64(blobBase64);
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);

    try {
        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            ciphertext
        );
        return JSON.parse(bufToStr(decrypted));
    } catch (e) {
        console.error("Decryption failed:", e);
        throw new Error("Failed to decrypt vault. Wrong password or corrupted data.");
    }
}

// --- App Logic ---

async function handleRegister() {
    const user = document.getElementById('username').value;
    const pass = document.getElementById('password').value;
    const btn = document.getElementById('login-btn');
    const msg = document.getElementById('status-msg');

    if (!user || !pass) { msg.textContent = "Please fill all fields"; return; }

    showLoading("Generating Zero-Knowledge Keys (Argon2)... please wait");
    btn.disabled = true;

    // Generate new random salt
    const salt = bufToHex(window.crypto.getRandomValues(new Uint8Array(16)));

    try {
        const keys = await deriveKeys(pass, salt);

        // Create empty vault
        const initialVault = [];

        const encryptedBlob = await encryptVault(initialVault, keys.encryptionKey);

        showLoading("Syncing Vault with Server...");
        // Send to server
        const res = await fetch('/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: user,
                auth_hash: keys.authHash,
                salt: salt,
                encrypted_blob: encryptedBlob
            })
        });

        const data = await res.json();
        if (data.status === 'success') {
            sessionStorage.setItem('encryptionKey', keys.encryptionKey);
            window.location.href = data.redirect;
        } else {
            hideLoading();
            msg.textContent = "Error: " + data.message;
        }
    } catch (e) {
        hideLoading();
        msg.textContent = "Error: " + e.message;
    } finally {
        btn.disabled = false;
    }
}

async function handleLogin() {
    const user = document.getElementById('username').value;
    const pass = document.getElementById('password').value;
    const btn = document.getElementById('login-btn');
    const msg = document.getElementById('status-msg');

    showLoading("Authenticating...");
    btn.disabled = true;

    // Check for hardcoded Admin
    if (user === "admin") {
        try {
            const res = await fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: user, password: pass })
            });
            const data = await res.json();
            if (data.status === 'success') {
                showLoading("Entering Command Center...");
                window.location.href = data.redirect;
                return;
            } else {
                throw new Error(data.message || "Invalid Admin Credentials");
            }
        } catch (e) {
            hideLoading();
            msg.textContent = "Admin Login Failed: " + e.message;
            btn.disabled = false;
            return;
        }
    }

    // User needs existing salt to derive keys. 
    // PROBLEM: We need the salt BEFORE we can authenticate?
    // Solution: We must ask the server for the user's salt first (unauthenticated or finding by username).
    // In strict ZK, salt is public or stored with the user record.
    // Let's first "get_salt" from server? 
    // Wait, the `/vault` API endpoint gets Blob and Salt, but that requires auth.
    // We should expose a `/api/salt/<username>` endpoint or just return it on failed login?
    // Actually, simpler: Login request sends Username. Server looks up Salt.
    // Server says "Here is the salt". 
    // Client computes Hash. Sends Hash. 
    // That's 2 round trips.
    // Alternative: We try to login without hash? No.
    // Let's Assume for this MVP: 
    // 1. Client fetches Salt for Username.
    // 2. Client derives Keys.
    // 3. Client POST /login.

    // We need an endpoint to get salt. I forgot it in `app.py`.
    // I will mock it or just assume we can get it? 
    // I can modify `app.py` or try a different approach.
    // Let's auto-handle it in `handleLogin`:

    try {
        // Step 1: Get Salt (We need a new endpoint or piggyback)
        // I'll add `/api/salt` to app.py in a fix up step.
        // For now let's assume I will add it.
        const saltRes = await fetch(`/api/user_salt?username=${encodeURIComponent(user)}`);
        if (!saltRes.ok) throw new Error("User not found");
        const saltData = await saltRes.json();
        const salt = saltData.salt;

        showLoading("Deriving Secure Keys (Argon2)...");
        const keys = await deriveKeys(pass, salt);

        showLoading("Verifying Credentials...");
        const res = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: user,
                auth_hash: keys.authHash
            })
        });

        const data = await res.json();
        if (data.status === 'success') {
            sessionStorage.setItem('encryptionKey', keys.encryptionKey);
            // Also store username
            sessionStorage.setItem('zk_user', user);
            window.location.href = data.redirect;
        } else {
            hideLoading();
            msg.textContent = "Login Failed: " + data.message;
        }
    } catch (e) {
        hideLoading();
        msg.textContent = "Login Failed: " + e.message;
    } finally {
        btn.disabled = false;
    }
}

async function loadVault() {
    const list = document.getElementById('vault-list');
    const empty = document.getElementById('empty-state');
    const loadDiv = document.getElementById('loading');

    try {
        const res = await fetch('/api/vault');
        if (res.status === 401) { window.location.href = '/login'; return; }

        const data = await res.json();
        const key = sessionStorage.getItem('encryptionKey');

        const vaultItems = await decryptVault(data.encrypted_blob, key);

        loadDiv.classList.add('hidden');
        if (vaultItems.length === 0) {
            empty.classList.remove('hidden');
        } else {
            list.classList.remove('hidden');
            renderVault(vaultItems);
        }

        // Store vault in memory for updates (simple global)
        window.currentVault = vaultItems;

    } catch (e) {
        loadDiv.textContent = "Error loading vault: " + e.message;
    }
}

const pwnedCache = new Map();

async function renderVault(items) {
    const list = document.getElementById('vault-list');
    list.innerHTML = "";

    // PARALLEL OPTIMIZATION: Start all pwned checks simultaneously
    const pwnedPromises = items.map(async (item) => {
        if (pwnedCache.has(item.pass)) return pwnedCache.get(item.pass);
        const count = await checkPwnedCount(item.pass);
        pwnedCache.set(item.pass, count);
        return count;
    });

    const pwnedCounts = await Promise.all(pwnedPromises);

    for (const [index, item] of items.entries()) {
        const li = document.createElement('li');
        li.className = 'vault-item';
        li.id = `item-${index}`;

        const pwnedCount = pwnedCounts[index];
        const isPwned = pwnedCount > 0;

        const badge = isPwned
            ? `<span class="badge badge-pwned" title="${pwnedCount} breaches">PWNED (${formatCount(pwnedCount)})</span>`
            : `<span class="badge badge-safe">SAFE</span>`;

        li.innerHTML = `
            <div class="item-main">
                <div class="item-details">
                    <span class="item-title" style="display: flex; align-items: center; gap: 8px;">
                        <i data-lucide="globe"></i>
                        ${item.site} ${badge}
                    </span>
                    <div class="item-meta" style="display: flex; align-items: center; gap: 6px; margin-top: 4px;">
                        <i data-lucide="user"></i> ${item.username} 
                        <span style="opacity: 0.3">•</span> 
                        <i data-lucide="lock"></i> ••••••••
                    </div>
                </div>
                <div class="actions">
                    <button class="icon-btn" onclick="copyPass(${index})" title="Copy Password"><i data-lucide="copy"></i></button>
                    <button class="icon-btn" onclick="togglePass(${index})" title="Show Password"><i data-lucide="eye"></i></button>
                    <button class="icon-btn" onclick="startEdit(${index})" title="Edit Entry"><i data-lucide="edit-3"></i></button>
                    <button class="icon-btn" onclick="deletePassword(${index})" style="color: var(--danger-color);" title="Delete"><i data-lucide="trash-2"></i></button>
                </div>
            </div>
            
            <div id="pass-reveal-${index}" class="hidden">
                 <div class="revealed-pass">
                    <code style="color: var(--text-primary); font-size: 16px;">${item.pass}</code>
                    <button class="icon-btn" style="font-size: 10px;" onclick="navigator.clipboard.writeText('${item.pass}'); showToast('Copied!')"><i data-lucide="copy"></i></button>
                 </div>
            </div>

            ${item.notes ? `<div class="note-box" style="display: flex; gap: 10px; align-items: flex-start;">
                <i data-lucide="sticky-note"></i>
                <span>${item.notes}</span>
            </div>` : ''}
            
            ${item.file ? `
                <a href="${item.file.data}" download="${item.file.name}" class="file-link" style="padding: 10px; background: rgba(255,255,255,0.03); border-radius: 8px; border: 1px solid var(--border-color);">
                    <i data-lucide="file-text"></i>
                    <span>${item.file.name}</span>
                    <i data-lucide="download" style="margin-left: auto; opacity: 0.5;"></i>
                </a>
            ` : ''}

            ${isPwned ? `
            <div style="margin-top: 10px; padding: 12px; background: rgba(255, 0, 0, 0.05); border: 1px solid var(--danger-color); border-radius: 12px; font-size: 13px; display: flex; align-items: center; gap: 10px;">
                <i data-lucide="alert-triangle" style="color: var(--danger-color)"></i>
                <div style="flex-grow: 1;">
                    <span style="color: #ff5555; font-weight: 600;">Security Vulnerability:</span> Found in ${formatCount(pwnedCount)} breaches.
                </div>
                <button onclick="generateSecurePassword(${index})" style="padding: 6px 12px; font-size: 12px; width: auto; background: var(--danger-color);">Rotate Password</button>
            </div>
            ` : ''}
        `;
        list.appendChild(li);
    }
    if (window.lucide) {
        lucide.createIcons({
            attrs: {
                stroke: 'currentColor',
                'stroke-width': 2,
                width: 18,
                height: 18
            }
        });
    }
}

function togglePass(index) {
    const el = document.getElementById(`pass-reveal-${index}`);
    if (el.classList.contains('hidden')) {
        el.classList.remove('hidden');
    } else {
        el.classList.add('hidden');
    }
}

async function syncVault() {
    // Calculate Metrics for ZK Metadata
    let totalPwned = 0;
    let itemCount = window.currentVault.length;
    let noteCount = 0;
    let fileCount = 0;

    for (const item of window.currentVault) {
        totalPwned += await checkPwnedCount(item.pass);
        if (item.notes && item.notes.trim() !== "") noteCount++;
        if (item.file) fileCount++;
    }

    // Encrypt and Sync
    const key = sessionStorage.getItem('encryptionKey');
    const blob = await encryptVault(window.currentVault, key);

    await fetch('/api/vault', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            encrypted_blob: blob,
            pwned_count: totalPwned,
            security_score: itemCount > 0 ? (totalPwned === 0 ? 100 : Math.max(0, 100 - (totalPwned * 10))) : 100,
            item_count: itemCount,
            note_count: noteCount,
            file_count: fileCount
        })
    });
}

async function generateSecurePassword(index) {
    const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=";
    let pass = "";
    for (let i = 0; i < 20; i++) {
        pass += chars.charAt(Math.floor(Math.random() * chars.length));
    }

    // Update the actual vault data (NO DUPLICATES)
    window.currentVault[index].pass = pass;
    window.currentVault[index].date = new Date().toISOString();

    // Sync encrypted blob to server
    await syncVault();

    // Copy to clipboard for user convenience anyway
    navigator.clipboard.writeText(pass);

    showToast("Security Fix Applied! Password updated and copied.");

    // Rerender UI
    renderVault(window.currentVault);
}

let currentEditIndex = null;

function startEdit(index) {
    const item = window.currentVault[index];
    currentEditIndex = index;

    document.getElementById('new-site').value = item.site;
    document.getElementById('new-user').value = item.username;
    document.getElementById('new-pass').value = item.pass;
    document.getElementById('new-notes').value = item.notes || "";

    const addBtn = document.querySelector('button[onclick="addPassword()"]');
    addBtn.innerHTML = `<i data-lucide="save" size="16"></i> Save Changes`;
    addBtn.style.background = "var(--accent-color)";

    const cancelBtn = document.getElementById('cancel-edit-btn');
    if (cancelBtn) cancelBtn.style.display = 'block';

    // Highlight the item being edited
    document.querySelectorAll('.vault-item').forEach(el => el.classList.remove('editing-mode'));
    const itemEl = document.getElementById(`item-${index}`);
    if (itemEl) itemEl.classList.add('editing-mode');

    // Re-init icons for the button
    if (window.lucide) lucide.createIcons();

    // Scroll to form
    document.querySelector('.card').scrollIntoView({ behavior: 'smooth' });
}

function cancelEdit() {
    currentEditIndex = null;
    document.getElementById('new-site').value = "";
    document.getElementById('new-user').value = "";
    document.getElementById('new-pass').value = "";
    document.getElementById('new-notes').value = "";

    const addBtn = document.querySelector('button[onclick="addPassword()"]');
    addBtn.innerHTML = "Add +";
    addBtn.style.background = "";

    const cancelBtn = document.getElementById('cancel-edit-btn');
    if (cancelBtn) cancelBtn.style.display = 'none';

    document.querySelectorAll('.vault-item').forEach(el => el.classList.remove('editing-mode'));
}

async function addPassword() {
    const site = document.getElementById('new-site').value;
    const username = document.getElementById('new-user').value;
    const pass = document.getElementById('new-pass').value;
    const notes = document.getElementById('new-notes').value;
    const fileInput = document.getElementById('new-file');

    if (!site || !username || !pass) {
        showToast("Please fill all mandatory fields.");
        return;
    }

    showLoading(currentEditIndex !== null ? "Updating Credential..." : "Encrypting Credential...");

    let fileData = null;
    if (fileInput.files.length > 0) {
        const file = fileInput.files[0];
        const base64 = await toBase64File(file);
        fileData = { name: file.name, data: base64 };
    }

    const newItem = { site, username, pass, notes, file: fileData, date: new Date().toISOString() };

    if (currentEditIndex !== null) {
        // Update existing
        window.currentVault[currentEditIndex] = newItem;
        showToast("Credential updated successfully!");
        cancelEdit();
    } else {
        // Add new
        window.currentVault.push(newItem);
        showToast("New credential added to vault.");
    }

    // Encrypt and Sync
    await syncVault();

    // Reset UI
    document.getElementById('new-site').value = "";
    document.getElementById('new-user').value = "";
    document.getElementById('new-pass').value = "";
    document.getElementById('new-notes').value = "";
    fileInput.value = "";

    hideLoading();
    renderVault(window.currentVault);
}

function toBase64File(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.readAsDataURL(file);
        reader.onload = () => resolve(reader.result);
        reader.onerror = error => reject(error);
    });
}

// SHA-1 helper for HIBP
async function checkPwnedCount(password) {
    const msgUint8 = new TextEncoder().encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-1', msgUint8);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

    const prefix = hashHex.slice(0, 5);
    const suffix = hashHex.slice(5);

    try {
        const res = await fetch(`/api/pwned/${prefix}`);
        const text = await res.text();

        const lines = text.split('\n');
        for (const line of lines) {
            const [h, count] = line.split(':');
            if (h === suffix) return parseInt(count);
        }
    } catch (e) {
        console.error("HIBP check failed", e);
    }
    return 0;
}

function formatCount(num) {
    if (num > 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num > 1000) return (num / 1000).toFixed(1) + 'K';
    return num;
}

function copyPass(index) {
    const pass = window.currentVault[index].pass;
    navigator.clipboard.writeText(pass);
    showToast("Password copied to clipboard!");
}

async function deletePassword(index) {
    if (!confirm(`Are you sure you want to delete the credentials for ${window.currentVault[index].site}?`)) {
        return;
    }

    // Remove from local array
    window.currentVault.splice(index, 1);

    // Sync encrypted blob to server
    await syncVault();

    showToast("Credential deleted successfully.");

    // Rerender UI
    renderVault(window.currentVault);
}

function logout() {
    showLoading("Securing Vault & Logging out...");
    sessionStorage.clear();
    // 3 second liquid logout
    setTimeout(() => { window.location.href = '/login'; }, 3000);
}

// --- Data Management ---

function exportVault() {
    const dataStr = JSON.stringify(window.currentVault, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,' + encodeURIComponent(dataStr);

    const exportFileDefaultName = `zk_vault_export_${new Date().toISOString().slice(0, 10)}.json`;

    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
}

async function importVault(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (e) => {
        const text = e.target.result;
        try {
            showLoading("Importing Data...");
            const lines = text.split('\n');
            const newItems = [];

            // Basic CSV parser (assuming Site, User, Pass format)
            for (let i = 1; i < lines.length; i++) {
                const cols = lines[i].split(',');
                if (cols.length >= 3) {
                    newItems.push({
                        site: cols[0].trim(),
                        username: cols[1].trim(),
                        pass: cols[2].trim(),
                        date: new Date().toISOString()
                    });
                }
            }

            window.currentVault = [...window.currentVault, ...newItems];
            await syncVault();
            hideLoading();
            renderVault(window.currentVault);
            alert(`Successfully imported ${newItems.length} items!`);
        } catch (err) {
            hideLoading();
            alert("Error parsing CSV. Please ensure format is: Site,Username,Password");
        }
    };
    reader.readAsText(file);
}
