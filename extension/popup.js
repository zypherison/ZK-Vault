// popup.js for ZK-Vault Extension

const RENDER_URL = "https://zk-vault.onrender.com";

const CONFIG = {
    argon2: {
        time: 2,
        mem: 1024 * 64,
        parallelism: 4,
        type: 2 // argon2id
    },
    algo: { name: "AES-GCM", length: 256 }
};

// Utils
const bufToHex = buf => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
const fromBase64 = str => Uint8Array.from(atob(str), c => c.charCodeAt(0));
const toBase64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const strToBuf = str => new TextEncoder().encode(str);
const bufToStr = buf => new TextDecoder().decode(buf);

async function deriveKeys(password, salt) {
    const result = await argon2.hash({
        pass: password, salt: salt,
        time: CONFIG.argon2.time, mem: CONFIG.argon2.mem,
        hashLen: 64, parallelism: CONFIG.argon2.parallelism, type: CONFIG.argon2.type
    });
    const hashBytes = result.hash;
    return {
        authHash: bufToHex(hashBytes.slice(0, 32)),
        encryptionKey: toBase64(hashBytes.slice(32, 64))
    };
}

async function decryptVault(blobBase64, keyBase64) {
    if (!blobBase64) return [];
    try {
        const key = await crypto.subtle.importKey("raw", fromBase64(keyBase64), CONFIG.algo, false, ["decrypt"]);
        const combined = fromBase64(blobBase64);
        const iv = combined.slice(0, 12);
        const ciphertext = combined.slice(12);
        const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, ciphertext);
        return JSON.parse(bufToStr(decrypted));
    } catch (e) {
        throw new Error("Decryption failed. Wrong password?");
    }
}

// UI Handling
document.addEventListener('DOMContentLoaded', async () => {
    lucide.createIcons();
    const loginView = document.getElementById('login-view');
    const vaultView = document.getElementById('vault-view');
    const statusMsg = document.getElementById('status-msg');

    // Check if already unlocked
    chrome.runtime.sendMessage({ action: "getKey" }, async (response) => {
        if (response && response.key) {
            showVault(response.vault);
        }
    });

    document.getElementById('login-btn').addEventListener('click', async () => {
        const user = document.getElementById('username').value.trim();
        const pass = document.getElementById('password').value; // Don't trim password! Matches web app behavior.

        if (!user || !pass) {
            statusMsg.textContent = "Please enter both fields.";
            return;
        }

        statusMsg.textContent = "Step 1: Fetching Salt...";
        console.log("Login initiated for:", user);

        try {
            let authHashToSend;
            let keys = null; // Defined in outer scope

            // SPECIAL CASE: Admin bypasses ZK hashing
            if (user === "admin") {
                console.log("Admin detected, using plain authentication");
                authHashToSend = pass;
                statusMsg.textContent = "Step 3: Authenticating Admin...";
            } else {
                // 1. Get Salt
                const saltRes = await fetch(`${RENDER_URL}/api/user_salt?username=${encodeURIComponent(user)}`, { credentials: 'include' });
                const saltData = await saltRes.json();
                if (!saltData.salt) throw new Error("User not found or connection error");

                console.log("Using Salt:", saltData.salt);

                // 2. Derive Keys
                statusMsg.textContent = "Step 2: Deriving ZK-Keys...";
                keys = await deriveKeys(pass, saltData.salt);
                authHashToSend = keys.authHash;
            }

            // 3. Login
            statusMsg.textContent = "Step 3: Verifying...";
            const loginRes = await fetch(`${RENDER_URL}/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: user, auth_hash: authHashToSend }),
                credentials: 'include'
            });
            const loginData = await loginRes.json();

            if (loginData.status !== 'success') throw new Error(loginData.message);

            // If Admin, stop here (Admin has no vault to decrypt)
            if (user === "admin") {
                statusMsg.textContent = "Admin Logged In. (No Vault)";
                showVault([]); // Show empty vault for admin
                return;
            }

            // 4. Fetch Vault Blob (Only for regular users)
            statusMsg.textContent = "Step 4: Syncing Vault...";
            const vaultRes = await fetch(`${RENDER_URL}/api/vault`, { credentials: 'include' });
            const vaultData = await vaultRes.json();

            // 5. Decrypt
            statusMsg.textContent = "Step 5: Decrypting Vault...";
            const decryptedItems = await decryptVault(vaultData.encrypted_blob, keys.encryptionKey);

            // 6. Store in background for persistence
            chrome.runtime.sendMessage({
                action: "storeKey",
                key: keys.encryptionKey,
                vault: decryptedItems
            });

            showVault(decryptedItems);
        } catch (e) {
            console.error("Login Error:", e);
            statusMsg.textContent = "Error: " + e.message;
        }
    });

    document.getElementById('logout-btn').addEventListener('click', () => {
        chrome.runtime.sendMessage({ action: "logout" }, () => {
            location.reload();
        });
    });
});

async function showVault(items) {
    console.log("Rendering vault with", items.length, "items");
    document.getElementById('login-view').classList.add('hidden');
    document.getElementById('vault-view').classList.remove('hidden');

    const list = document.getElementById('extension-vault-list');
    list.innerHTML = "";

    // Get current tab URL
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = new URL(tab.url);
    const domain = url.hostname.replace('www.', '');

    const matches = items.filter(item => item.site.toLowerCase().includes(domain.toLowerCase()));

    if (matches.length > 0) {
        const actionDiv = document.getElementById('current-site-action');
        actionDiv.innerHTML = `<p style="font-size: 11px; color: var(--text-secondary);">Found ${matches.length} for ${domain}</p>`;
        matches.forEach(item => {
            const btn = document.createElement('button');
            btn.className = 'btn';
            btn.style.marginBottom = '5px';
            btn.textContent = `Autofill ${item.username}`;
            btn.onclick = () => autofill(item.username, item.pass);
            actionDiv.appendChild(btn);
        });
    }

    items.forEach((item, index) => {
        const div = document.createElement('div');
        div.className = 'vault-item';
        div.innerHTML = `
            <div class="item-main">
                <div>
                    <div class="item-title">${item.site}</div>
                    <div class="item-user">${item.username}</div>
                </div>
                <button class="icon-btn" onclick="navigator.clipboard.writeText('${item.pass}')"><i data-lucide="copy"></i></button>
            </div>
        `;
        list.appendChild(div);
    });
    lucide.createIcons();
}

async function autofill(username, password) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    chrome.tabs.sendMessage(tab.id, {
        action: "autofill",
        username: username,
        password: password
    });
}
