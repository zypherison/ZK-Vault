// background.js for ZK-Vault Extension
let encryptionKey = null;
let currentVault = null;

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "storeKey") {
        encryptionKey = request.key;
        currentVault = request.vault;
        sendResponse({ success: true });
    } else if (request.action === "getKey") {
        sendResponse({ key: encryptionKey, vault: currentVault });
    } else if (request.action === "logout") {
        encryptionKey = null;
        currentVault = null;
        sendResponse({ success: true });
    } else if (request.action === "getMatchingCredentials") {
        if (!currentVault) {
            sendResponse({ credentials: [] });
            return;
        }
        const domain = request.domain;
        const matches = currentVault.filter(item =>
            item.site.toLowerCase().includes(domain.toLowerCase())
        );
        sendResponse({ credentials: matches });
    }
});
