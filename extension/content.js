// content.js for ZK-Vault Extension
console.log("🛡️ ZK-Vault: Content Script Active");

function findLoginFields() {
    const passwordFields = document.querySelectorAll('input[type="password"]');
    const userFields = document.querySelectorAll('input[type="text"], input[type="email"]');
    return { userFields, passwordFields };
}

function fillCredentials(username, password) {
    const { userFields, passwordFields } = findLoginFields();

    // Simple heuristic: fill the last text/email field before the first password field
    if (passwordFields.length > 0) {
        passwordFields[0].value = password;
        passwordFields[0].dispatchEvent(new Event('input', { bubbles: true }));

        // Find best guess for username field
        for (let i = userFields.length - 1; i >= 0; i--) {
            if (userFields[i].getBoundingClientRect().top < passwordFields[0].getBoundingClientRect().top) {
                userFields[i].value = username;
                userFields[i].dispatchEvent(new Event('input', { bubbles: true }));
                break;
            }
        }
    }
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "autofill") {
        fillCredentials(request.username, request.password);
        sendResponse({ success: true });
    }
});
