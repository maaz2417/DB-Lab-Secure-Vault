// SecureVault Javascript File
// Handles copying, dynamic generator, auto-logout, clipboard timeout, and re-authentication modal

document.addEventListener('DOMContentLoaded', () => {
    // 1. Password Generator Logic
    const lengthInput = document.getElementById('gen-length');
    const lengthVal = document.getElementById('length-val');
    const uppercaseInput = document.getElementById('gen-uppercase');
    const lowercaseInput = document.getElementById('gen-lowercase');
    const numbersInput = document.getElementById('gen-numbers');
    const symbolsInput = document.getElementById('gen-symbols');
    const generateBtn = document.getElementById('generate-btn');
    const generatorOutput = document.getElementById('generator-result');
    const strengthBar = document.getElementById('gen-strength-bar');

    if (lengthInput && lengthVal) {
        lengthInput.addEventListener('input', () => {
            lengthVal.textContent = lengthInput.value;
        });
    }

    if (generateBtn) {
        generateBtn.addEventListener('click', generatePassword);
    }

    function generatePassword() {
        const length = parseInt(lengthInput.value);
        const hasUpper = uppercaseInput.checked;
        const hasLower = lowercaseInput.checked;
        const hasNumber = numbersInput.checked;
        const hasSymbol = symbolsInput.checked;

        const uppercaseChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const lowercaseChars = 'abcdefghijklmnopqrstuvwxyz';
        const numberChars = '0123456789';
        const symbolChars = '!@#$%^&*()_+-=[]{}|;:,.<>?';

        let allowedChars = '';
        if (hasUpper) allowedChars += uppercaseChars;
        if (hasLower) allowedChars += lowercaseChars;
        if (hasNumber) allowedChars += numberChars;
        if (hasSymbol) allowedChars += symbolChars;

        if (allowedChars === '') {
            showFlashMessage('Please select at least one character type.', 'error');
            return;
        }

        let password = '';
        // Ensure at least one of each selected type is included
        if (hasUpper) password += uppercaseChars[Math.floor(Math.random() * uppercaseChars.length)];
        if (hasLower) password += lowercaseChars[Math.floor(Math.random() * lowercaseChars.length)];
        if (hasNumber) password += numberChars[Math.floor(Math.random() * numberChars.length)];
        if (hasSymbol) password += symbolChars[Math.floor(Math.random() * symbolChars.length)];

        while (password.length < length) {
            password += allowedChars[Math.floor(Math.random() * allowedChars.length)];
        }

        // Shuffle password
        password = password.split('').sort(() => 0.5 - Math.random()).join('');
        generatorOutput.textContent = password;
        
        // Update strength meter
        updateStrengthMeter(password);
    }

    function updateStrengthMeter(password) {
        if (!strengthBar) return;
        
        let score = 0;
        if (password.length >= 8) score++;
        if (password.length >= 14) score++;
        if (/[A-Z]/.test(password)) score++;
        if (/[0-9]/.test(password)) score++;
        if (/[^A-Za-z0-9]/.test(password)) score++;

        strengthBar.className = 'strength-bar';
        if (score <= 2) {
            strengthBar.classList.add('weak');
            strengthBar.style.width = '25%';
        } else if (score === 3) {
            strengthBar.classList.add('medium');
            strengthBar.style.width = '50%';
        } else if (score === 4) {
            strengthBar.classList.add('strong');
            strengthBar.style.width = '75%';
        } else {
            strengthBar.classList.add('very-strong');
            strengthBar.style.width = '100%';
        }
    }

    // 2. Clipboard Management and Timeouts
    window.copyToClipboard = function(text, timeoutSeconds = 30) {
        if (!text || text.includes('[Encrypted]') || text === '••••••••') {
            showFlashMessage('Please decrypt the password before copying.', 'warning');
            return;
        }
        
        navigator.clipboard.writeText(text).then(() => {
            showFlashMessage(`Password copied! Clearing clipboard in ${timeoutSeconds}s...`, 'success');
            
            // Clear clipboard after timeout
            setTimeout(() => {
                navigator.clipboard.writeText("").then(() => {
                    showFlashMessage('Clipboard cleared for security.', 'info');
                });
            }, timeoutSeconds * 1000);
        }).catch(err => {
            showFlashMessage('Failed to copy password.', 'error');
        });
    }

    // 3. Re-Authentication Modal and Password Decryption
    const reauthModal = document.getElementById('reauth-modal');
    const reauthForm = document.getElementById('reauth-form');
    const masterPasswordInput = document.getElementById('reauth-master-password');
    const cancelReauthBtn = document.getElementById('cancel-reauth');
    
    let activeVaultId = null;
    let activePasswordElement = null;
    let activeAction = null; // 'view' or 'copy'
    let activeTimeout = 30;

    window.requestDecryption = function(vaultId, requiresReauth, timeoutSec, action) {
        activeVaultId = vaultId;
        activePasswordElement = document.getElementById(`pwd-text-${vaultId}`);
        activeAction = action;
        activeTimeout = timeoutSec;

        if (requiresReauth === 'True' || requiresReauth === '1' || requiresReauth === true) {
            // Show re-auth modal
            reauthModal.classList.add('active');
            masterPasswordInput.value = '';
            masterPasswordInput.focus();
        } else {
            // Fetch password directly
            decryptPassword("");
        }
    }

    if (cancelReauthBtn) {
        cancelReauthBtn.addEventListener('click', () => {
            reauthModal.classList.remove('active');
        });
    }

    if (reauthForm) {
        reauthForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const masterPwd = masterPasswordInput.value;
            reauthModal.classList.remove('active');
            decryptPassword(masterPwd);
        });
    }

    function decryptPassword(masterPwd) {
        fetch('/vault/decrypt', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                vault_id: activeVaultId,
                master_password: masterPwd
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                if (activeAction === 'view') {
                    // Update field text
                    activePasswordElement.textContent = data.password;
                    activePasswordElement.style.fontFamily = 'monospace';
                    
                    // Automatically hide password after timeout
                    setTimeout(() => {
                        activePasswordElement.textContent = '••••••••';
                    }, activeTimeout * 1000);
                    
                    showFlashMessage(`Password visible for ${activeTimeout} seconds.`, 'success');
                } else if (activeAction === 'copy') {
                    copyToClipboard(data.password, activeTimeout);
                }
            } else {
                showFlashMessage(data.error || 'Decryption failed. Incorrect master password.', 'error');
            }
        })
        .catch(err => {
            showFlashMessage('Error communicating with server.', 'error');
            console.error(err);
        });
    }

    // 4. Auto-Logout System
    const autoLogoutMinutes = parseInt(document.body.dataset.autoLogout || '10');
    if (autoLogoutMinutes > 0 && !window.location.pathname.includes('/login') && !window.location.pathname.includes('/register')) {
        let logoutTimer;
        
        const resetTimer = () => {
            clearTimeout(logoutTimer);
            logoutTimer = setTimeout(() => {
                showFlashMessage('Logging out due to inactivity...', 'warning');
                setTimeout(() => {
                    window.location.href = '/logout?reason=inactivity';
                }, 1500);
            }, autoLogoutMinutes * 60 * 1000);
        };
        
        // Track activity
        window.onload = resetTimer;
        document.onmousemove = resetTimer;
        document.onkeypress = resetTimer;
        document.onclick = resetTimer;
        document.onscroll = resetTimer;
    }

    // Helper: Show custom beautiful flash notifications
    function showFlashMessage(message, category = 'info') {
        const container = document.getElementById('flash-container');
        if (!container) return;

        const flash = document.createElement('div');
        flash.className = `flash-message flash-${category}`;
        
        let icon = '🔔';
        if (category === 'success') icon = '✅';
        if (category === 'error') icon = '❌';
        if (category === 'warning') icon = '⚠️';
        if (category === 'info') icon = 'ℹ️';

        flash.innerHTML = `<span>${icon}</span> <span>${message}</span>`;
        container.appendChild(flash);

        // Auto remove
        setTimeout(() => {
            flash.style.animation = 'slideIn 0.3s ease reverse forwards';
            setTimeout(() => flash.remove(), 300);
        }, 4000);
    }
});
