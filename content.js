const jwtInput = document.querySelector('#jwt');
const headerResult = document.querySelector('#header-result');
const bodyResult = document.querySelector('#body-result');
const error = document.querySelector('#error');
const jwtParts = document.querySelectorAll('.jwt-parts');
const secretInput = document.querySelector('#secret');
const saveButton = document.querySelector('#save-jwt');

const jwtRegex = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;

if (jwtParts.length === 2 && secretInput && jwtInput && saveButton && error) {
    initializeEncoder();
} else if (jwtInput && headerResult && bodyResult && error) {
    initializeDecoder();
} else if (jwtInput && document.querySelector('#brute-forcer') && error) {
    initializeBruteForce();
} else {
    throw new Error('JWT page elements are missing from the HTML');
}

function initializeDecoder() {
    function render(token) {
        token = token.trim();
        if (!token) {
            headerResult.textContent = '';
            bodyResult.textContent = '';
            error.textContent = 'no jwt found';
            browser.storage.local.remove('decodedJwtParts');
            return;
        }

        try {
            const decoded = decodeJWT(token);
            headerResult.textContent = JSON.stringify(decoded.header, null, 2);
            bodyResult.textContent = JSON.stringify(decoded.payload, null, 2);
            error.textContent = '';
            browser.storage.local.set({
                decodedJwtParts: {
                    header: decoded.header,
                    payload: decoded.payload
                }
            });
        } catch (decodeError) {
            headerResult.textContent = '';
            bodyResult.textContent = '';
            error.textContent = decodeError instanceof Error ? decodeError.message : String(decodeError);
            browser.storage.local.remove('decodedJwtParts');
        }
    }

    let draftKey;
    jwtInput.addEventListener('input', () => {
        const token = jwtInput.value;
        render(token);
        if (draftKey) {
            if (token.trim()) {
                browser.storage.local.set({ [draftKey]: token });
            } else {
                browser.storage.local.remove(draftKey);
            }
        }
    });

    loadJWTForActiveTab().then(loaded => {
        if (!loaded) return;

        draftKey = `jwtDraft:${loaded.tabId}`;
        if (loaded.token) {
            jwtInput.value = loaded.token;
            render(loaded.token);
            browser.storage.local.set({ [draftKey]: loaded.token });
        } else {
            render('');
        }
    }).catch(loadError => {
        error.textContent = loadError instanceof Error ? loadError.message : String(loadError);
    });
}

function initializeBruteForce() {
    const crackButton = document.querySelector('#crack');
    const cancelButton = document.querySelector('#cancel');
    const progressContainer = document.querySelector('#progress');
    const progressFill = progressContainer ? progressContainer.querySelector('.progress-fill') : null;
    const progressText = progressContainer ? progressContainer.querySelector('.progress-text') : null;
    const secretResult = document.querySelector('#secret-result');
    const hashcatCmd = document.querySelector('#hashcat-cmd');
    const copyHashcatButton = document.querySelector('#copy-hashcat');

    let draftKey;
    let cancelled = false;
    let running = false;

    function renderHashcat(token) {
        if (!hashcatCmd || !copyHashcatButton) return;
        const trimmed = (token || '').trim();
        if (!trimmed || !jwtRegex.test(trimmed)) {
            hashcatCmd.textContent = '';
            copyHashcatButton.disabled = true;
            return;
        }
        const parts = trimmed.split('.');
        const sig = parts[2] || '';
        // Mode 16500 covers HS256/HS384/HS512. Hashcat expects the full JWT as the hash.
        const escaped = trimmed.replace(/'/g, "'\\''");
        const cmd = `hashcat -m 16500 -a 0 '${escaped}' <YOUR-WORDLIST>`;
        hashcatCmd.textContent = sig ? cmd : '';
        copyHashcatButton.disabled = !sig;
    }

    function clearHashcat() {
        if (hashcatCmd) hashcatCmd.textContent = '';
        if (copyHashcatButton) copyHashcatButton.disabled = true;
    }

    jwtInput.addEventListener('input', () => {
        const token = jwtInput.value;
        renderHashcat(token);
        if (!draftKey) return;

        if (token.trim()) {
            browser.storage.local.set({ [draftKey]: token });
        } else {
            browser.storage.local.remove(draftKey);
        }
    });

    loadJWTForActiveTab().then(loaded => {
        if (!loaded) return;

        draftKey = `jwtDraft:${loaded.tabId}`;
        jwtInput.value = loaded.token || '';
        renderHashcat(jwtInput.value);
        if (loaded.token) {
            browser.storage.local.set({ [draftKey]: loaded.token });
        }
    }).catch(loadError => {
        error.textContent = loadError instanceof Error ? loadError.message : String(loadError);
    });

    if (copyHashcatButton) {
        let feedbackTimer = 0;
        copyHashcatButton.addEventListener('click', async () => {
            const cmd = hashcatCmd ? hashcatCmd.textContent : '';
            if (!cmd) return;
            try {
                await navigator.clipboard.writeText(cmd);
                copyHashcatButton.classList.add('copied');
                clearTimeout(feedbackTimer);
                feedbackTimer = setTimeout(() => {
                    copyHashcatButton.classList.remove('copied');
                }, 1400);
            } catch (clipError) {
                error.textContent = 'Copy failed: ' + (clipError instanceof Error ? clipError.message : String(clipError));
            }
        });
    }

    crackButton.addEventListener('click', async () => {
        if (running) return;

        error.style.color = '';
        error.textContent = '';
        if (secretResult) secretResult.textContent = '';
        if (progressFill) progressFill.style.width = '0%';
        if (progressText) progressText.textContent = '';

        const token = jwtInput.value.trim();
        if (!token || !jwtRegex.test(token)) {
            error.textContent = 'Paste a valid JWT first.';
            clearHashcat();
            return;
        }
        renderHashcat(token);

        const parts = token.split('.');
        const signatureB64 = parts[2];
        if (!signatureB64) {
            error.textContent = 'This JWT has no signature (algorithm "none") — nothing to crack.';
            return;
        }

        let header;
        try {
            header = decodeSegment(parts[0]);
        } catch (decodeError) {
            error.textContent = 'Could not decode the JWT header.';
            return;
        }

        const alg = (header.alg || '').toString().toUpperCase();
        if (alg === 'NONE') {
            error.textContent = 'Algorithm "none" uses no secret — nothing to crack.';
            return;
        }
        const hashName = getHmacHashName(alg);
        if (!hashName) {
            error.textContent = `Cannot brute-force algorithm "${header.alg}". Only HS256, HS384, and HS512 are supported.`;
            return;
        }

        let wordlist;
        try {
            const response = await fetch('jwt.secrets.list');
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const text = await response.text();
            wordlist = text.split(/\r?\n/).filter(line => line.length > 0);
        } catch (fetchError) {
            error.textContent = `Failed to load wordlist: ${fetchError instanceof Error ? fetchError.message : String(fetchError)}`;
            return;
        }

        if (wordlist.length === 0) {
            error.textContent = 'The wordlist is empty.';
            return;
        }

        const dataToSign = `${parts[0]}.${parts[1]}`;
        const total = wordlist.length;
        const batchSize = 25;
        let tested = 0;
        let found = null;

        running = true;
        cancelled = false;
        crackButton.disabled = true;
        if (cancelButton) cancelButton.disabled = false;
        if (progressContainer) progressContainer.hidden = false;

        const startTime = performance.now();

        for (let i = 0; i < total; i++) {
            if (cancelled) break;
            const candidate = wordlist[i];

            try {
                const key = await crypto.subtle.importKey(
                    'raw',
                    new TextEncoder().encode(candidate),
                    { name: 'HMAC', hash: hashName },
                    false,
                    ['sign']
                );
                const signature = await crypto.subtle.sign(
                    'HMAC',
                    key,
                    new TextEncoder().encode(dataToSign)
                );
                const encodedSignature = base64UrlEncodeBytes(new Uint8Array(signature));
                tested++;

                if (encodedSignature === signatureB64) {
                    found = candidate;
                    break;
                }
            } catch (signError) {
                // Skip candidates that cannot be imported/signed (e.g. invalid encoding).
                tested++;
            }

            if (tested % batchSize === 0) {
                const percent = Math.min(100, Math.round((tested / total) * 100));
                if (progressFill) progressFill.style.width = `${percent}%`;
                if (progressText) {
                    progressText.textContent = `${tested}/${total} tried — current: ${truncate(candidate, 28)}`;
                }
                await new Promise(resolve => setTimeout(resolve, 0));
            }
        }

        const elapsedMs = Math.round(performance.now() - startTime);
        const finalPercent = cancelled ? Math.min(100, Math.round((tested / total) * 100)) : 100;
        if (progressFill) progressFill.style.width = `${finalPercent}%`;

        if (found) {
            if (secretResult) secretResult.textContent = found;
            if (progressText) progressText.textContent = `Found after ${tested} attempt${tested === 1 ? '' : 's'} in ${elapsedMs} ms.`;
            error.style.color = '#ff8c00';
            error.textContent = 'Secret found! Switch to Encode to use it.';
            try {
                await browser.storage.local.set({ crackedJwtSecret: found });
            } catch (saveErr) {
                // Non-fatal: keep going even if storage write fails.
            }
        } else if (cancelled) {
            if (progressText) progressText.textContent = `Cancelled after ${tested} attempt${tested === 1 ? '' : 's'}.`;
            error.textContent = 'Brute-force cancelled.';
        } else {
            if (secretResult) secretResult.textContent = '';
            if (progressText) progressText.textContent = `Tested ${tested} words in ${elapsedMs} ms.`;
            error.textContent = 'No matching secret found in the wordlist.';
        }

        running = false;
        crackButton.disabled = false;
        if (cancelButton) cancelButton.disabled = true;
    });

    if (cancelButton) {
        cancelButton.addEventListener('click', () => {
            cancelled = true;
        });
    }
}

function getHmacHashName(alg) {
    switch (alg) {
        case 'HS256': return 'SHA-256';
        case 'HS384': return 'SHA-384';
        case 'HS512': return 'SHA-512';
        default: return null;
    }
}

function truncate(value, max) {
    if (value.length <= max) return value;
    return value.slice(0, max - 1) + '\u2026';
}

async function loadJWTForActiveTab() {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    if (!tab) return null;

    const draftKey = `jwtDraft:${tab.id}`;
    const key = `jwt:${tab.id}`;
    const stored = await browser.storage.local.get([draftKey, key]);
    let token = stored[draftKey] || stored[key];

    if (!token && tab.url && tab.url.startsWith('http')) {
        const cookies = await browser.cookies.getAll({ url: tab.url });
        const jwtCookie = cookies.find(cookie => jwtRegex.test(cookie.value));
        if (jwtCookie) token = jwtCookie.value;
    }

    return { tabId: tab.id, token };
}

function initializeEncoder() {
    let updateId = 0;

    async function updateJWT() {
        const currentUpdateId = ++updateId;
        jwtInput.value = '';
        error.textContent = '';

        try {
            const header = JSON.parse(jwtParts[0].value);
            const payload = JSON.parse(jwtParts[1].value);
            secretInput.disabled = header.alg === 'none';
            const token = await createJWT(header, payload, secretInput.value);
            if (currentUpdateId === updateId) jwtInput.value = token;
        } catch (encodeError) {
            if (currentUpdateId === updateId) {
                error.textContent = encodeError instanceof Error ? encodeError.message : String(encodeError);
            }
        }
    }

    jwtParts.forEach(part => part.addEventListener('input', updateJWT));

    // If the user manually edits the secret, drop the cracked-secret hint so we
    // don't keep overwriting their input on the next encoder open.
    let userTouchedSecret = false;
    secretInput.addEventListener('input', () => {
        userTouchedSecret = true;
        browser.storage.local.remove('crackedJwtSecret');
        updateJWT();
    });
    saveButton.addEventListener('click', saveJWTToCookie);

    browser.storage.local.get('decodedJwtParts').then(stored => {
        const decoded = stored.decodedJwtParts;
        if (decoded && typeof decoded === 'object' && 'header' in decoded && 'payload' in decoded) {
            jwtParts[0].value = JSON.stringify(decoded.header, null, 2);
            jwtParts[1].value = JSON.stringify(decoded.payload, null, 2);
        }
        // Pick up any secret recovered by the Brute-force tab.
        return browser.storage.local.get('crackedJwtSecret');
    }).then(stored => {
        const cracked = stored.crackedJwtSecret;
        if (cracked && typeof cracked === 'string' && cracked.length > 0 && !userTouchedSecret && !secretInput.value) {
            secretInput.value = cracked;
        }
        updateJWT();
    }).catch(storageError => {
        error.textContent = storageError instanceof Error ? storageError.message : String(storageError);
        updateJWT();
    });
}

async function saveJWTToCookie() {
    error.style.color = '';
    error.textContent = '';

    const token = jwtInput.value.trim();
    if (!token || !jwtRegex.test(token)) {
        error.textContent = 'Generate a valid JWT before saving.';
        return;
    }

    try {
        const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
        if (!tab || !tab.url || !/^https?:\/\//i.test(tab.url)) {
            throw new Error('The active tab must be an HTTP or HTTPS site.');
        }

        const cookies = await browser.cookies.getAll({ url: tab.url });
        const jwtCookie = cookies.find(cookie => jwtRegex.test(cookie.value));
        if (!jwtCookie) {
            throw new Error('No existing JWT cookie was found for this site.');
        }

        const details = {
            url: tab.url,
            name: jwtCookie.name,
            value: token,
            path: jwtCookie.path,
            secure: jwtCookie.secure,
            httpOnly: jwtCookie.httpOnly,
            sameSite: jwtCookie.sameSite,
            storeId: jwtCookie.storeId
        };
        if (jwtCookie.domain.startsWith('.')) details.domain = jwtCookie.domain;
        if (jwtCookie.expirationDate !== undefined) {
            details.expirationDate = jwtCookie.expirationDate;
        }

        const updatedCookie = await browser.cookies.set(details);
        if (!updatedCookie) {
            throw new Error('The browser did not update the JWT cookie.');
        }

        error.style.color = '#ff8c00';
        error.textContent = `Updated the "${jwtCookie.name}" cookie. Reloading the page...`;
        await browser.tabs.reload(tab.id);
    } catch (saveError) {
        error.textContent = saveError instanceof Error ? saveError.message : String(saveError);
    }
}

function decodeJWT(token) {
    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new Error('Invalid JWT format: expected three dot-separated parts');
    }

    return {
        header: decodeSegment(parts[0]),
        payload: decodeSegment(parts[1])
    };
}

function decodeSegment(segment) {
    let base64 = segment.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) base64 += '=';

    const json = decodeURIComponent(
        atob(base64)
            .split('')
            .map(character => '%' + ('00' + character.charCodeAt(0).toString(16)).slice(-2))
            .join('')
    );
    return JSON.parse(json);
}

function base64UrlEncode(value) {
    return base64UrlEncodeBytes(new TextEncoder().encode(value));
}

function base64UrlEncodeBytes(bytes) {
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);

    return btoa(binary)
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
}

async function createJWT(header, payload, secret) {
    const encodedHeader = base64UrlEncode(JSON.stringify(header));
    const encodedPayload = base64UrlEncode(JSON.stringify(payload));
    const dataToSign = `${encodedHeader}.${encodedPayload}`;

    if (header.alg === 'none') {
        return `${dataToSign}.`;
    }

    const key = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    const signature = await crypto.subtle.sign(
        'HMAC',
        key,
        new TextEncoder().encode(dataToSign)
    );
    const encodedSignature = base64UrlEncodeBytes(new Uint8Array(signature));

    return `${dataToSign}.${encodedSignature}`;
}