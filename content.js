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

    (async () => {
        const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
        if (!tab) return;

        draftKey = `jwtDraft:${tab.id}`;
        const key = `jwt:${tab.id}`;
        const stored = await browser.storage.local.get([draftKey, key]);
        let token = stored[draftKey] || stored[key];

        if (!token && tab.url && tab.url.startsWith('http')) {
            const cookies = await browser.cookies.getAll({ url: tab.url });
            const jwtCookie = cookies.find(cookie => jwtRegex.test(cookie.value));
            if (jwtCookie) token = jwtCookie.value;
        }

        if (token) {
            jwtInput.value = token;
            render(token);
            browser.storage.local.set({ [draftKey]: token });
        } else {
            render('');
        }
    })();
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
    secretInput.addEventListener('input', updateJWT);
    saveButton.addEventListener('click', saveJWTToCookie);

    browser.storage.local.get('decodedJwtParts').then(stored => {
        const decoded = stored.decodedJwtParts;
        if (!decoded || typeof decoded !== 'object' || !('header' in decoded) || !('payload' in decoded)) return;

        jwtParts[0].value = JSON.stringify(decoded.header, null, 2);
        jwtParts[1].value = JSON.stringify(decoded.payload, null, 2);
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
