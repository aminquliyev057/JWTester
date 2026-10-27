const jwtInput = document.querySelector('#jwt');
const headerResult = document.querySelector('#header-result');
const bodyResult = document.querySelector('#body-result');
const error = document.querySelector('#error');
const jwtParts = document.querySelectorAll('.jwt-parts');
const secretInput = document.querySelector('#secret');
const saveButton = document.querySelector('#save-jwt');

const jwtRegex = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;

// Detect which page we are on by inspecting the DOM. Each initializer
// returns early if its required elements are not present, so a single
// content.js can serve all three tabs (decode / encode / brute-force).
if (document.querySelector('#encoder') && jwtParts.length >= 2 && jwtInput && saveButton && error) {
    initializeEncoder();
} else if (jwtInput && headerResult && bodyResult && error) {
    initializeDecoder();
} else if (jwtInput && document.querySelector('#brute-forcer') && error) {
    initializeBruteForce();
} else {
    throw new Error('JWT page elements are missing from the HTML');
}

// ============================================================
// Decoder
// ============================================================
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

// ============================================================
// Brute-force
// ============================================================
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
                // Non-fatal.
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

// ============================================================
// Encoder  (HS256 / RS256 / none)
// ============================================================
function initializeEncoder() {
    // ----- DOM refs -----
    const algorithmSelect = document.querySelector('#algorithm');
    const hs256Section = document.querySelector('#hs256-section');
    const rs256Section = document.querySelector('#rs256-section');
    const privateKeyPem = document.querySelector('#private-key-pem');
    const privateKeyFile = document.querySelector('#private-key-file');
    const generateHs256KeyButton = document.querySelector('#generate-hs256-key');
    const copyHs256JwkButton = document.querySelector('#copy-hs256-jwk');
    const addHs256JwkHeaderButton = document.querySelector('#add-hs256-jwk-header');
    const hs256KeyList = document.querySelector('#hs256-key-list');

    const generateKeypairButton = document.querySelector('#generate-keypair');
    const keyList = document.querySelector('#key-list');
    const copyButtons = document.querySelectorAll('.copy-key-btn[data-key]');

    const addJwkHeaderButton = document.querySelector('#add-jwk-header');
    const addJkuHeaderButton = document.querySelector('#add-jku-header');

    // In-memory cache of the last generated RSA key pair (CryptoKey objects).
    // Persisted to storage so it survives popup re-opens.
    let generatedKeys = null;
    // Pre-exported string forms of the generated keys, so copy buttons don't
    // have to re-export from CryptoKey on every click.
    let keyStrings = { public: { jwk: '', pem: '' }, private: { jwk: '', pem: '' } };

    let updateId = 0;
    let userTouchedSecret = false;

    // ----- Persistence: save all encoder inputs so the popup reopens with
    // the same header / payload / secret / private key the user typed. -----
    function saveEncoderState() {
        const state = {
            header:          jwtParts[0]        ? jwtParts[0].value        : '',
            payload:         jwtParts[1]        ? jwtParts[1].value        : '',
            hs256Secret:     secretInput        ? secretInput.value        : '',
            rs256PrivateKeyPem: privateKeyPem  ? privateKeyPem.value       : ''
        };
        // Fire-and-forget: storage writes are async but we don't need to
        // await them on every keystroke.
        try {
            browser.storage.local.set({ encoderState: state });
        } catch (_) { /* non-fatal */ }
    }

    // ----- Algorithm switching -----
    // Keep RSA key generation and JKU tools limited to RS256. HS256 key tools
    // are part of the HS256 secret section.
    function updateAlgorithmSections(alg) {
        const a = (alg || 'HS256').toUpperCase();
        const isHs256 = (a === 'HS256');
        const isRs256 = (a === 'RS256');
        if (hs256Section) hs256Section.hidden = !isHs256;
        if (rs256Section) rs256Section.hidden = !isRs256;
        if (secretInput) secretInput.disabled = !isHs256;
        const keyGen = document.querySelector('.key-pair-generator');
        const hs256KeyGen = document.querySelector('.hs256-key-generator');
        const headerTools = document.querySelector('.header-tools');
        if (keyGen) keyGen.hidden = !isRs256;
        if (hs256KeyGen) hs256KeyGen.hidden = !isHs256;
        if (headerTools) headerTools.hidden = !isRs256;
    }

    function syncAlgorithmFromHeader() {
        try {
            const header = JSON.parse(jwtParts[0].value || '{}');
            const alg = (header.alg || 'HS256').toString().toUpperCase();
            if (algorithmSelect) {
                // Option values in encode.html are HS256 / RS256 / none
                algorithmSelect.value = alg === 'NONE' ? 'none' : alg;
            }
            updateAlgorithmSections(alg);
        } catch (_) {
            // leave the dropdown as-is if header is not valid JSON yet
        }
    }

    function updateHs256KeyList() {
        if (hs256KeyList) hs256KeyList.hidden = !secretInput || !secretInput.value;
    }

    async function createHs256Jwk(secret, kid) {
        const key = base64UrlEncodeBytes(getHs256KeyBytes(secret));
        const thumbprint = await computeJwkThumbprint({ kty: 'oct', k: key });
        return {
            kty: 'oct',
            k: key,
            kid: kid || thumbprint,
            alg: 'HS256',
            use: 'sig'
        };
    }

    // ----- Main encoder routine -----
    async function updateJWT() {
        const currentUpdateId = ++updateId;
        if (jwtInput) jwtInput.value = '';
        if (error) { error.style.color = ''; error.textContent = ''; }

        let header, payload;
        try {
            header = JSON.parse(jwtParts[0].value || '{}');
            payload = JSON.parse(jwtParts[1].value || '{}');
        } catch (parseError) {
            if (currentUpdateId === updateId) {
                error.textContent = 'Header/Body must be valid JSON: ' +
                    (parseError instanceof Error ? parseError.message : String(parseError));
            }
            return false;
        }

        const alg = (header.alg || 'HS256').toString().toUpperCase();
        if (algorithmSelect) {
            algorithmSelect.value = alg === 'NONE' ? 'none' : alg;
        }
        updateAlgorithmSections(alg);

        try {
            let token;
            if (alg === 'NONE') {
                token = await createJWTNone(header, payload);
            } else if (alg === 'HS256') {
                token = await createJWTHS256(header, payload, secretInput ? secretInput.value : '');
            } else if (alg === 'RS256') {
                token = await createJWTRS256(header, payload, privateKeyPem ? privateKeyPem.value : '');
            } else {
                throw new Error(`Unsupported algorithm: ${header.alg}. Use HS256, RS256, or none.`);
            }
            if (currentUpdateId !== updateId) return false;
            if (jwtInput) jwtInput.value = token;
            return true;
        } catch (encodeError) {
            if (currentUpdateId === updateId) {
                error.textContent = encodeError instanceof Error ? encodeError.message : String(encodeError);
            }
            return false;
        }
    }

    // ----- Event wiring: header / body / secret -----
    jwtParts.forEach(part => part.addEventListener('input', () => {
        syncAlgorithmFromHeader();
        saveEncoderState();
        updateJWT();
    }));

    if (secretInput) {
        secretInput.addEventListener('input', () => {
            userTouchedSecret = true;
            browser.storage.local.remove('crackedJwtSecret');
            updateHs256KeyList();
            saveEncoderState();
            updateJWT();
        });
    }

    if (generateHs256KeyButton) {
        generateHs256KeyButton.addEventListener('click', async () => {
            error.style.color = '';
            error.textContent = '';
            if (!secretInput) return;
            try {
                const randomKey = crypto.getRandomValues(new Uint8Array(32));
                secretInput.value = base64UrlEncodeBytes(randomKey);
                userTouchedSecret = true;
                await browser.storage.local.remove('crackedJwtSecret');
                updateHs256KeyList();
                saveEncoderState();
                if (!await updateJWT()) return;
                error.style.color = '#66bb6a';
                error.textContent = 'A 256-bit HS256 secret was generated.';
            } catch (generationError) {
                error.textContent = 'Key generation failed: ' +
                    (generationError instanceof Error ? generationError.message : String(generationError));
            }
        });
    }

    if (copyHs256JwkButton) {
        copyHs256JwkButton.addEventListener('click', async () => {
            const secret = secretInput ? secretInput.value : '';
            try {
                const jwk = await createHs256Jwk(secret);
                await navigator.clipboard.writeText(JSON.stringify(jwk, null, 2));
                copyHs256JwkButton.classList.add('copied');
                setTimeout(() => copyHs256JwkButton.classList.remove('copied'), 1400);
                error.style.color = '#66bb6a';
                error.textContent = 'Copied the HS256 octet JWK.';
            } catch (copyError) {
                error.textContent = 'Copy failed: ' +
                    (copyError instanceof Error ? copyError.message : String(copyError));
            }
        });
    }

    if (addHs256JwkHeaderButton) {
        addHs256JwkHeaderButton.addEventListener('click', async () => {
            error.style.color = '';
            error.textContent = '';
            const secret = secretInput ? secretInput.value : '';
            if (!window.confirm('This embeds the HS256 signing secret in the JWT header. Anyone who can read the token can recover it and forge signatures. This is for testing only. Continue?')) {
                return;
            }
            try {
                const header = JSON.parse(jwtParts[0].value || '{}');
                const kid = typeof header.kid === 'string' && header.kid.length > 0
                    ? header.kid
                    : undefined;
                const jwk = await createHs256Jwk(secret, kid);
                header.alg = 'HS256';
                header.kid = jwk.kid;
                header.jwk = jwk;
                jwtParts[0].value = JSON.stringify(header, null, 2);
                if (algorithmSelect) algorithmSelect.value = 'HS256';
                updateAlgorithmSections('HS256');
                saveEncoderState();
                if (!await updateJWT()) return;
                error.style.color = '#66bb6a';
                error.textContent = 'Embedded the HS256 octet JWK in the JWT header. The secret is visible in the token.';
            } catch (headerError) {
                error.textContent = headerError instanceof Error ? headerError.message : String(headerError);
            }
        });
    }

    // Direct typing in the RS256 private key textarea should re-sign the
    // JWT (previously this only worked when loading from a file).
    if (privateKeyPem) {
        privateKeyPem.addEventListener('input', () => {
            saveEncoderState();
            updateJWT();
        });
    }

    if (algorithmSelect) {
        algorithmSelect.addEventListener('change', async () => {
            const newAlg = algorithmSelect.value;
            try {
                const header = JSON.parse(jwtParts[0].value || '{}');
                header.alg = newAlg === 'none' ? 'none' : newAlg.toUpperCase();
                jwtParts[0].value = JSON.stringify(header, null, 2);
            } catch (_) {
                // If header is not valid JSON, just set a minimal one.
                jwtParts[0].value = JSON.stringify({ alg: newAlg === 'none' ? 'none' : newAlg.toUpperCase(), typ: 'JWT' }, null, 2);
            }
            updateAlgorithmSections(newAlg);
            saveEncoderState();
            await updateJWT();
        });
    }

    if (saveButton) saveButton.addEventListener('click', saveJWTToCookie);

    // ----- File input for RS256 private key (PEM or DER) -----
    if (privateKeyFile) {
        privateKeyFile.addEventListener('change', async (event) => {
            const file = event.target.files && event.target.files[0];
            if (!file) return;
            try {
                const buffer = await file.arrayBuffer();
                const bytes = new Uint8Array(buffer);
                // Detect PEM by ASCII prefix "-----BEGIN"
                const head = bytesToAscii(bytes.slice(0, 11));
                if (head === '-----BEGIN') {
                    // PEM text - decode and put into the textarea
                    privateKeyPem.value = new TextDecoder().decode(bytes).trim();
                } else {
                    // DER binary - import and re-export as PEM
                    const key = await importPrivateKeyFromBytes(bytes);
                    privateKeyPem.value = await exportPrivateKeyAsPem(key);
                }
                await updateJWT();
                saveEncoderState();
            } catch (loadError) {
                error.textContent = 'Failed to load key file: ' +
                    (loadError instanceof Error ? loadError.message : String(loadError));
            }
        });
    }

    // ----- Key pair generator -----
    if (generateKeypairButton) {
        generateKeypairButton.addEventListener('click', async () => {
            error.style.color = '';
            error.textContent = 'Generating RSA 2048 key pair…';
            generateKeypairButton.disabled = true;
            try {
                const pair = await crypto.subtle.generateKey(
                    {
                        name: 'RSASSA-PKCS1-v1_5',
                        modulusLength: 2048,
                        publicExponent: new Uint8Array([1, 0, 1]),
                        hash: 'SHA-256'
                    },
                    true,
                    ['sign', 'verify']
                );
                generatedKeys = pair;
                await renderGeneratedKeys(true); // autoFillPrivateKey = true
                await persistGeneratedKeys(pair);
                error.style.color = '#66bb6a';
                error.textContent = 'RSA 2048 key pair generated. Private key (PEM) loaded into RS256 textbox.';
            } catch (genError) {
                error.style.color = '';
                error.textContent = 'Key generation failed: ' +
                    (genError instanceof Error ? genError.message : String(genError));
            } finally {
                generateKeypairButton.disabled = false;
            }
        });
    }

    async function renderGeneratedKeys(autoFillPrivateKey) {
        if (!generatedKeys) {
            if (keyList) keyList.hidden = true;
            return;
        }
        const pubJwk = await crypto.subtle.exportKey('jwk', generatedKeys.publicKey);
        const privJwk = await crypto.subtle.exportKey('jwk', generatedKeys.privateKey);
        const pubPem = await exportPublicKeyAsPem(generatedKeys.publicKey);
        const privPem = await exportPrivateKeyAsPem(generatedKeys.privateKey);

        // WebCrypto returns only the raw RSA parameters (kty/n/e for public,
        // plus d/p/q/dp/dq/qi for private) along with the noisy key_ops/ext
        // metadata fields. Build a clean, ordered JWK that contains only the
        // portable JOSE fields: kty first, the key material, then a stable
        // kid (RFC 7638 thumbprint of the public key) plus alg/use so the
        // copied JWK is directly usable in a JWKS endpoint and the kid
        // matches the one embedded by Add JWK Header.
        const kid = await computeJwkThumbprint(pubJwk);
        const cleanPubJwk = {
            kty:  pubJwk.kty,
            n:    pubJwk.n,
            e:    pubJwk.e,
            kid:  kid,
            alg:  'RS256',
            use:  'sig'
        };
        const cleanPrivJwk = {
            kty:  privJwk.kty,
            n:    privJwk.n,
            e:    privJwk.e,
            d:    privJwk.d,
            p:    privJwk.p,
            q:    privJwk.q,
            dp:   privJwk.dp,
            dq:   privJwk.dq,
            qi:   privJwk.qi,
            kid:  kid,
            alg:  'RS256',
            use:  'sig'
        };

        keyStrings = {
            public:  { jwk: JSON.stringify(cleanPubJwk, null, 2),  pem: pubPem },
            private: { jwk: JSON.stringify(cleanPrivJwk, null, 2), pem: privPem }
        };

        if (keyList) keyList.hidden = false;

        // Auto-fill: drop the private key PEM into the RS256 signer textbox so
        // the user can sign immediately without manually copying it across.
        if (autoFillPrivateKey && privateKeyPem) {
            privateKeyPem.value = privPem;
            // Make sure the algorithm switches to RS256 so the key is actually used.
            try {
                const header = JSON.parse(jwtParts[0].value || '{}');
                header.alg = 'RS256';
                jwtParts[0].value = JSON.stringify(header, null, 2);
            } catch (_) {
                jwtParts[0].value = JSON.stringify({ alg: 'RS256', typ: 'JWT' }, null, 2);
            }
            if (algorithmSelect) algorithmSelect.value = 'RS256';
            updateAlgorithmSections('RS256');
            await updateJWT();
            saveEncoderState();
        }
    }

    // Persist the generated key pair in storage as JWK so it survives popup reopens.
    async function persistGeneratedKeys(pair) {
        try {
            const pubJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
            const privJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
            await browser.storage.local.set({
                generatedRsaKeyPair: { publicKey: pubJwk, privateKey: privJwk }
            });
        } catch (_) { /* non-fatal */ }
    }

    async function loadPersistedKeyPair() {
        try {
            const stored = await browser.storage.local.get('generatedRsaKeyPair');
            const data = stored.generatedRsaKeyPair;
            if (!data || !data.publicKey || !data.privateKey) return;
            const publicKey = await crypto.subtle.importKey(
                'jwk', data.publicKey,
                { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
                true, ['verify']
            );
            const privateKey = await crypto.subtle.importKey(
                'jwk', data.privateKey,
                { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
                true, ['sign']
            );
            generatedKeys = { publicKey, privateKey };
            await renderGeneratedKeys();
        } catch (_) { /* non-fatal */ }
    }

    // ----- Copy buttons: each button declares data-key (public|private) and
    // data-format (jwk|pem). We look up the pre-exported string in keyStrings. -----
    copyButtons.forEach(btn => {
        btn.addEventListener('click', async () => {
            const which = btn.getAttribute('data-key');     // public | private
            const format = btn.getAttribute('data-format'); // jwk | pem
            if (!which || !format) return;
            const text = keyStrings && keyStrings[which] && keyStrings[which][format];
            if (!text) {
                error.textContent = 'Generate a key pair first.';
                return;
            }
            try {
                await navigator.clipboard.writeText(text);
                btn.classList.add('copied');
                setTimeout(() => btn.classList.remove('copied'), 1400);
            } catch (clipError) {
                error.textContent = 'Copy failed: ' +
                    (clipError instanceof Error ? clipError.message : String(clipError));
            }
        });
    });

    // ----- JWK header injection (embed public key in header) -----
    if (addJwkHeaderButton) {
        addJwkHeaderButton.addEventListener('click', async () => {
            error.style.color = '';
            error.textContent = '';
            if (!generatedKeys) {
                error.textContent = 'Generate a key pair first (Key Pair Generator section).';
                return;
            }
            try {
                const header = JSON.parse(jwtParts[0].value || '{}');
                const pubJwk = await crypto.subtle.exportKey('jwk', generatedKeys.publicKey);
                // Use the header's existing kid if present, otherwise compute
                // the RFC 7638 thumbprint of the public key. The same kid is
                // placed in both the JWT header and the embedded jwk so they
                // match exactly.
                let kid = (typeof header.kid === 'string' && header.kid.length > 0)
                    ? header.kid
                    : await computeJwkThumbprint(pubJwk);
                header.alg = 'RS256';
                header.kid = kid;
                header.jwk = {
                    kty: pubJwk.kty,
                    n: pubJwk.n,
                    e: pubJwk.e,
                    alg: 'RS256',
                    use: 'sig',
                    kid: kid
                };
                jwtParts[0].value = JSON.stringify(header, null, 2);
                if (algorithmSelect) algorithmSelect.value = 'RS256';
                updateAlgorithmSections('RS256');
                await updateJWT();
                saveEncoderState();
                error.style.color = '#66bb6a';
                error.textContent = `Embedded public key as jwk in JWT header (kid=${kid}).`;
            } catch (e) {
                error.textContent = e instanceof Error ? e.message : String(e);
            }
        });
    }

    // ----- JKU header injection (JWK Set URL) -----
    if (addJkuHeaderButton) {
        addJkuHeaderButton.addEventListener('click', async () => {
            error.style.color = '';
            error.textContent = '';
            try {
                const header = JSON.parse(jwtParts[0].value || '{}');
                if (!header.jku) {
                    header.jku = 'https://example.com/.well-known/jwks.json';
                }
                jwtParts[0].value = JSON.stringify(header, null, 2);
                await updateJWT();
                saveEncoderState();
                error.style.color = '#66bb6a';
                error.textContent = 'Added jku field to JWT header (edit the URL as needed).';
            } catch (e) {
                error.textContent = e instanceof Error ? e.message : String(e);
            }
        });
    }

    // NOTE: The "Apply Generated Key Pair" button was removed from the UI.
    // The same behavior is now triggered automatically when the user clicks
    // Generate RSA Key Pair (see renderGeneratedKeys(true)).

    // ----- Restore state on open -----
    // Order of precedence for header/payload:
    //   1. Saved encoder state (preserves the user's manual edits).
    //   2. decodedJwtParts (preserves a JWT decoded on the Decode tab).
    // Order of precedence for HS256 secret:
    //   1. Saved encoder state.
    //   2. crackedJwtSecret (recovered on the Brute-force tab).
    browser.storage.local.get(['decodedJwtParts', 'encoderState', 'crackedJwtSecret']).then(stored => {
        const enc = stored.encoderState;
        if (enc && typeof enc === 'object' && 'header' in enc && 'payload' in enc) {
            // 1. Restore the user's saved encoder inputs verbatim.
            if (jwtParts[0]) jwtParts[0].value = enc.header || '';
            if (jwtParts[1]) jwtParts[1].value = enc.payload || '';
            if (privateKeyPem) privateKeyPem.value = enc.rs256PrivateKeyPem || '';
            if (enc.hs256Secret && secretInput) {
                secretInput.value = enc.hs256Secret;
                userTouchedSecret = true; // suppress cracked-secret override below
            }
        } else if (stored.decodedJwtParts) {
            // 2. Fall back to whatever was decoded on the Decode tab.
            const decoded = stored.decodedJwtParts;
            if (decoded && typeof decoded === 'object' && 'header' in decoded && 'payload' in decoded) {
                if (jwtParts[0]) jwtParts[0].value = JSON.stringify(decoded.header, null, 2);
                if (jwtParts[1]) jwtParts[1].value = JSON.stringify(decoded.payload, null, 2);
            }
        }
        // 3. Brute-force fallback: if no saved secret yet, use the cracked one.
        if (!userTouchedSecret && secretInput && !secretInput.value) {
            const cracked = stored.crackedJwtSecret;
            if (cracked && typeof cracked === 'string' && cracked.length > 0) {
                secretInput.value = cracked;
            }
        }
        updateHs256KeyList();
        syncAlgorithmFromHeader();
        // 4. Restore any persisted RSA key pair so copy buttons keep working.
        return loadPersistedKeyPair();
    }).then(() => {
        updateJWT();
    }).catch(storageError => {
        error.textContent = storageError instanceof Error ? storageError.message : String(storageError);
        updateJWT();
    });
}

// ============================================================
// Shared helpers
// ============================================================
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
    return btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function base64EncodeBytes(bytes) {
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary);
}

function bytesToAscii(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return s;
}

// ============================================================
// JWT signers
// ============================================================
function getHs256KeyBytes(secret) {
    return secret ? new TextEncoder().encode(secret) : new Uint8Array([0]);
}

async function createJWTNone(header, payload) {
    const encodedHeader = base64UrlEncode(JSON.stringify(header));
    const encodedPayload = base64UrlEncode(JSON.stringify(payload));
    return `${encodedHeader}.${encodedPayload}.`;
}

async function createJWTHS256(header, payload, secret) {
    const encodedHeader = base64UrlEncode(JSON.stringify(header));
    const encodedPayload = base64UrlEncode(JSON.stringify(payload));
    const dataToSign = `${encodedHeader}.${encodedPayload}`;

    const key = await crypto.subtle.importKey(
        'raw',
        getHs256KeyBytes(secret),
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

async function createJWTRS256(header, payload, pemText) {
    if (!pemText || !pemText.trim()) {
        throw new Error('RS256 requires a private key. Paste a PEM private key or load a DER/PEM file.');
    }
    const key = await importPrivateKeyFromPem(pemText);
    const encodedHeader = base64UrlEncode(JSON.stringify(header));
    const encodedPayload = base64UrlEncode(JSON.stringify(payload));
    const dataToSign = `${encodedHeader}.${encodedPayload}`;
    const signature = await crypto.subtle.sign(
        'RSASSA-PKCS1-v1_5',
        key,
        new TextEncoder().encode(dataToSign)
    );
    const encodedSignature = base64UrlEncodeBytes(new Uint8Array(signature));
    return `${dataToSign}.${encodedSignature}`;
}

// ============================================================
// RSA key import / export (PEM and DER)
// ============================================================
function detectPemLabel(pem) {
    const m = pem.match(/-----BEGIN ([A-Z0-9 ]+)-----/);
    return m ? m[1].trim() : null;
}

function pemToBytes(pem) {
    const cleaned = pem
        .replace(/-----BEGIN [A-Z0-9 ]+-----/g, '')
        .replace(/-----END [A-Z0-9 ]+-----/g, '')
        .replace(/\s+/g, '');
    const binary = atob(cleaned);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

function bytesToPem(bytes, label) {
    const b64 = base64EncodeBytes(bytes);
    const lines = b64.match(/.{1,64}/g) || [];
    return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
}

// RFC 7638 §3: JWK thumbprint uses the lexicographically ordered required
// members for RSA ({e, kty, n}) or octet-sequence ({k, kty}) keys.
async function computeJwkThumbprint(jwk) {
    const canonical = jwk.kty === 'oct'
        ? JSON.stringify({ k: jwk.k, kty: jwk.kty })
        : JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n });
    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
    return base64UrlEncodeBytes(new Uint8Array(hash));
}

async function importPrivateKeyFromPem(pem) {
    const label = detectPemLabel(pem);
    if (!label) {
        throw new Error('Unrecognized PEM format. Expected "-----BEGIN PRIVATE KEY-----" (PKCS#8).');
    }
    if (label === 'PRIVATE KEY' || label === 'ENCRYPTED PRIVATE KEY') {
        const bytes = pemToBytes(pem);
        return await importPrivateKeyFromBytes(bytes);
    }
    if (label === 'RSA PRIVATE KEY') {
        throw new Error('PKCS#1 "RSA PRIVATE KEY" is not supported by WebCrypto. Please convert it to PKCS#8 (BEGIN PRIVATE KEY).');
    }
    throw new Error(`Unsupported PEM label "${label}". Use PKCS#8 (BEGIN PRIVATE KEY).`);
}

async function importPrivateKeyFromBytes(bytes) {
    // Try PKCS#8 first (most common for RS256)
    try {
        return await crypto.subtle.importKey(
            'pkcs8',
            bytes,
            { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
            true,
            ['sign']
        );
    } catch (e) {
        // Fall back to PKCS#1 by wrapping in a minimal PKCS#8 shim
        try {
            return await importPkcs1PrivateKey(bytes);
        } catch (_) {
            throw new Error('Could not import private key. Expected PKCS#8 (BEGIN PRIVATE KEY) format.');
        }
    }
}

// Convert a PKCS#1 RSA private key into a JWK, then import via JWK.
// This handles .der files exported by OpenSSL with `openssl genrsa`/`rsa` commands
// in the legacy PKCS#1 RSAPrivateKey format.
async function importPkcs1PrivateKey(derBytes) {
    // Parse ASN.1 manually to extract the integer components.
    const parts = parseRsaPrivateKeyAsn1(derBytes);
    if (!parts) {
        throw new Error('Failed to parse PKCS#1 RSA private key.');
    }
    const jwk = {
        kty: 'RSA',
        n: base64UrlEncodeBytes(parts.modulus),
        e: base64UrlEncodeBytes(parts.publicExponent),
        d: base64UrlEncodeBytes(parts.privateExponent),
        p: base64UrlEncodeBytes(parts.prime1),
        q: base64UrlEncodeBytes(parts.prime2),
        dp: base64UrlEncodeBytes(parts.exponent1),
        dq: base64UrlEncodeBytes(parts.exponent2),
        qi: base64UrlEncodeBytes(parts.coefficient)
    };
    return await crypto.subtle.importKey(
        'jwk',
        jwk,
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        true,
        ['sign']
    );
}

// Minimal ASN.1 parser for an RSAPrivateKey SEQUENCE (RFC 8017).
function parseRsaPrivateKeyAsn1(bytes) {
    let cursor = 0;
    function readTag() {
        const tag = bytes[cursor++];
        const lenByte = bytes[cursor++];
        let length;
        if (lenByte & 0x80) {
            const numBytes = lenByte & 0x7f;
            length = 0;
            for (let i = 0; i < numBytes; i++) length = (length << 8) | bytes[cursor++];
        } else {
            length = lenByte;
        }
        return { tag, length };
    }
    function readInteger() {
        const { tag, length } = readTag();
        if (tag !== 0x02) return null;
        let start = cursor;
        // Skip leading zero used to indicate positive integer
        if (bytes[start] === 0 && length > 1) { start++; }
        const value = bytes.slice(start, cursor + length);
        cursor += length;
        return value;
    }
    const outer = readTag();
    if (outer.tag !== 0x30) return null;
    const version = readInteger();
    if (!version) return null;
    const modulus = readInteger();
    const publicExponent = readInteger();
    const privateExponent = readInteger();
    const prime1 = readInteger();
    const prime2 = readInteger();
    const exponent1 = readInteger();
    const exponent2 = readInteger();
    const coefficient = readInteger();
    if (!modulus || !publicExponent || !privateExponent) return null;
    return { modulus, publicExponent, privateExponent, prime1, prime2, exponent1, exponent2, coefficient };
}

async function exportPublicKeyAsPem(publicKey) {
    const exported = await crypto.subtle.exportKey('spki', publicKey);
    return bytesToPem(new Uint8Array(exported), 'PUBLIC KEY');
}

async function exportPrivateKeyAsPem(privateKey) {
    const exported = await crypto.subtle.exportKey('pkcs8', privateKey);
    return bytesToPem(new Uint8Array(exported), 'PRIVATE KEY');
}