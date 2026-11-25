@once
<script>
(() => {
    if (window.HybridCryptoBrowser) {
        return;
    }

    const encoder = new TextEncoder();
    const zeroSalt = new Uint8Array(32);
    const publicKeyRequests = new Map();
    const mlKemImportUrl = 'https://esm.sh/@noble/post-quantum/ml-kem.js';

    function base64ToBytes(value, label) {
        if (typeof value !== 'string') {
            throw new Error(`${label} must be a base64 string.`);
        }

        const normalized = value.replace(/\s+/g, '').trim();
        if (normalized === '') {
            throw new Error(`${label} is required.`);
        }

        try {
            const binary = atob(normalized);
            return Uint8Array.from(binary, (char) => char.codePointAt(0));
        } catch (error) {
            throw new Error(`${label} is not valid base64.`);
        }
    }

    function bytesToBase64(bytes) {
        return btoa(Array.from(bytes, (byte) => String.fromCodePoint(byte)).join(''));
    }

    function containsByteSequence(bytes, sequence) {
        if (!Array.isArray(sequence) || sequence.length === 0 || bytes.length < sequence.length) {
            return false;
        }

        for (let index = 0; index <= bytes.length - sequence.length; index += 1) {
            let matches = true;

            for (let offset = 0; offset < sequence.length; offset += 1) {
                if (bytes[index + offset] !== sequence[offset]) {
                    matches = false;
                    break;
                }
            }

            if (matches) {
                return true;
            }
        }

        return false;
    }

    function firstNonEmptyString(...values) {
        for (const value of values) {
            if (typeof value !== 'string') {
                continue;
            }

            const trimmed = value.trim();
            if (trimmed !== '') {
                return trimmed;
            }
        }

        return null;
    }

    function normalizeSalt(salt) {
        if (salt === null || salt === undefined) {
            return null;
        }

        const normalized = String(salt).trim();
        if (normalized === '' || normalized === '0') {
            return null;
        }

        return normalized;
    }

    function normalizeKdfInfoPrefix(prefix) {
        if (typeof prefix !== 'string') {
            throw new Error('KDF info prefix is required.');
        }

        const normalized = prefix.trim();
        if (normalized === '') {
            throw new Error('KDF info prefix is required.');
        }

        return normalized;
    }

    function normalizeAlgorithm(value) {
        const normalized = String(value ?? '').trim().toLowerCase();
        if (normalized === '') {
            throw new Error('Crypto algorithm is required.');
        }

        switch (normalized) {
            case 'p256':
            case 'secp256r1':
            case 'prime256v1':
            case 'p-256':
                return 'p256';
            case 'p384':
            case 'secp384r1':
            case 'prime384v1':
            case 'p-384':
                return 'p384';
            case 'ecdh':
            case 'x25519':
                return 'ecdh';
            case 'mlkem768':
            case 'ml-kem-768':
            case 'mlkem-768':
                return 'mlkem768';
            default:
                throw new Error(`Unsupported crypto algorithm: ${value}`);
        }
    }

    function decodePublicKeyBytes(value, label) {
        if (typeof value !== 'string') {
            throw new Error(`${label} must be a string.`);
        }

        const trimmed = value.trim();
        if (trimmed === '') {
            throw new Error(`${label} is required.`);
        }

        if (trimmed.startsWith('-----BEGIN')) {
            const stripped = trimmed
                .replace(/-----BEGIN[^-]+-----/g, '')
                .replace(/-----END[^-]+-----/g, '')
                .replace(/\s+/g, '');

            if (stripped === '') {
                throw new Error(`Invalid PEM for ${label}.`);
            }

            return base64ToBytes(stripped, label);
        }

        return base64ToBytes(trimmed, label);
    }

    function detectAlgorithmFromPublicKey(value) {
        const bytes = decodePublicKeyBytes(value, 'public key');

        if (bytes.length === 1184) {
            return 'mlkem768';
        }

        if (
            containsByteSequence(bytes, [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]) ||
            (bytes.length === 65 && bytes[0] === 0x04)
        ) {
            return 'p256';
        }

        if (
            containsByteSequence(bytes, [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]) ||
            (bytes.length === 97 && bytes[0] === 0x04)
        ) {
            return 'p384';
        }

        if (
            containsByteSequence(bytes, [0x06, 0x03, 0x2b, 0x65, 0x6e]) ||
            bytes.length === 32
        ) {
            return 'ecdh';
        }

        throw new Error(`Unable to infer crypto algorithm from public key length ${bytes.length}.`);
    }

    function resolvePublicKeyValue(responseJson) {
        const publicKey = firstNonEmptyString(
            responseJson?.server_public,
            responseJson?.public_key,
            responseJson?.exchange_public_key,
            responseJson?.server_public_key
        );

        if (!publicKey) {
            throw new Error('Public key response is missing server_public.');
        }

        return publicKey;
    }

    function normalizePublicKeyResponse(responseJson) {
        if (!responseJson || typeof responseJson !== 'object') {
            throw new Error('Public key response must be an object.');
        }

        const serverPublic = resolvePublicKeyValue(responseJson);
        const detectedAlgorithm = detectAlgorithmFromPublicKey(serverPublic);

        return {
            server_public: serverPublic,
            algorithm: detectedAlgorithm,
        };
    }

    async function readJsonResponse(response, label) {
        const contentType = response.headers.get('content-type') || '';
        if (contentType.includes('application/json')) {
            return await response.json();
        }

        const text = await response.text();
        if (response.status === 429) {
            throw new Error(`Too many ${label} attempts. Please wait a minute and try again.`);
        }

        throw new Error(
            text && !text.startsWith('<!DOCTYPE')
                ? text
                : `The server returned an unexpected ${label} response.`
        );
    }

    async function fetchPublicKey(url, options = {}) {
        const trimmedUrl = typeof url === 'string' ? url.trim() : '';
        if (trimmedUrl === '') {
            throw new Error('publicKeyUrl is required.');
        }

        const cacheKey = trimmedUrl;
        if (publicKeyRequests.has(cacheKey)) {
            return await publicKeyRequests.get(cacheKey);
        }

        const request = (async () => {
            const response = await fetch(trimmedUrl, {
                method: 'GET',
                headers: {
                    Accept: 'application/json',
                    ...(options.headers || {}),
                },
                credentials: options.credentials ?? 'same-origin',
            });

            const data = await readJsonResponse(response, 'public key');
            if (!response.ok || data?.success !== true) {
                throw new Error(data?.message || 'Failed to fetch public key.');
            }

            return normalizePublicKeyResponse(data);
        })();

        publicKeyRequests.set(
            cacheKey,
            request.catch((error) => {
                publicKeyRequests.delete(cacheKey);
                throw error;
            })
        );

        return await request;
    }

    async function deriveSharedSecret(keyMeta) {
        const publicKeyBytes = decodePublicKeyBytes(keyMeta.server_public, 'server public key');

        if (keyMeta.algorithm === 'mlkem768') {
            const { ml_kem768 } = await import(mlKemImportUrl);
            const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKeyBytes);

            return {
                sharedSecret,
                payloadExtra: {
                    mlkem_ciphertext: bytesToBase64(cipherText),
                    public_key: bytesToBase64(cipherText),
                    ephemeral_public_key: bytesToBase64(cipherText),
                },
            };
        }

        if (keyMeta.algorithm === 'ecdh') {
            if (!crypto?.subtle?.generateKey) {
                throw new Error('Browser X25519 support is unavailable in this environment.');
            }

            const serverPublicKey = await crypto.subtle.importKey(
                'raw',
                publicKeyBytes,
                { name: 'X25519' },
                false,
                []
            );

            const clientKeyPair = await crypto.subtle.generateKey(
                { name: 'X25519' },
                true,
                ['deriveBits']
            );

            const clientPublicKey = new Uint8Array(await crypto.subtle.exportKey('raw', clientKeyPair.publicKey));
            const sharedBits = await crypto.subtle.deriveBits(
                { name: 'X25519', public: serverPublicKey },
                clientKeyPair.privateKey,
                256
            );

            return {
                sharedSecret: new Uint8Array(sharedBits),
                payloadExtra: {
                    client_public: bytesToBase64(clientPublicKey),
                    public_key: bytesToBase64(clientPublicKey),
                    ephemeral_public_key: bytesToBase64(clientPublicKey),
                },
            };
        }

        const curveName = keyMeta.algorithm === 'p256'
            ? 'P-256'
            : keyMeta.algorithm === 'p384'
                ? 'P-384'
                : null;

        if (!curveName) {
            throw new Error(`Browser encryption is not enabled for algorithm "${keyMeta.algorithm}".`);
        }

        const serverPublicKey = await crypto.subtle.importKey(
            'spki',
            publicKeyBytes,
            { name: 'ECDH', namedCurve: curveName },
            false,
            []
        );

        const clientKeyPair = await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: curveName },
            true,
            ['deriveBits']
        );

        const clientPublicKey = new Uint8Array(await crypto.subtle.exportKey('spki', clientKeyPair.publicKey));
        const sharedBits = await crypto.subtle.deriveBits(
            { name: 'ECDH', public: serverPublicKey },
            clientKeyPair.privateKey,
            256
        );

        return {
            sharedSecret: new Uint8Array(sharedBits),
            payloadExtra: {
                client_public: bytesToBase64(clientPublicKey),
                public_key: bytesToBase64(clientPublicKey),
                ephemeral_public_key: bytesToBase64(clientPublicKey),
            },
        };
    }

    async function deriveAesKey(sharedSecret, kdfInfoPrefix, algorithm, salt) {
        const hkdfKey = await crypto.subtle.importKey(
            'raw',
            sharedSecret,
            { name: 'HKDF' },
            false,
            ['deriveKey']
        );

        return await crypto.subtle.deriveKey(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: salt === null ? zeroSalt : encoder.encode(salt),
                info: encoder.encode(`${kdfInfoPrefix}|${algorithm}`),
            },
            hkdfKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt']
        );
    }

    async function encryptData(data, options = {}) {
        const kdfInfoPrefix = normalizeKdfInfoPrefix(options.kdfInfoPrefix);
        const normalizedSalt = normalizeSalt(options.salt);
        const payload = JSON.stringify(data);

        const keyMeta = options.publicKeyResponse
            ? normalizePublicKeyResponse(options.publicKeyResponse)
            : options.publicKey
                ? normalizePublicKeyResponse({
                    server_public: options.publicKey,
                })
                : await fetchPublicKey(options.publicKeyUrl, options);

        const { sharedSecret, payloadExtra } = await deriveSharedSecret(keyMeta);
        const aesKey = await deriveAesKey(sharedSecret, kdfInfoPrefix, keyMeta.algorithm, normalizedSalt);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encryptedBuffer = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            aesKey,
            encoder.encode(payload)
        );

        const envelope = {
            algorithm: keyMeta.algorithm,
            encrypted: bytesToBase64(new Uint8Array(encryptedBuffer)),
            iv: bytesToBase64(iv),
            gcmNonce: bytesToBase64(iv),
            ...payloadExtra,
        };

        if (normalizedSalt !== null) {
            envelope.salt = normalizedSalt;
        }

        return envelope;
    }

    window.HybridCryptoBrowser = Object.freeze({
        publicKey: fetchPublicKey,
        detectAlgorithm: detectAlgorithmFromPublicKey,
        normalizeSalt,
        encryptData,
    });

    window.LaravelHybridCryptoBrowser = window.HybridCryptoBrowser;
})();
</script>
@endonce
