<?php

namespace Vendor\HybridCrypto\Drivers;

use ParagonIE\PQCrypto\Compat;
use RuntimeException;
use Vendor\HybridCrypto\Contracts\CryptoDriver;

class MlKem768Driver extends AbstractHybridCryptoDriver implements CryptoDriver
{
    private const ALGORITHM = 'mlkem768';

    public function algorithm(): string
    {
        return self::ALGORITHM;
    }

    public function publicKey(): string
    {
        $keyPair = $this->loadKeyPair();
        $public = (string) ($keyPair['public_key_b64'] ?? '');
        if ($public === '') {
            throw new RuntimeException('ML-KEM public key is missing.');
        }

        return $public;
    }

    public function generateEphemeralKeyPair(): array
    {
        [$decapsulationKey, $encapsulationKey] = Compat::mlkem768_keygen();

        return [
            'algorithm'       => self::ALGORITHM,
            'private_key_b64' => base64_encode($decapsulationKey->bytes()),
            'public_key_b64'  => base64_encode($encapsulationKey->bytes()),
        ];
    }

    public function encrypt(string $jsonPlaintext, string|int|null $salt, string $receiverPublicKey): array
    {
        $publicKey = $this->decodeBase64($receiverPublicKey, 'ML-KEM public key', Compat::MLKEM768_ENCAPSKEY_BYTES);
        $encapsulated = Compat::mlkem768_encaps($publicKey);

        $sharedSecret = $encapsulated['sharedKey'];
        if (!is_string($sharedSecret) || $sharedSecret === '') {
            throw new RuntimeException('Failed to derive ML-KEM shared secret.');
        }

        $aesKey = $this->deriveAesKey($sharedSecret, $salt, self::ALGORITHM);
        $iv = random_bytes(12);
        $tag = '';
        $ciphertext = openssl_encrypt(
            $jsonPlaintext,
            'aes-256-gcm',
            $aesKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
        );

        if ($ciphertext === false) {
            throw new RuntimeException('Failed to encrypt payload with ML-KEM-768.');
        }

        return array_merge($this->encodeEncryptedPayload($iv, $ciphertext, $tag), [
            'algorithm' => self::ALGORITHM,
            'ephemeral_public_key' => base64_encode($encapsulated['ciphertext']),
            'public_key' => base64_encode($encapsulated['ciphertext']),
        ]);
    }

    public function decrypt(array $payload, string|int|null $salt, string $senderPublicKey, ?array $keyMaterial = null): string
    {
        $this->verifyTimestamp($payload);

        $encryptedB64 = (string) ($payload['encrypted'] ?? '');
        $ivB64 = (string) ($payload['iv'] ?? '');
        if ($ivB64 === '') {
            $ivB64 = (string) ($payload['gcmNonce'] ?? '');
        }
        $ciphertextB64 = trim($senderPublicKey);
        if ($ciphertextB64 === '') {
            $ciphertextB64 = (string) ($payload['public_key'] ?? $payload['ephemeral_public_key'] ?? '');
        }

        if ($encryptedB64 === '' || $ivB64 === '' || $ciphertextB64 === '') {
            throw new RuntimeException('Missing ML-KEM encrypted payload fields.');
        }

        $encrypted = $this->decodeBase64($encryptedB64, 'encrypted payload');
        $iv = $this->decodeBase64($ivB64, 'IV', 12);
        $parts = $this->splitEncryptedPayload($encrypted);

        $aesKey = $this->deriveAesKey($this->sharedSecret($ciphertextB64, $keyMaterial), $salt, self::ALGORITHM);

        $jsonPlaintext = openssl_decrypt(
            $parts['ciphertext'],
            'aes-256-gcm',
            $aesKey,
            OPENSSL_RAW_DATA,
            $iv,
            $parts['tag'],
        );

        if ($jsonPlaintext === false) {
            throw new RuntimeException('Failed to decrypt payload with ML-KEM-768.');
        }

        return $jsonPlaintext;
    }

    /**
     * @param  array{private_key_b64: string, public_key_b64: string}|null  $keyMaterial
     *         Optional caller-supplied key material. The package never stores
     *         this — the caller is responsible for persistence.
     */
    private function sharedSecret(string $ciphertextB64, ?array $keyMaterial = null): string
    {
        if ($keyMaterial !== null) {
            $privateKeyB64 = (string) ($keyMaterial['private_key_b64'] ?? '');
            if ($privateKeyB64 === '') {
                throw new RuntimeException('Supplied ML-KEM key material is missing private_key_b64.');
            }
        } else {
            $storedKeyPair = $this->loadKeyPair();
            $privateKeyB64 = (string) ($storedKeyPair['private_key_b64'] ?? '');
        }

        $privateKey = $this->decodeBase64($privateKeyB64, 'ML-KEM private key');
        $ciphertext = $this->decodeBase64($ciphertextB64, 'ML-KEM ciphertext', Compat::MLKEM768_CIPHERTEXT_BYTES);

        $sharedSecret = Compat::mlkem768_decaps($privateKey, $ciphertext);
        if (!is_string($sharedSecret) || $sharedSecret === '') {
            throw new RuntimeException('Failed to decapsulate ML-KEM shared secret.');
        }

        return $sharedSecret;
    }

    /**
     * @return array{private_key_b64: string, public_key_b64: string}
     */
    private function loadKeyPair(): array
    {
        $path = $this->resolvePath((string) config('hybrid-crypto.paths.mlkem768_keypair'));
        $existing = $this->readJsonFile($path);
        if (is_array($existing)) {
            if (!empty($existing['private_key_b64']) && !empty($existing['public_key_b64'])) {
                return $existing;
            }

            throw new RuntimeException('Stored ML-KEM key pair is invalid.');
        }

        [$decapsulationKey, $encapsulationKey] = Compat::mlkem768_keygen();
        $data = [
            'private_key_b64' => base64_encode($decapsulationKey->bytes()),
            'public_key_b64' => base64_encode($encapsulationKey->bytes()),
        ];

        $this->writeJsonFile($path, $data);

        return $data;
    }
}
