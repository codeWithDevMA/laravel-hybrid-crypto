<?php

namespace Vendor\HybridCrypto\Drivers;

use RuntimeException;
use Vendor\HybridCrypto\Contracts\CryptoDriver;

class X25519Driver extends AbstractHybridCryptoDriver implements CryptoDriver
{
    private const ALGORITHM = 'ecdh';

    public function algorithm(): string
    {
        return self::ALGORITHM;
    }

    public function publicKey(): string
    {
        $keyPair = $this->loadKeyPair();
        $public = (string) ($keyPair['public_key_b64'] ?? '');
        if ($public === '') {
            throw new RuntimeException('X25519 public key is missing.');
        }

        return $public;
    }

    public function generateEphemeralKeyPair(): array
    {
        $keyPair = sodium_crypto_box_keypair();

        return [
            'algorithm'       => self::ALGORITHM,
            'private_key_b64' => base64_encode(sodium_crypto_box_secretkey($keyPair)),
            'public_key_b64'  => base64_encode(sodium_crypto_box_publickey($keyPair)),
        ];
    }

    public function encrypt(string $jsonPlaintext, string|int|null $salt, string $receiverPublicKey): array
    {
        $receiverPublic = $this->decodeBase64($receiverPublicKey, 'receiver public key', 32);
        $ephemeralKeyPair = sodium_crypto_box_keypair();
        $ephemeralSecret = sodium_crypto_box_secretkey($ephemeralKeyPair);
        $ephemeralPublic = sodium_crypto_box_publickey($ephemeralKeyPair);

        $aesKey = $this->deriveAesKey(
            sodium_crypto_scalarmult($ephemeralSecret, $receiverPublic),
            $salt,
            self::ALGORITHM
        );

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
            throw new RuntimeException('Failed to encrypt payload with X25519.');
        }

        return array_merge($this->encodeEncryptedPayload($iv, $ciphertext, $tag), [
            'algorithm' => self::ALGORITHM,
            'ephemeral_public_key' => base64_encode($ephemeralPublic),
            'public_key' => base64_encode($ephemeralPublic),
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
        if ($encryptedB64 === '' || $ivB64 === '') {
            throw new RuntimeException('Missing X25519 encrypted payload fields.');
        }

        $encrypted = $this->decodeBase64($encryptedB64, 'encrypted payload');
        $iv = $this->decodeBase64($ivB64, 'IV', 12);
        $parts = $this->splitEncryptedPayload($encrypted);

        $senderPublic = $this->decodeBase64($senderPublicKey, 'sender public key', 32);
        $keyPair = $this->loadKeyPair($keyMaterial);
        $private = $this->decodeBase64((string) ($keyPair['private_key_b64'] ?? ''), 'X25519 private key', 32);

        $aesKey = $this->deriveAesKey(
            sodium_crypto_scalarmult($private, $senderPublic),
            $salt,
            self::ALGORITHM
        );

        $jsonPlaintext = openssl_decrypt(
            $parts['ciphertext'],
            'aes-256-gcm',
            $aesKey,
            OPENSSL_RAW_DATA,
            $iv,
            $parts['tag'],
        );

        if ($jsonPlaintext === false) {
            throw new RuntimeException('Failed to decrypt payload with X25519.');
        }

        return $jsonPlaintext;
    }

    /**
     * @param  array{private_key_b64: string, public_key_b64: string}|null  $keyMaterialOverride
     *         When non-null, this key material is returned as-is. The package
     *         never stores it — the caller is responsible for persistence.
     * @return array{private_key_b64: string, public_key_b64: string}
     */
    private function loadKeyPair(?array $keyMaterialOverride = null): array
    {
        if ($keyMaterialOverride !== null) {
            if (!empty($keyMaterialOverride['private_key_b64']) && !empty($keyMaterialOverride['public_key_b64'])) {
                return $keyMaterialOverride;
            }

            throw new RuntimeException('Supplied X25519 key material is missing private_key_b64 or public_key_b64.');
        }

        $path = $this->resolvePath((string) config('hybrid-crypto.paths.ecdh_keypair'));
        $existing = $this->readJsonFile($path);
        if (is_array($existing)) {
            if (!empty($existing['private_key_b64']) && !empty($existing['public_key_b64'])) {
                return $existing;
            }

            throw new RuntimeException('Stored X25519 key pair is invalid.');
        }

        $keyPair = sodium_crypto_box_keypair();
        $data = [
            'private_key_b64' => base64_encode(sodium_crypto_box_secretkey($keyPair)),
            'public_key_b64'  => base64_encode(sodium_crypto_box_publickey($keyPair)),
        ];

        $this->writeJsonFile($path, $data);

        return $data;
    }
}
