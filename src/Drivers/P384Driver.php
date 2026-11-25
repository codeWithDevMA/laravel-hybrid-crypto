<?php

namespace Vendor\HybridCrypto\Drivers;

use OpenSSLAsymmetricKey;
use RuntimeException;
use Vendor\HybridCrypto\Contracts\CryptoDriver;

class P384Driver extends AbstractHybridCryptoDriver implements CryptoDriver
{
    private const ALGORITHM = 'p384';
    private const CURVE = 'secp384r1';
    private ?string $opensslConfigPath = null;

    public function algorithm(): string
    {
        return self::ALGORITHM;
    }

    public function publicKey(): string
    {
        $details = openssl_pkey_get_details($this->privateKey());
        if (!is_array($details) || empty($details['key']) || !is_string($details['key'])) {
            throw new RuntimeException('Unable to extract P-384 public key.');
        }

        return $this->pemToDerBase64($details['key']);
    }

    public function generateEphemeralKeyPair(): array
    {
        $configPath = $this->prepareOpenSsl();
        $resource = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'private_key_bits' => 384,
            'curve_name'       => self::CURVE,
            ...($configPath ? ['config' => $configPath] : []),
        ]);

        if ($resource === false) {
            $suffix = $this->collectOpenSslErrors();
            throw new RuntimeException('Failed to generate P-384 ephemeral key pair.' . ($suffix !== '' ? ' ' . $suffix : ''));
        }

        $pem = '';
        $exportOptions = $configPath ? ['config' => $configPath] : [];
        if (!openssl_pkey_export($resource, $pem, null, $exportOptions) || $pem === '') {
            throw new RuntimeException('Failed to export P-384 ephemeral private key. ' . $this->collectOpenSslErrors());
        }

        $details = openssl_pkey_get_details($resource);
        if (!is_array($details) || empty($details['key']) || !is_string($details['key'])) {
            throw new RuntimeException('Failed to extract P-384 ephemeral public key.');
        }

        return [
            'algorithm'       => self::ALGORITHM,
            'private_key_pem' => $pem,
            'public_key_b64'  => $this->pemToDerBase64($details['key']),
        ];
    }

    public function encrypt(string $jsonPlaintext, string|int|null $salt, string $receiverPublicKey): array
    {
        $ephemeralPrivate = $this->ephemeralPrivateKey();
        $ephemeralPublic = openssl_pkey_get_details($ephemeralPrivate);
        if (!is_array($ephemeralPublic) || empty($ephemeralPublic['key']) || !is_string($ephemeralPublic['key'])) {
            throw new RuntimeException('Failed to extract P-384 ephemeral public key.');
        }

        $sharedSecret = $this->sharedSecretFromReceiverPublicKey($receiverPublicKey, $ephemeralPrivate);
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
            throw new RuntimeException('Failed to encrypt payload with P-384.');
        }

        return array_merge($this->encodeEncryptedPayload($iv, $ciphertext, $tag), [
            'algorithm' => self::ALGORITHM,
            'ephemeral_public_key' => $this->pemToDerBase64($ephemeralPublic['key']),
            'public_key' => $this->pemToDerBase64($ephemeralPublic['key']),
        ]);
    }

    public function decrypt(array $payload, string|int|null $salt, string $senderPublicKey, ?array $keyMaterial = null): string
    {
        $encryptedB64 = (string) ($payload['encrypted'] ?? '');
        $ivB64 = (string) ($payload['iv'] ?? '');
        if ($ivB64 === '') {
            $ivB64 = (string) ($payload['gcmNonce'] ?? '');
        }
        if ($encryptedB64 === '' || $ivB64 === '') {
            throw new RuntimeException('Missing P-384 encrypted payload fields.');
        }

        $encrypted = $this->decodeBase64($encryptedB64, 'encrypted payload');
        $iv = $this->decodeBase64($ivB64, 'IV', 12);
        $parts = $this->splitEncryptedPayload($encrypted);

        $aesKey = $this->deriveAesKey(
            $this->sharedSecretFromSenderPublicKey($senderPublicKey, $keyMaterial),
            $salt,
            self::ALGORITHM,
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
            throw new RuntimeException('Failed to decrypt payload with P-384.');
        }

        return $jsonPlaintext;
    }

    private function sharedSecretFromReceiverPublicKey(string $receiverPublicKey, OpenSSLAsymmetricKey $ephemeralPrivate): string
    {
        $publicPem = $this->publicKeyPemFromReceiver($receiverPublicKey);
        $public = openssl_pkey_get_public($publicPem);
        if ($public === false) {
            throw new RuntimeException('Failed to load P-384 public key.');
        }

        $sharedSecret = openssl_pkey_derive($public, $ephemeralPrivate, 32);
        if ($sharedSecret === false || $sharedSecret === '') {
            throw new RuntimeException('Failed to derive P-384 shared secret.');
        }

        return $sharedSecret;
    }

    /**
     * @param  array{private_key_pem: string, public_key_b64: string}|null  $keyMaterial
     *         Optional caller-supplied key material previously returned by
     *         {@see generateEphemeralKeyPair()}. The package never stores this;
     *         the caller is responsible for persistence.
     */
    private function sharedSecretFromSenderPublicKey(string $senderPublicKey, ?array $keyMaterial = null): string
    {
        $public = openssl_pkey_get_public($this->publicKeyPemFromReceiver($senderPublicKey));
        if ($public === false) {
            throw new RuntimeException('Failed to load P-384 sender public key.');
        }

        if ($keyMaterial !== null) {
            $privatePem = (string) ($keyMaterial['private_key_pem'] ?? '');
            if ($privatePem === '') {
                throw new RuntimeException('Supplied P-384 key material is missing private_key_pem.');
            }
            $privateKey = openssl_pkey_get_private($privatePem);
            if ($privateKey === false) {
                throw new RuntimeException('Failed to load supplied P-384 private key.');
            }
        } else {
            $privateKey = $this->privateKey();
        }

        $sharedSecret = openssl_pkey_derive($public, $privateKey, 32);
        if ($sharedSecret === false || $sharedSecret === '') {
            throw new RuntimeException('Failed to derive P-384 shared secret.');
        }

        return $sharedSecret;
    }

    private function privateKey(): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_get_private($this->privateKeyPem());
        if ($key === false) {
            throw new RuntimeException('Failed to load P-384 private key.');
        }

        return $key;
    }

    private function ephemeralPrivateKey(): OpenSSLAsymmetricKey
    {
        $configPath = $this->prepareOpenSsl();
        $resource = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'private_key_bits' => 384,
            'curve_name' => self::CURVE,
            ...($configPath ? ['config' => $configPath] : []),
        ]);

        if ($resource === false) {
            $suffix = $this->collectOpenSslErrors();
            throw new RuntimeException('Failed to generate P-384 ephemeral key pair.' . ($suffix !== '' ? ' ' . $suffix : ''));
        }

        return $resource;
    }

    private function privateKeyPem(): string
    {
        $path = $this->resolvePath((string) config('hybrid-crypto.paths.p384_private_key'));
        if (is_file($path)) {
            $pem = file_get_contents($path);
            if (is_string($pem) && trim($pem) !== '') {
                return $pem;
            }

            throw new RuntimeException('Stored P-384 private key is empty or unreadable.');
        }

        $configPath = $this->prepareOpenSsl();
        $resource = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'private_key_bits' => 384,
            'curve_name' => self::CURVE,
            ...($configPath ? ['config' => $configPath] : []),
        ]);

        if ($resource === false) {
            $suffix = $this->collectOpenSslErrors();
            throw new RuntimeException('Failed to generate P-384 key pair.' . ($suffix !== '' ? ' ' . $suffix : ''));
        }

        $pem = '';
        $exportOptions = $configPath ? ['config' => $configPath] : [];
        if (!openssl_pkey_export($resource, $pem, null, $exportOptions) || $pem === '') {
            $suffix = $this->collectOpenSslErrors();
            throw new RuntimeException('Failed to export P-384 private key.' . ($suffix !== '' ? ' ' . $suffix : ''));
        }

        $dir = dirname($path);
        if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new RuntimeException('Unable to create P-384 key directory.');
        }

        file_put_contents($path, $pem);
        chmod($path, 0600);

        return $pem;
    }

    private function publicKeyPemFromReceiver(string $publicKey): string
    {
        $trimmed = trim($publicKey);
        if ($trimmed === '') {
            throw new RuntimeException('Missing P-384 public key.');
        }

        if (str_starts_with($trimmed, '-----BEGIN')) {
            return $trimmed;
        }

        $decoded = base64_decode($trimmed, true);
        if ($decoded === false) {
            throw new RuntimeException('Invalid P-384 public key encoding.');
        }

        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($decoded), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    private function pemToDerBase64(string $pem): string
    {
        $clean = preg_replace('/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/', '', $pem);
        if (!is_string($clean) || $clean === '') {
            throw new RuntimeException('Failed to normalize P-384 public key.');
        }

        return $clean;
    }

    private function collectOpenSslErrors(): string
    {
        $errors = [];
        while ($error = openssl_error_string()) {
            $errors[] = $error;
        }

        return implode(' | ', $errors);
    }

    private function prepareOpenSsl(): ?string
    {
        $configPath = $this->resolveOpenSslConfigPath();
        $this->opensslConfigPath = $configPath;

        if ($configPath) {
            putenv('OPENSSL_CONF=' . $configPath);
            $modulesDir = $this->resolveOpenSslModulesPath($configPath);
            if ($modulesDir) {
                putenv('OPENSSL_MODULES=' . $modulesDir);
            }
        }

        return $configPath;
    }

    private function resolveOpenSslConfigPath(): ?string
    {
        $envPath = trim((string) env('OPENSSL_CONF', ''));
        if ($envPath !== '' && is_file($envPath)) {
            return $envPath;
        }

        $phpDir = dirname((string) PHP_BINARY);
        if ($phpDir !== '' && $phpDir !== DIRECTORY_SEPARATOR) {
            $candidate = $phpDir . DIRECTORY_SEPARATOR . 'extras' . DIRECTORY_SEPARATOR . 'ssl' . DIRECTORY_SEPARATOR . 'openssl.cnf';
            if (is_file($candidate)) {
                return $candidate;
            }
        }

        $path = storage_path('app/openssl.cnf');
        if (!is_file($path)) {
            $contents = <<<CONF
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect

[default_sect]
activate = 1
CONF;
            $dir = dirname($path);
            if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
                throw new RuntimeException('Unable to create OpenSSL config directory.');
            }

            file_put_contents($path, $contents);
        }

        return is_file($path) ? $path : null;
    }

    private function resolveOpenSslModulesPath(string $configPath): ?string
    {
        $envPath = trim((string) env('OPENSSL_MODULES', ''));
        if ($this->looksLikeOpenSslModulesDir($envPath)) {
            return $envPath;
        }

        $configDir = dirname($configPath);
        $candidates = array_filter([
            $configDir,
            dirname($configDir) . DIRECTORY_SEPARATOR . 'lib' . DIRECTORY_SEPARATOR . 'ossl-modules',
            dirname($configDir) . DIRECTORY_SEPARATOR . 'ossl-modules',
            dirname(dirname($configDir)) . DIRECTORY_SEPARATOR . 'lib' . DIRECTORY_SEPARATOR . 'ossl-modules',
            '/usr/lib/ssl/modules',
            '/usr/lib64/ossl-modules',
            '/usr/lib/x86_64-linux-gnu/ossl-modules',
        ]);

        foreach ($candidates as $candidate) {
            if ($this->looksLikeOpenSslModulesDir($candidate)) {
                return $candidate;
            }
        }

        return null;
    }

    private function looksLikeOpenSslModulesDir(string $path): bool
    {
        if ($path === '' || !is_dir($path)) {
            return false;
        }

        foreach (['legacy', 'default', 'fips'] as $provider) {
            foreach (['so', 'dll', 'dylib'] as $extension) {
                $candidate = $path . DIRECTORY_SEPARATOR . $provider . '.' . $extension;
                if (is_file($candidate)) {
                    return true;
                }
            }
        }

        return false;
    }
}
