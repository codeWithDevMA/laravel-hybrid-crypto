<?php

namespace Vendor\HybridCrypto\Drivers;

use RuntimeException;

abstract class AbstractHybridCryptoDriver
{
    protected function kdfHash(): string
    {
        return (string) config('hybrid-crypto.kdf.hash', 'sha256');
    }

    protected function kdfInfo(string $algorithm): string
    {
        $prefix = (string) config('hybrid-crypto.kdf.info', 'laravel-hybrid-crypto:v1');

        return $prefix . '|' . $algorithm;
    }

    protected function deriveAesKey(string $sharedSecret, string|int|null $salt, string $algorithm): string
    {
        return hash_hkdf(
            $this->kdfHash(),
            $sharedSecret,
            32,
            $this->kdfInfo($algorithm),
            $this->normalizeSalt($salt),
        );
    }

    protected function normalizeSalt(string|int|null $salt): string
    {
        if ($salt === null) {
            return '';
        }

        $normalized = trim((string) $salt);

        if ($normalized === '' || $normalized === '0') {
            return '';
        }

        return $normalized;
    }

    /**
     * @return array{iv: string, encrypted: string}
     */
    protected function encodeEncryptedPayload(string $iv, string $ciphertext, string $tag): array
    {
        return [
            'iv' => base64_encode($iv),
            'gcmNonce' => base64_encode($iv),
            'encrypted' => base64_encode($ciphertext . $tag),
        ];
    }

    /**
     * @return array{ciphertext: string, tag: string}
     */
    protected function splitEncryptedPayload(string $encrypted): array
    {
        if (strlen($encrypted) < 17) {
            throw new RuntimeException('Encrypted payload is too short.');
        }

        return [
            'ciphertext' => substr($encrypted, 0, -16),
            'tag' => substr($encrypted, -16),
        ];
    }

    protected function verifyTimestamp(array $payload, int $maxAgeSeconds = 300): void
    {
        $timestamp = $payload['timestamp'] ?? null;
        if ($timestamp === null || trim((string) $timestamp) === '') {
            return; // Allow omitted timestamp if not enforced, or check if present
        }

        $ts = (int) trim((string) $timestamp);
        if ($ts > 9999999999) {
            $ts = (int) floor($ts / 1000);
        }

        $now = time();
        $diff = abs($now - $ts);

        if ($diff > $maxAgeSeconds) {
            throw new RuntimeException('Payload timestamp expired or out of bounds (age: ' . $diff . 's).');
        }
    }

    protected function decodeBase64(string $value, string $label, ?int $expectedLength = null): string
    {
        $decoded = base64_decode($value, true);
        if ($decoded === false) {
            throw new RuntimeException('Invalid base64 for ' . $label . '.');
        }

        if ($expectedLength !== null && strlen($decoded) !== $expectedLength) {
            throw new RuntimeException('Invalid length for ' . $label . '.');
        }

        return $decoded;
    }

    protected function resolvePath(string $configuredPath): string
    {
        $path = trim($configuredPath);
        if ($path === '') {
            throw new RuntimeException('Missing storage path configuration.');
        }

        if ($this->isAbsolutePath($path)) {
            return $path;
        }

        return storage_path($path);
    }

    protected function isAbsolutePath(string $path): bool
    {
        return str_starts_with($path, DIRECTORY_SEPARATOR)
            || preg_match('/^[A-Za-z]:[\\\\\\/]/', $path) === 1;
    }

    /**
     * @return array<string, mixed>|null
     */
    protected function readJsonFile(string $path): ?array
    {
        if (!is_file($path)) {
            return null;
        }

        $json = file_get_contents($path);
        if (!is_string($json) || trim($json) === '') {
            return null;
        }

        $decoded = json_decode($json, true);
        return is_array($decoded) ? $decoded : null;
    }

    protected function writeJsonFile(string $path, array $data): void
    {
        $dir = dirname($path);
        if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new RuntimeException('Unable to create key directory.');
        }

        $encoded = json_encode($data, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT);
        file_put_contents($path, $encoded);
        chmod($path, 0600);
    }
}
