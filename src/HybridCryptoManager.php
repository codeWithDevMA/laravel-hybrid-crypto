<?php

namespace Vendor\HybridCrypto;

use InvalidArgumentException;
use JsonException;
use ParagonIE\PQCrypto\Compat;
use Vendor\HybridCrypto\Contracts\CryptoDriver;
use Vendor\HybridCrypto\Drivers\MlKem768Driver;
use Vendor\HybridCrypto\Drivers\P256Driver;
use Vendor\HybridCrypto\Drivers\P384Driver;
use Vendor\HybridCrypto\Drivers\X25519Driver;

class HybridCryptoManager
{
    public const ALGORITHM_P256 = 'p256';
    public const ALGORITHM_P384 = 'p384';
    public const ALGORITHM_ECDH = 'ecdh';
    public const ALGORITHM_MLKEM768 = 'mlkem768';

    public function __construct(private readonly array $config = [])
    {
    }

    public function algorithm(?string $algorithm = null): string
    {
        if ($this->antiQcp()) {
            return self::ALGORITHM_MLKEM768;
        }

        if ($algorithm === null || trim($algorithm) === '') {
            throw new InvalidArgumentException('Algorithm is required when anti_qcp is false.');
        }

        $normalized = $this->normalizeAlgorithm($algorithm);
        if ($normalized === self::ALGORITHM_MLKEM768) {
            throw new InvalidArgumentException('ML-KEM-768 is only available when anti_qcp is true.');
        }

        return $normalized;
    }

    public function publicKey(?string $algorithm = null): string
    {
        return $this->driverForAlgorithm($this->algorithm($algorithm))->publicKey();
    }

    public function publicKeyPayload(?string $algorithm = null): array
    {
        $resolvedAlgorithm = $this->algorithm($algorithm);

        return [
            'success' => true,
            'algorithm' => $resolvedAlgorithm,
            'public_key' => $this->publicKey($resolvedAlgorithm),
        ];
    }

    /**
     * Generate an ephemeral key pair for the given algorithm.
     *
     * The package never stores this key pair. The caller is fully responsible
     * for persisting it wherever makes sense for their application
     * (e.g. Laravel's encrypted session, Redis, a database row, etc.).
     *
     * Example — store in an encrypted Laravel session:
     *   $keyMaterial = HybridCrypto::generateEphemeralKeyPair('p256');
     *   session()->put('server_key', encrypt(json_encode($keyMaterial)));
     *
     * Example — retrieve and use for decryption:
     *   $keyMaterial = json_decode(decrypt(session('server_key')), true);
     *   $decrypted   = HybridCrypto::decryptData($envelope, $sessionId, $senderKey, keyMaterial: $keyMaterial);
     *
     * @param  string  $algorithm  e.g. 'p256', 'ecdh', 'mlkem768'
     * @return array{algorithm: string, private_key_b64?: string, private_key_pem?: string, public_key_b64: string}
     */
    public function generateEphemeralKeyPair(string $algorithm): array
    {
        return $this->driverForAlgorithm($this->algorithm($algorithm))->generateEphemeralKeyPair();
    }

    /**
     * @param mixed $data
     */
    public function encryptData(mixed $data, string|int|null $salt, string $receiverPublicKey): array
    {
        $resolvedAlgorithm = $this->resolveAlgorithmFromPublicKey($receiverPublicKey);
        $jsonPlaintext = $this->jsonPlaintextFromData($data);
        $payload = $this->driverForAlgorithm($resolvedAlgorithm)->encrypt($jsonPlaintext, $salt, $receiverPublicKey);

        return $payload;
    }

    /**
     * @param  array<string, mixed>                                           $payload
     * @param  array{private_key_b64?: string, private_key_pem?: string, public_key_b64: string}|null  $keyMaterial
     *         Optional ephemeral key material previously returned by
     *         {@see generateEphemeralKeyPair()} and stored by the caller.
     *         When supplied, these keys are used instead of the driver's
     *         on-disk stored key pair — so the package never touches storage.
     * @return array<string, mixed>|object|string
     */
    public function decryptData(array $payload, string|int|null $salt, string $publicKey, bool $asObject = false, ?array $keyMaterial = null): array|object|string
    {
        $resolvedAlgorithm = $this->resolveAlgorithmFromPublicKey($publicKey);
        $payloadAlgorithm = strtolower(trim((string) ($payload['algorithm'] ?? '')));

        if ($payloadAlgorithm !== '' && $payloadAlgorithm !== $resolvedAlgorithm) {
            throw new InvalidArgumentException('Payload algorithm does not match the provided public key.');
        }

        $jsonPlaintext = $this->driverForAlgorithm($resolvedAlgorithm)->decrypt($payload, $salt, $publicKey, $keyMaterial);

        return $this->decodeJsonPlaintext($jsonPlaintext, $asObject);
    }

    private function antiQcp(): bool
    {
        return (bool) config('hybrid-crypto.anti_qcp', $this->config['anti_qcp'] ?? false);
    }

    private function normalizeAlgorithm(string $algorithm): string
    {
        $normalized = strtolower(trim($algorithm));

        return match ($normalized) {
            'secp256r1', 'prime256v1', 'p-256' => self::ALGORITHM_P256,
            self::ALGORITHM_P256,
            self::ALGORITHM_P384,
            self::ALGORITHM_ECDH,
            self::ALGORITHM_MLKEM768 => $normalized,
            default => throw new InvalidArgumentException('Unsupported crypto algorithm: ' . $algorithm),
        };
    }

    private function driverForAlgorithm(string $algorithm): CryptoDriver
    {
        return match ($algorithm) {
            self::ALGORITHM_P256 => new P256Driver(),
            self::ALGORITHM_P384 => new P384Driver(),
            self::ALGORITHM_ECDH => new X25519Driver(),
            self::ALGORITHM_MLKEM768 => new MlKem768Driver(),
            default => throw new InvalidArgumentException('Unsupported crypto algorithm: ' . $algorithm),
        };
    }

    private function resolveAlgorithmFromPublicKey(string $publicKey): string
    {
        $normalized = trim($publicKey);
        if ($normalized === '') {
            throw new InvalidArgumentException('Public key is required.');
        }

        $decoded = $this->decodePublicKey($normalized);
        $length = strlen($decoded);

        if (
            $length === Compat::MLKEM768_ENCAPSKEY_BYTES
            || $length === Compat::MLKEM768_CIPHERTEXT_BYTES
        ) {
            if (! $this->antiQcp()) {
                throw new InvalidArgumentException('anti_qcp=false does not accept ML-KEM-768 public keys.');
            }

            return self::ALGORITHM_MLKEM768;
        }

        if (str_contains($decoded, hex2bin('06032b656e'))) {
            if ($this->antiQcp()) {
                throw new InvalidArgumentException('anti_qcp=true only accepts ML-KEM-768 public keys.');
            }

            return self::ALGORITHM_ECDH;
        }

        if (str_contains($decoded, hex2bin('06082a8648ce3d030107'))) {
            if ($this->antiQcp()) {
                throw new InvalidArgumentException('anti_qcp=true only accepts ML-KEM-768 public keys.');
            }

            return self::ALGORITHM_P256;
        }

        if (str_contains($decoded, hex2bin('06052b81040022'))) {
            if ($this->antiQcp()) {
                throw new InvalidArgumentException('anti_qcp=true only accepts ML-KEM-768 public keys.');
            }

            return self::ALGORITHM_P384;
        }

        if ($length === 32) {
            if ($this->antiQcp()) {
                throw new InvalidArgumentException('anti_qcp=true only accepts ML-KEM-768 public keys.');
            }

            return self::ALGORITHM_ECDH;
        }

        if ($length === 65 && $decoded[0] === "\x04") {
            if ($this->antiQcp()) {
                throw new InvalidArgumentException('anti_qcp=true only accepts ML-KEM-768 public keys.');
            }

            return self::ALGORITHM_P256;
        }

        if ($length === 97 && $decoded[0] === "\x04") {
            if ($this->antiQcp()) {
                throw new InvalidArgumentException('anti_qcp=true only accepts ML-KEM-768 public keys.');
            }

            return self::ALGORITHM_P384;
        }

        throw new InvalidArgumentException('Unable to identify public key algorithm.');
    }

    private function decodePublicKey(string $publicKey): string
    {
        $trimmed = trim($publicKey);

        if (str_starts_with($trimmed, '-----BEGIN')) {
            $base64 = preg_replace('/\-+BEGIN.*\-+|\-+END.*\-+|\s+/', '', $trimmed);
            if (! is_string($base64) || $base64 === '') {
                throw new InvalidArgumentException('Invalid PEM public key.');
            }

            $decoded = base64_decode($base64, true);
            if ($decoded === false) {
                throw new InvalidArgumentException('Invalid PEM public key encoding.');
            }

            return $decoded;
        }

        $decoded = base64_decode($trimmed, true);
        if ($decoded !== false) {
            return $decoded;
        }

        return $trimmed;
    }

    private function jsonPlaintextFromData(mixed $data): string
    {
        try {
            return json_encode(
                $data,
                JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
            );
        } catch (JsonException $e) {
            throw new InvalidArgumentException('Unable to encode payload as JSON: ' . $e->getMessage(), 0, $e);
        }
    }

    private function decodeJsonPlaintext(string $jsonPlaintext, bool $asObject): array|object|string
    {
        try {
            return json_decode($jsonPlaintext, ! $asObject, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new InvalidArgumentException('Unable to decode decrypted payload: ' . $e->getMessage(), 0, $e);
        }
    }
}
