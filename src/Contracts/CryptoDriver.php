<?php

namespace Vendor\HybridCrypto\Contracts;

interface CryptoDriver
{
    public function algorithm(): string;

    public function publicKey(): string;

    /**
     * Generate an ephemeral key pair for this algorithm.
     *
     * The package never stores this key pair. The caller is fully responsible
     * for persisting it wherever makes sense for their application
     * (e.g. Laravel's encrypted session, Redis, a database row, etc.).
     *
     * @return array{algorithm: string, private_key_b64: string, public_key_b64: string}
     */
    public function generateEphemeralKeyPair(): array;

    /**
     * @return array<string, string>
     */
    public function encrypt(string $jsonPlaintext, string|int|null $salt, string $receiverPublicKey): array;

    /**
     * Decrypt a payload.
     *
     * @param array<string, mixed> $payload
     * @param array{private_key_b64: string, public_key_b64: string}|null $keyMaterial
     *        Optional ephemeral key material previously returned by
     *        {@see generateEphemeralKeyPair()} and stored by the caller.
     *        When supplied, these keys are used instead of the driver's
     *        on-disk stored key pair. This allows callers to implement
     *        per-session ephemeral key exchanges without the package ever
     *        touching key storage.
     */
    public function decrypt(array $payload, string|int|null $salt, string $senderPublicKey, ?array $keyMaterial = null): string;
}
