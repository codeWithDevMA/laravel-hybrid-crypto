<?php

namespace Vendor\HybridCrypto\Traits;

use Vendor\HybridCrypto\HybridCryptoManager;

trait InteractsWithHybridCrypto
{
    protected function hybridCrypto(): HybridCryptoManager
    {
        return app('hybrid-crypto');
    }

    protected function hybridPublicKey(?string $algorithm = null): string
    {
        return $this->hybridCrypto()->publicKey($algorithm);
    }

    protected function hybridPublicKeyPayload(?string $algorithm = null): array
    {
        return $this->hybridCrypto()->publicKeyPayload($algorithm);
    }

    protected function hybridEncrypt(mixed $data, string|int|null $salt, string $receiverPublicKey): array
    {
        return $this->hybridCrypto()->encryptData($data, $salt, $receiverPublicKey);
    }

    protected function hybridDecrypt(array $payload, string|int|null $salt, string $publicKey, bool $asObject = false): array|object|string
    {
        return $this->hybridCrypto()->decryptData($payload, $salt, $publicKey, $asObject);
    }
}
