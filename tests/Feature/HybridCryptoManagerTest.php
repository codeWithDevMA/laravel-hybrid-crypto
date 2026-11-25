<?php

namespace Tests\Feature;

use InvalidArgumentException;
use Vendor\HybridCrypto\HybridCryptoManager;
use Tests\TestCase;

class HybridCryptoManagerTest extends TestCase
{
    public function test_p256_round_trip(): void
    {
        config()->set('hybrid-crypto.anti_qcp', false);

        $crypto = app('hybrid-crypto');
        $receiverPublicKey = $crypto->publicKey(HybridCryptoManager::ALGORITHM_P256);
        $payload = $crypto->encryptData(['user_id' => 303, 'role' => 'gamma'], 'p256-salt', $receiverPublicKey);
        $decrypted = $crypto->decryptData($payload, 'p256-salt', (string) $payload['public_key']);

        $this->assertIsArray($decrypted);
        $this->assertSame(303, $decrypted['user_id']);
        $this->assertSame('gamma', $decrypted['role']);
        $this->assertSame(HybridCryptoManager::ALGORITHM_P256, $payload['algorithm']);
        $this->assertNotEmpty($payload['gcmNonce']);
        $this->assertNotEmpty($payload['ephemeral_public_key']);
    }

    public function test_secp256r1_alias_returns_p256_public_key(): void
    {
        config()->set('hybrid-crypto.anti_qcp', false);

        $crypto = app('hybrid-crypto');
        $receiverPublicKey = $crypto->publicKey('secp256r1');
        $payload = $crypto->encryptData(['curve' => 'secp256r1'], 0, $receiverPublicKey);
        $decrypted = $crypto->decryptData($payload, 0, (string) $payload['public_key']);

        $this->assertIsArray($decrypted);
        $this->assertSame('secp256r1', $decrypted['curve']);
        $this->assertSame(HybridCryptoManager::ALGORITHM_P256, $payload['algorithm']);
    }

    public function test_p384_round_trip(): void
    {
        config()->set('hybrid-crypto.anti_qcp', false);

        $crypto = app('hybrid-crypto');
        $receiverPublicKey = $crypto->publicKey(HybridCryptoManager::ALGORITHM_P384);
        $payload = $crypto->encryptData(['user_id' => 101, 'role' => 'alpha'], 'p384-salt', $receiverPublicKey);
        $decrypted = $crypto->decryptData($payload, 'p384-salt', (string) $payload['public_key']);

        $this->assertIsArray($decrypted);
        $this->assertSame(101, $decrypted['user_id']);
        $this->assertSame('alpha', $decrypted['role']);
        $this->assertSame(HybridCryptoManager::ALGORITHM_P384, $payload['algorithm']);
        $this->assertNotEmpty($payload['gcmNonce']);
        $this->assertNotEmpty($payload['ephemeral_public_key']);
    }

    public function test_ecdh_round_trip(): void
    {
        config()->set('hybrid-crypto.anti_qcp', false);

        $crypto = app('hybrid-crypto');
        $receiverPublicKey = $crypto->publicKey(HybridCryptoManager::ALGORITHM_ECDH);
        $payload = $crypto->encryptData(['user_id' => 202, 'role' => 'beta'], 'ecdh-salt', $receiverPublicKey);
        $decrypted = $crypto->decryptData($payload, 'ecdh-salt', (string) $payload['public_key']);

        $this->assertIsArray($decrypted);
        $this->assertSame(202, $decrypted['user_id']);
        $this->assertSame('beta', $decrypted['role']);
        $this->assertSame(HybridCryptoManager::ALGORITHM_ECDH, $payload['algorithm']);
        $this->assertNotEmpty($payload['gcmNonce']);
        $this->assertNotEmpty($payload['ephemeral_public_key']);
    }

    public function test_mlkem_round_trip_for_both_modes(): void
    {
        config()->set('hybrid-crypto.anti_qcp', true);

        $crypto = app('hybrid-crypto');
        $receiverPublicKey = $crypto->publicKey();

        $firstPayload = $crypto->encryptData(['mode' => 'first'], 'mlkem-first', $receiverPublicKey);
        $firstDecrypted = $crypto->decryptData($firstPayload, 'mlkem-first', (string) $firstPayload['public_key']);

        $secondPayload = $crypto->encryptData(['mode' => 'second'], 'mlkem-second', $receiverPublicKey);
        $secondDecrypted = $crypto->decryptData($secondPayload, 'mlkem-second', (string) $secondPayload['public_key']);

        $this->assertIsArray($firstDecrypted);
        $this->assertSame('first', $firstDecrypted['mode']);
        $this->assertIsArray($secondDecrypted);
        $this->assertSame('second', $secondDecrypted['mode']);
        $this->assertSame(HybridCryptoManager::ALGORITHM_MLKEM768, $firstPayload['algorithm']);
        $this->assertSame(HybridCryptoManager::ALGORITHM_MLKEM768, $secondPayload['algorithm']);
        $this->assertNotEmpty($firstPayload['gcmNonce']);
        $this->assertNotEmpty($secondPayload['gcmNonce']);
        $this->assertNotEmpty($firstPayload['ephemeral_public_key']);
        $this->assertNotEmpty($secondPayload['ephemeral_public_key']);
    }

    public function test_algorithm_is_required_when_anti_qcp_is_false(): void
    {
        config()->set('hybrid-crypto.anti_qcp', false);

        $this->expectException(InvalidArgumentException::class);

        app('hybrid-crypto')->publicKey();
    }

    public function test_encryption_works_without_salt(): void
    {
        config()->set('hybrid-crypto.anti_qcp', false);

        $crypto = app('hybrid-crypto');
        $receiverPublicKey = $crypto->publicKey(HybridCryptoManager::ALGORITHM_P384);
        $payload = $crypto->encryptData(['status' => 'ok'], 0, $receiverPublicKey);
        $decrypted = $crypto->decryptData($payload, null, (string) $payload['public_key']);

        $this->assertIsArray($decrypted);
        $this->assertSame('ok', $decrypted['status']);
    }
}
