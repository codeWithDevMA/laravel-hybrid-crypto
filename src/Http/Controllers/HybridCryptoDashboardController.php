<?php

namespace Vendor\HybridCrypto\Http\Controllers;

use Illuminate\Contracts\View\View;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;
use JsonException;
use Vendor\HybridCrypto\HybridCryptoManager;
use Vendor\HybridCrypto\Traits\InteractsWithHybridCrypto;

class HybridCryptoDashboardController
{
    use InteractsWithHybridCrypto;

    public function index(): View
    {
        return $this->renderDashboard();
    }

    public function build(Request $request): View
    {
        if (config('hybrid-crypto.anti_qcp', false)) {
            $validated = $request->validate([
                'salt' => ['nullable', 'string'],
            ]);

            $algorithm = null;
            $salt = $validated['salt'];
        } else {
            $validated = $request->validate([
                'algorithm' => ['required', 'string', Rule::in([
                    HybridCryptoManager::ALGORITHM_P256,
                    HybridCryptoManager::ALGORITHM_P384,
                    HybridCryptoManager::ALGORITHM_ECDH,
                ])],
                'salt' => ['nullable', 'string'],
            ]);

            $algorithm = $validated['algorithm'];
            $salt = $validated['salt'];
        }

        $receiverPublicKey = $this->hybridPublicKey($algorithm);
        $payload = $this->samplePayload($algorithm, $receiverPublicKey);

        return $this->renderDashboard(
            algorithm: $algorithm,
            salt: $salt,
            receiverPublicKey: $receiverPublicKey,
            encryptedPayload: $this->hybridEncrypt($payload, $salt, $receiverPublicKey),
        );
    }

    public function decrypt(Request $request): View
    {
        if (config('hybrid-crypto.anti_qcp', false)) {
            $validated = $request->validate([
                'salt' => ['nullable', 'string'],
                'encrypted_payload' => ['required', 'string'],
            ]);

            $algorithm = null;
            $salt = $validated['salt'];
        } else {
            $validated = $request->validate([
                'algorithm' => ['required', 'string', Rule::in([
                    HybridCryptoManager::ALGORITHM_P256,
                    HybridCryptoManager::ALGORITHM_P384,
                    HybridCryptoManager::ALGORITHM_ECDH,
                ])],
                'salt' => ['nullable', 'string'],
                'encrypted_payload' => ['required', 'string'],
            ]);

            $algorithm = $validated['algorithm'];
            $salt = $validated['salt'];
        }

        $encryptedPayload = $this->decodeEncryptedPayload($validated['encrypted_payload']);
        $senderPublicKey = $this->extractPublicKey($encryptedPayload);
        $decryptedPayload = $this->hybridDecrypt($encryptedPayload, $salt, $senderPublicKey, false);
        $reencryptedPayload = $this->hybridEncrypt($decryptedPayload, $salt, $this->hybridPublicKey($algorithm));

        return $this->renderDashboard(
            algorithm: $algorithm,
            salt: $salt,
            encryptedPayload: $reencryptedPayload,
            decryptedPayload: $decryptedPayload,
            previousEncryptedPayload: $encryptedPayload,
            payloadPublicKey: $senderPublicKey,
        );
    }

    /**
     * @param array<string, mixed>|null $encryptedPayload
     * @param array<string, mixed>|array<int, mixed>|object|string|null $decryptedPayload
     * @param array<string, mixed>|null $previousEncryptedPayload
     */
    private function renderDashboard(
        ?string $algorithm = null,
        ?string $salt = null,
        ?string $receiverPublicKey = null,
        ?string $payloadPublicKey = null,
        ?array $encryptedPayload = null,
        array|object|string|null $decryptedPayload = null,
        ?array $previousEncryptedPayload = null,
    ): View {
        $resolvedAlgorithm = $this->resolveDashboardAlgorithm($algorithm);
        $antiQcp = (bool) config('hybrid-crypto.anti_qcp', false);
        $publicKeyPayload = $resolvedAlgorithm === null
            ? null
            : $this->hybridPublicKeyPayload($resolvedAlgorithm);

        return view('hybrid-crypto::dashboard', [
            'algorithm' => $resolvedAlgorithm,
            'salt' => $salt,
            'receiverPublicKey' => $receiverPublicKey,
            'payloadPublicKey' => $payloadPublicKey,
            'publicKeyPayload' => $publicKeyPayload,
            'encryptedPayload' => $encryptedPayload,
            'encryptedPayloadToken' => $encryptedPayload === null ? null : $this->encodePayloadForForm($encryptedPayload),
            'decryptedPayload' => $decryptedPayload,
            'decryptedPayloadDisplay' => $decryptedPayload === null ? null : $this->formatPayload($decryptedPayload),
            'previousEncryptedPayload' => $previousEncryptedPayload,
            'previousEncryptedPayloadDisplay' => $previousEncryptedPayload === null ? null : $this->formatPayload($previousEncryptedPayload),
            'dashboardReady' => $encryptedPayload !== null,
            'antiQcp' => $antiQcp,
            'availableAlgorithms' => [
                HybridCryptoManager::ALGORITHM_P256,
                HybridCryptoManager::ALGORITHM_P384,
                HybridCryptoManager::ALGORITHM_ECDH,
            ],
        ]);
    }

    private function resolveDashboardAlgorithm(?string $algorithm): ?string
    {
        if (config('hybrid-crypto.anti_qcp', false)) {
            return HybridCryptoManager::ALGORITHM_MLKEM768;
        }

        if ($algorithm === null || trim($algorithm) === '') {
            return null;
        }

        return $this->hybridCrypto()->algorithm($algorithm);
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function encodePayloadForForm(array $payload): string
    {
        try {
            return base64_encode(
                json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
            );
        } catch (JsonException $e) {
            abort(422, 'Unable to prepare encrypted payload for transport.');
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function decodeEncryptedPayload(string $encodedPayload): array
    {
        $decoded = base64_decode($encodedPayload, true);
        if (! is_string($decoded) || $decoded === '') {
            abort(422, 'Encrypted payload is not valid base64.');
        }

        try {
            $payload = json_decode($decoded, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            abort(422, 'Encrypted payload JSON is invalid.');
        }

        if (! is_array($payload)) {
            abort(422, 'Encrypted payload must decode to an array.');
        }

        return $payload;
    }

    private function extractPublicKey(array $payload): string
    {
        $publicKey = trim((string) ($payload['public_key'] ?? ''));

        if ($publicKey === '') {
            abort(422, 'Encrypted payload must contain a public_key.');
        }

        return $publicKey;
    }

    /**
     * @param array<string, mixed>|array<int, mixed>|object|string $payload
     */
    private function formatPayload(array|object|string $payload): string
    {
        if (is_string($payload)) {
            return $payload;
        }

        $normalized = json_decode(
            json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            true,
            512,
            JSON_THROW_ON_ERROR
        );

        return json_encode(
            $normalized,
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR
        );
    }

    /**
     * @return array<string, string>
     */
    private function samplePayload(?string $algorithm, string $receiverPublicKey): array
    {
        return [
            'message' => 'This payload is encrypted before it reaches the control panel view.',
            'algorithm' => config('hybrid-crypto.anti_qcp', false) ? HybridCryptoManager::ALGORITHM_MLKEM768 : (string) $algorithm,
            'receiver_public_key' => $receiverPublicKey,
            'anti_qcp' => (bool) config('hybrid-crypto.anti_qcp', false),
            'issued_at' => now()->toIso8601String(),
        ];
    }
}
