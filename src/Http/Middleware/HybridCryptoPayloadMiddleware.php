<?php

namespace Vendor\HybridCrypto\Http\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Vendor\HybridCrypto\HybridCryptoManager;

class HybridCryptoPayloadMiddleware
{
    public function handle(Request $request, Closure $next): Response
    {
        $salt = (string) $request->header('X-Hybrid-Crypto-Salt', '');
        $antiQcp = (bool) config('hybrid-crypto.anti_qcp', false);
        $publicKey = (string) $request->header('X-Hybrid-Crypto-Public-Key', '');
        $receiverPublicKey = (string) $request->header('X-Hybrid-Crypto-Receiver-Public-Key', '');

        if ($salt !== '' && $publicKey !== '' && ($request->has('encrypted') || $request->has('public_key') || $request->has('ephemeral_public_key'))) {
            $payload = $request->only([
                'algorithm',
                'encrypted',
                'ephemeral_public_key',
                'gcmNonce',
                'iv',
                'public_key',
            ]);

            $decrypted = app('hybrid-crypto')->decryptData($payload, $salt, $publicKey, false);

            if (is_array($decrypted)) {
                $request->merge($decrypted);
            }
        }

        $response = $next($request);

        if ($response instanceof JsonResponse && $request->header('X-Hybrid-Crypto-Encrypt-Response') === '1' && $salt !== '') {
            $content = json_decode($response->getContent(), true);
            if (is_array($content) && $receiverPublicKey !== '') {
                $encrypted = app('hybrid-crypto')->encryptData($content, $salt, $receiverPublicKey);
                $response->setData([
                    'hybrid_crypto' => $encrypted,
                ]);
            }
        }

        return $response;
    }
}
