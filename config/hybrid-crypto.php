<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Crypto Family Selector
    |--------------------------------------------------------------------------
    | This flag only selects the cryptographic family used by the package.
    | Integrity or "verified" app modes stay in the host application layer.
    */
    'anti_qcp' => (bool) env('ANTI_QCP', false),

    'paths' => [
        'p384_private_key' => env('HYBRID_CRYPTO_P384_PRIVATE_KEY', 'app/private/hybrid-crypto/p384_private.pem'),
        'p256_private_key' => env('HYBRID_CRYPTO_P256_PRIVATE_KEY', 'app/web_login_ecdh_private.pem'),
        'ecdh_keypair' => env('HYBRID_CRYPTO_ECDH_KEYPAIR', 'app/private/hybrid-crypto/ecdh_keypair.json'),
        'mlkem768_keypair' => env('HYBRID_CRYPTO_MLKEM768_KEYPAIR', 'app/private/hybrid-crypto/mlkem768_keypair.json'),
    ],

    'kdf' => [
        'hash' => 'sha256',
        'info' => env('HYBRID_CRYPTO_KDF_INFO', 'laravel-hybrid-crypto:v1'),
    ],
];
