# Laravel Hybrid Crypto

A Laravel package for hybrid cryptography support (P-256, P-384, X25519, and ML-KEM-768) designed for easy integration with frontend and mobile SDKs (like Flutter).

## Installation

Add the local path repository to your host application's `composer.json` or install it via composer:

```json
"repositories": [
    {
        "type": "path",
        "url": "../laravel-hybrid-crypto",
        "options": {
            "symlink": true
        }
    }
]
```

Then run:

```bash
composer require vendor/laravel-hybrid-crypto
```

## Features

- **No automatic model mapping:** Encrypt and decrypt payloads manually at the controller or service layer.
- **Multiple Curves/Algorithms:** Supports P-256 (`prime256v1`), P-384 (`secp384r1`), X25519 (`ecdh`), and ML-KEM-768 (`mlkem768`).
- **Standardized output format:** Outputs standard `iv`, `ephemeral_public_key`, `encrypted`, and `tag` values in a GCM-encrypted envelope.
- **Ephemeral Session Mode (Zero Storage):** Generate challenge keypairs in memory and decrypt payloads on-the-fly without storing private keys on disk.

## Documentation

- Read [USAGE.md](./USAGE.md) for the integration guide, payload formats, and ephemeral session key management.
- For `anti_qcp=true`, the server selects ML-KEM-768 automatically. Otherwise, standard elliptic curve cryptography (ECC) algorithms are used and clients infer the exact algorithm from the public key.

## License

This package is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).
