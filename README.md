# Laravel Hybrid Crypto

A Laravel package for hybrid cryptography support (P-256, P-384, X25519, and ML-KEM-768) designed for easy integration with frontend and mobile SDKs (like Flutter).

## Installation

Install via Composer:

```bash
composer require ghazali/laravel-hybrid-crypto
```

Publish the configuration file:

```bash
php artisan vendor:publish --provider="Vendor\HybridCrypto\HybridCryptoServiceProvider"
```

## Features

- **Manual Controller/Service Layer Encryption:** Encrypt and decrypt payloads explicitly without Eloquent model magic.
- **Multiple Curves & Post-Quantum Support:** Supports P-256 (`prime256v1`), P-384 (`secp384r1`), X25519 (`ecdh`), and ML-KEM-768 (`mlkem768`).
- **Standardized AES-256-GCM Envelope:** Outputs `iv`, `gcmNonce`, `ephemeral_public_key`, `encrypted`, and `tag`.
- **Ephemeral Session Mode (Zero Disk Storage):** Generate challenge keypairs in memory and decrypt payloads on-the-fly without storing private keys on disk.

## Quick Start

### Encrypt Data

```php
use Vendor\HybridCrypto\Facades\HybridCrypto;

$receiverPublicKey = HybridCrypto::publicKey('p256'); // or 'ecdh' / 'mlkem768'
$payload = HybridCrypto::encryptData($data, $salt, $receiverPublicKey);
```

### Decrypt Data

```php
$decrypted = HybridCrypto::decryptData($payload, $salt, $payload['public_key']);
```

### Ephemeral Session Mode

```php
$keyMaterial = HybridCrypto::generateEphemeralKeyPair('p256');
// Store $keyMaterial in session/cache and send $keyMaterial['public_key_b64'] to the client
```

## Documentation

- Read [USAGE.md](./USAGE.md) for the integration guide, payload formats, and ephemeral session key management.
- For `anti_qcp=true`, the server selects ML-KEM-768 automatically. Otherwise, standard elliptic curve cryptography (ECC) algorithms are used and clients infer the exact algorithm from the public key.

## License

This package is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).
