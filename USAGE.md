# Laravel Hybrid Crypto Usage

## What this package does

This package encrypts and decrypts payloads manually at the controller or service layer.
It does not use Eloquent casts, model traits, or automatic model encryption.
Encryption always uses the peer's public key plus the local private key. The package never encrypts with its own public key.

## Algorithm rules

- `ANTI_QCP=true` uses `mlkem768` for both browser and mobile flows.
- `ANTI_QCP=false` uses `p256`, `p384`, or `ecdh`.
- `anti_qcp` is only a server-side crypto selector. It does not decide Play Integrity, App Attest, or any other verified-mode check, and browser or Dart callers should infer the algorithm from the public key instead of relying on this flag in the payload.
- The package detects the algorithm from the provided public key material.
- `gcmNonce` is included in every encrypted payload and is used during decryption.
- Salt is optional. Pass `null`, `''`, or `0` to skip salting.

---

## Direct File-Backed Usage

When using file-backed persistent keypairs configured in your `config/hybrid-crypto.php`:

### Encrypt

```php
use Vendor\HybridCrypto\Facades\HybridCrypto;

$receiverPublicKey = HybridCrypto::publicKey('p256'); // or 'p384' / 'ecdh'
$payload = HybridCrypto::encryptData($data, $salt, $receiverPublicKey);
```

### Decrypt

The decrypt step takes the encrypted payload, the salt, and the public key value that came with the payload.

```php
$decrypted = HybridCrypto::decryptData($payload, $salt, $payload['public_key']);
```

---

## Ephemeral Session-Backed Usage (Zero Disk Storage)

If you do not want the package to store your server's private keys on disk, you can generate ephemeral keys per session/request, store them yourself (e.g. in Laravel's encrypted session, Redis, database), and pass them during decryption.

### 1. Generate & Store Ephemeral Key Pair

Call `generateEphemeralKeyPair` on the server. The package generates the keys and returns them without saving them to disk.

```php
use Vendor\HybridCrypto\Facades\HybridCrypto;

// 1. Generate ephemeral P-256 pair
$keyMaterial = HybridCrypto::generateEphemeralKeyPair('p256'); 
// Returns:
// [
//     'algorithm' => 'p256',
//     'private_key_pem' => '-----BEGIN EC PRIVATE KEY...',
//     'public_key_b64' => 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...'
// ]

// 2. Store the key material in the encrypted session (or cache/DB)
session()->put('server_key_material', encrypt(json_encode($keyMaterial)));

// 3. Send the public key to the client (e.g., in a challenge)
return response()->json([
    'challenge' => $challenge,
    'server_public_key' => $keyMaterial['public_key_b64']
]);
```

### 2. Decrypt Using Stored Ephemeral Key Pair

When the client sends back an encrypted payload, retrieve your stored keys from the session and pass them using the `keyMaterial` parameter:

```php
// 1. Retrieve key material from session
$keyMaterial = json_decode(decrypt(session('server_key_material')), true);

// 2. Decrypt payload using the explicit key material
$decrypted = HybridCrypto::decryptData(
    payload: $payload,
    salt: $salt,
    publicKey: $payload['public_key'], // client's public key (e.g. ephemeral_public_key)
    asObject: false,
    keyMaterial: $keyMaterial
);
```

---

## Payload envelope

The encrypted response includes:

- `algorithm`
- `public_key`
- `ephemeral_public_key`
- `iv`
- `gcmNonce`
- `encrypted`

The package always JSON-encodes the payload before encryption.

## Controller usage (File-Backed)

Use the trait in a controller when you want short calls:

```php
use Vendor\HybridCrypto\Traits\InteractsWithHybridCrypto;

class DashboardController extends Controller
{
    use InteractsWithHybridCrypto;

    public function store(Request $request)
    {
        $publicKey = $this->hybridPublicKey('p256');
        $payload = $this->hybridEncrypt($request->all(), 'salt-value', $publicKey);

        return response()->json($payload);
    }
}
```

## Important notes

- The receiver public key is required for encryption.
- The public key value from the payload is required for decryption.
- For `mlkem768`, the payload's `public_key` field carries the encapsulated ciphertext that the receiver uses to decapsulate.
- `ANTI_QCP=true` rejects `p256`, `p384`, and `ecdh` keys.
- `ANTI_QCP=false` rejects `mlkem768` keys.
