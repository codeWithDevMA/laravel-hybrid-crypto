<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hybrid Crypto Dashboard</title>
    <style>
        :root {
            color-scheme: light;
            --bg: #0f172a;
            --panel: #111827;
            --panel-soft: #1f2937;
            --border: rgba(148, 163, 184, 0.25);
            --text: #e5e7eb;
            --muted: #94a3b8;
            --accent: #38bdf8;
            --accent-2: #22c55e;
            --danger: #fb7185;
            --code: #020617;
        }

        * { box-sizing: border-box; }
        body {
            margin: 0;
            min-height: 100vh;
            background: radial-gradient(circle at top, rgba(56, 189, 248, 0.18), transparent 30%),
                        radial-gradient(circle at right, rgba(34, 197, 94, 0.12), transparent 25%),
                        var(--bg);
            color: var(--text);
            font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            line-height: 1.5;
        }

        .shell {
            max-width: 1180px;
            margin: 0 auto;
            padding: 40px 20px 56px;
        }

        .hero {
            display: grid;
            gap: 18px;
            padding: 28px;
            background: linear-gradient(180deg, rgba(17, 24, 39, 0.96), rgba(15, 23, 42, 0.92));
            border: 1px solid var(--border);
            border-radius: 24px;
            box-shadow: 0 24px 80px rgba(2, 6, 23, 0.36);
        }

        h1, h2, h3, p { margin: 0; }
        h1 { font-size: clamp(2rem, 4vw, 3.5rem); letter-spacing: -0.04em; }
        h2 { font-size: 1.1rem; letter-spacing: 0.01em; }
        .muted { color: var(--muted); }

        .grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: 20px;
            margin-top: 22px;
        }

        @media (min-width: 980px) {
            .grid {
                grid-template-columns: 1.1fr 0.9fr;
            }
        }

        .card {
            background: rgba(15, 23, 42, 0.92);
            border: 1px solid var(--border);
            border-radius: 22px;
            padding: 22px;
        }

        .stack {
            display: grid;
            gap: 16px;
        }

        .row {
            display: grid;
            gap: 14px;
        }

        .pill {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            width: fit-content;
            padding: 8px 12px;
            border-radius: 999px;
            background: rgba(56, 189, 248, 0.12);
            color: #dbeafe;
            border: 1px solid rgba(56, 189, 248, 0.28);
            font-size: 0.9rem;
        }

        label {
            display: grid;
            gap: 8px;
            font-size: 0.92rem;
            color: #dbeafe;
        }

        input, select, textarea, button {
            font: inherit;
        }

        input, select, textarea {
            width: 100%;
            border: 1px solid rgba(148, 163, 184, 0.28);
            border-radius: 14px;
            background: rgba(2, 6, 23, 0.65);
            color: var(--text);
            padding: 14px 16px;
            outline: none;
        }

        textarea {
            min-height: 220px;
            resize: vertical;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
            font-size: 0.9rem;
        }

        input:focus, select:focus, textarea:focus {
            border-color: rgba(56, 189, 248, 0.7);
            box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.12);
        }

        button {
            border: 0;
            border-radius: 14px;
            padding: 14px 18px;
            background: linear-gradient(135deg, var(--accent), #60a5fa);
            color: white;
            font-weight: 700;
            cursor: pointer;
        }

        button.secondary {
            background: linear-gradient(135deg, var(--accent-2), #16a34a);
        }

        .badge {
            display: inline-flex;
            padding: 6px 10px;
            border-radius: 999px;
            border: 1px solid var(--border);
            color: #f8fafc;
            background: rgba(15, 23, 42, 0.9);
            font-size: 0.85rem;
            margin-right: 8px;
            margin-bottom: 8px;
        }

        .error {
            color: #fecaca;
            background: rgba(127, 29, 29, 0.35);
            border: 1px solid rgba(248, 113, 113, 0.35);
            border-radius: 14px;
            padding: 12px 14px;
        }

        .section {
            display: grid;
            gap: 12px;
        }

        pre {
            margin: 0;
            padding: 16px;
            border-radius: 16px;
            overflow: auto;
            background: var(--code);
            border: 1px solid rgba(148, 163, 184, 0.18);
            color: #e2e8f0;
            font-size: 0.88rem;
            line-height: 1.55;
        }
    </style>
</head>
<body>
<div class="shell">
    <section class="hero">
        <div class="pill">Vendor Hybrid Crypto Control Panel</div>
        <div class="stack">
            <h1>Controller-based hybrid encryption flow</h1>
            <p class="muted">
                The controller encrypts payloads before the view is rendered, and the panel decrypts them only when you press the button.
            </p>
        </div>
    </section>

    <div class="grid">
        <section class="card stack">
            <div class="section">
                <h2>1. Prepare payload</h2>
                <p class="muted">
                    anti_qcp only selects the crypto family. App integrity or verified-mode checks are handled outside this package.
                    When anti_qcp is true, ML-KEM is used automatically.
                    When anti_qcp is false, choose p256, p384, or ecdh.
                </p>
            </div>

            <form method="POST" action="{{ route('hybrid-crypto.dashboard.build') }}" class="stack">
                @csrf
                @if($antiQcp)
                    <div class="pill">algorithm: mlkem768</div>
                @else
                    <label>
                        <span>Algorithm</span>
                        <select name="algorithm" required>
                            <option value="" disabled @selected(old('algorithm', $algorithm) === null || old('algorithm', $algorithm) === '')>select algorithm</option>
                            <option value="p256" @selected(old('algorithm', $algorithm) === 'p256')>p256 / secp256r1</option>
                            <option value="p384" @selected(old('algorithm', $algorithm) === 'p384')>p384</option>
                            <option value="ecdh" @selected(old('algorithm', $algorithm) === 'ecdh')>ecdh</option>
                        </select>
                    </label>
                @endif

                <label>
                    <span>Salt</span>
                    <input type="text" name="salt" value="{{ old('salt', $salt ?? '') }}" autocomplete="off" placeholder="Optional. Leave empty or use 0 to skip salting.">
                </label>

                <button type="submit">Encrypt in Controller</button>
            </form>
        </section>

        <section class="card stack">
            <div class="section">
                <h2>2. Panel state</h2>
                <p class="muted">When encryption is built, the view receives only encrypted data and public-key metadata.</p>
            </div>

            <div>
                <span class="badge">anti_qcp: {{ $antiQcp ? 'true' : 'false' }}</span>
                @if($algorithm !== null)
                    <span class="badge">algorithm: {{ $algorithm }}</span>
                @endif
                @if(!empty($receiverPublicKey))
                    <span class="badge">receiver public key: present</span>
                @endif
                @if(!empty($payloadPublicKey))
                    <span class="badge">public key: present</span>
                @endif
            </div>

            @if($publicKeyPayload !== null)
                <div class="section">
                    <h3>Public key payload</h3>
                    <pre>{{ json_encode($publicKeyPayload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) }}</pre>
                </div>
            @endif

            @if($dashboardReady)
                <div class="section">
                    <h3>Encrypted payload</h3>
                    <pre>{{ json_encode($encryptedPayload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) }}</pre>
                </div>

                <form method="POST" action="{{ route('hybrid-crypto.dashboard.decrypt') }}" class="stack">
                    @csrf
                    <input type="hidden" name="salt" value="{{ $salt }}">
                    <input type="hidden" name="encrypted_payload" value="{{ $encryptedPayloadToken }}">
                    <button type="submit" class="secondary">Decrypt on Server</button>
                </form>
            @endif
        </section>
    </div>

    @if($decryptedPayload !== null)
        <section class="card stack" style="margin-top: 20px;">
            <div class="section">
                <h2>Decrypted payload</h2>
                <p class="muted">The payload was decrypted on the server and then immediately re-encrypted before rendering back to the panel.</p>
            </div>

            <div class="section">
                <h3>Decrypted data</h3>
                <pre>{{ $decryptedPayloadDisplay }}</pre>
            </div>

            @if($previousEncryptedPayloadDisplay !== null)
                <div class="section">
                    <h3>Encrypted payload before re-encryption</h3>
                    <pre>{{ $previousEncryptedPayloadDisplay }}</pre>
                </div>
            @endif

            @if($encryptedPayload !== null)
                <div class="section">
                    <h3>Re-encrypted payload</h3>
                    <pre>{{ json_encode($encryptedPayload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) }}</pre>
                </div>
            @endif
        </section>
    @endif
</div>
</body>
</html>
