# Security review — RH Wallet Relayer

Audit date: 2026-08-14. Scope: `public/index.html`, `public/app.js`, `vercel.json`.

## What's solid

- **Client-side only.** No backend; keys never leave the device. `to`/`value` are derived locally from keys, so even a
  hostile RPC server cannot redirect funds — it only relays your signed transaction.
- **Strict CSP** (`script-src 'self'`, no `unsafe-eval`, `img-src 'none'`). No external/remote script can load.
- **Vault at rest:** PBKDF2 + AES-256-GCM via WebCrypto, random salt + IV per save, keys cleared from memory on
  `beforeunload` and on idle.
- **Vendored + integrity-pinned ethers** — no runtime supply-chain CDN dependency.

## Fixed (2026-08-14)

### 1. "WIPE SAVED" now really wipes — HIGH
`wipe()` previously only cleared in-memory keys. It now calls `deepWipe()` which removes the encrypted
`localStorage` vault (`setVault(null)`), clears the fail counter, drops the passphrase, and shows a destructive-action
confirm. The overlay "Reset (clear saved)" uses the same path.

### 2. 4 wrong attempts → full wipe (was 5) + stronger KDF — MEDIUM-HIGH
- Fail threshold is now `MAX_FAILS = 4`. On the 4th wrong password the vault is **wiped for real** (memory + saved
  blob), not just locked.
- PBKDF2 iterations raised from **100k to 600k** (OWASP-aligned). New vault blobs tag their iteration count (`n`);
  old blobs without the tag decrypt at the historical 100k so nothing breaks.
- Password floor stays at 4 chars (explicit user decision).

### 3. Auto re-lock — MEDIUM
Keys are now cleared from memory after an idle timeout. Default **30 minutes**, configurable under
**Settings → Security → Auto re-lock after (minutes)** (`0` disables). The idle timer resets on any user activity and
re-arms after every unlock. On expiry the app returns to the unlock overlay and keys are wiped from memory.

### 4. Untrusted RPC error text no longer injected as HTML — MEDIUM
`netStatus` error output switched from `innerHTML` to `textContent`, so an attacker-controlled string from a
user-supplied RPC endpoint cannot break out of the page structure (defense in depth on top of CSP).

### 5. Confirmation before irreversible sends — LOW
`runRelay` now shows a pre-flight `confirm()` (direction + pair count + warning that real signed txs will be sent).

### 6. Confirmation before full export — LOW
All three export buttons (CSV / XLSX / clipboard) now confirm before dumping every private key in plaintext.

## Residual notes
- Generated keys still sit plaintext in the generator table and clipboard for the duration of a session — inherent to
  "copy your key now" UX; auto re-lock and export confirmations reduce the window.
- `connect-src https: wss:` is intentionally permissive (user-supplied RPCs) — acceptable because `script-src` blocks
  execution and RPC cannot read keys or redirect locally-signed funds.