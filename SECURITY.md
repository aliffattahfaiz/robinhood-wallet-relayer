# Security review — RH Wallet Relayer

Audit date: 2026-08-14. Scope: `public/index.html`, `public/app.js`, `vercel.json`.

## What's solid

- **Client-side only.** No backend; keys never leave the device. `to`/`value` are derived locally from keys, so even a
  hostile RPC server cannot redirect funds — it only relays your signed transaction.
- **Strict CSP** (`script-src 'self'`, no `unsafe-eval`, `img-src 'none'`). No external/remote script can load, which
  kills the most common wallet-drain attack (injected keylogger / exfil).
- **Vault at rest:** PBKDF2 + AES-256-GCM via WebCrypto, random salt + IV per save, 5-fail self-wipe, keys cleared
  from JS memory on `beforeunload`.
- **Vendored + integrity-pinned ethers** — no runtime supply-chain CDN dependency.

## Open findings (unfixed as of this audit)

### 1. HIGH — "WIPE SAVED" does not wipe the saved vault
`app.js` `wipe()` clears in-memory keys only; it never calls `setVault(null)`. The label implies the encrypted
localStorage vault is removed, but it persists and is restored on next unlock. Only the overlay "Reset (clear saved)"
actually deletes it. **Fix:** have `wipe()` also `setVault(null)` + `clearFails()`.

### 2. MEDIUM-HIGH — Weak KDF + weak password floor
- PBKDF2 at **100k iterations** (below OWASP's current 600k recommendation). Whoever obtains the localStorage blob
  (malware, backup, browser sync) can brute-force offline.
- Minimum password is **4 characters** — trivial for a crypto keystore.
**Fix:** raise iterations to ≥600k and enforce a ≥10-char password.

### 3. MEDIUM — No auto re-lock
Only `beforeunload` clears keys from memory. A tab left unlocked keeps the passphrase alive indefinitely, and
"Export to clipboard" exposes every key with zero re-auth. **Fix:** idle-based re-lock (e.g. 5 min).

### 4. MEDIUM — Untrusted RPC error text injected via `innerHTML`
`netStatus.innerHTML` renders attacker-controlled strings from the user-configurable RPC endpoint. CSP currently
blocks script execution from it, but it should use `textContent`. Same pattern at the wallet status renders — those are
local-only (low risk), but RPC-derived error strings must not be interpolated as HTML.

### 5. LOW — No confirmation before irreversible sends
Run Relay fires N signed txs in one click. A wrong direction/amount is unrecoverable. **Fix:** pre-run summary
(from → to → amount) + confirm.

### 6. LOW — Keys linger in DOM + clipboard
Generated keys sit plaintext in the table (screenshot/shoulder-surf risk); "Copy CSV"/"Export CSV"/"XLSX" put all keys
on the clipboard, readable by any other app. Consider masking until needed and warning on export.

## Non-issues
- `connect-src https: wss:` is intentionally permissive (user-supplied RPCs) — acceptable because `script-src` blocks
  execution.
- RPC cannot redirect funds (local signing), cannot read keys (they never leave the browser).