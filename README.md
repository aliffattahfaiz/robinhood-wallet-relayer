# RH Wallet Relayer

A client-side **Robinhood Chain** (any EVM) wallet utility that runs entirely in the browser and deploys to Vercel as a
static site. Three tabs:

1. **Wallet Generator** — mint fresh random wallets, copy the address + private key, export CSV, or push them straight
   into the relayer tiers.
2. **Wallet Relayer** — the tiers and pairing: **main → buffer → hot**, or back up again. Every buffer is paired 1:1
   with a hot wallet and forwards the exact amount it received. Also **Export** — CSV file, XLSX file, or clipboard —
   dumps every wallet in a paired layout: each row holds **one buffer + its hot wallet side by side** (same row =
   same pair index), plus the main wallet on its own row.
3. **Settings** — network (chain / chain ID / RPC) and relay config (direction, amount + delay randomization).

> **Unofficial / community tool.** Not affiliated with, endorsed by, or operated by Robinhood. "Robinhood Chain" is the
> public EVM L2; this is an independent utility that talks to it over standard JSON-RPC.

## The three tiers

| Tier | How many | Role |
|------|----------|------|
| **Main** | exactly 1 | Source of funds (deposit) / sink (sweep). One private key only. |
| **Buffer** | as many as you like | Middle relay tier. `buffer[i]` forwards to `hot[i]`. |
| **Hot** | as many as you like | Endpoint wallets that hold / spend the money. |

Pairs are index-matched: `buffer[0] ↔ hot[0]`, `buffer[1] ↔ hot[1]`, … The amount forwarded is 1:1 — buffer forwards
the same amount it received (minus gas).

## Directions

- **Deposit (main → buffer → hot):** main sends a randomized amount to `buffer[i]`, then `buffer[i]` forwards the same
  amount to `hot[i]`.
- **Sweep (hot → buffer → main):** `hot[i]` sends to `buffer[i]`, then `buffer[i]` forwards to main.

Every hop picks a **random amount** (within your min/max) and waits a **random delay** (within your min/max), so
transactions never land at the same instant.

## Security model

- **Client-side only.** Static page, all logic runs in the browser. Keys never hit a server.
- **Encrypted at rest.** Main / buffer / hot private keys are encrypted with your password (PBKDF2 + AES-256-GCM via
  WebCrypto) and stored only in `localStorage` on your own device. Reload the page and unlock with your password to
  restore them.
- **5-fail self-wipe.** 5 wrong password attempts wipe the saved vault.
- **No runtime CDN.** ethers v6.13.4 is vendored and self-hosted. The CSP blocks all external scripts.
- **RPC from your IP.** Requests go direct from your browser to the RPC you configure — no shared server key.

## Run locally

```
npm run dev          # python3 -m http.server 8080 --directory public
# open http://localhost:8080
```

## Deploy to Vercel

Static, zero-build. `vercel.json` sets `outputDirectory: public` and hardens headers (CSP, nosniff, no-referrer,
X-Frame-Options DENY).

```
vercel            # preview
vercel --prod     # production
```

> This hosts a tool where users manage private keys. Treat the URL as sensitive — the app is safe by construction
> (client-side, no exfiltration path), but don't share a key-input URL casually.

## Files

- `public/index.html` — UI + inline CSS.
- `public/app.js` — all logic (vault, generator, tiers, pairing, relay scheduling, RPC).
- `public/vendor/ethers.umd.min.js` — pinned ethers v6.13.4.
- `vercel.json`, `package.json` — deploy config.
