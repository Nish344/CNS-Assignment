# Encrypted Medical Records Vault

Zero-knowledge, end-to-end encrypted demo for securely sharing medical records. The Flask server acts as blind storage only: it never sees plaintext records or plaintext AES keys. Cryptography runs in the browser via the **Web Crypto API**.

For a presenter-friendly walkthrough (architecture, crypto, demo script), see **[PRESENTATION.md](PRESENTATION.md)**.

## Features

- **Vault UI (`/`):** Patient upload (encrypt + sign + upload ciphertext); doctor request access + download after approval; client-side decrypt and signature verify.
- **Live status (`/status`):** Read-only dashboard fed by `GET /api/vault_status` — ciphertext fingerprints, approximate storage footprint, wrapped-key holders, access-request counts. No plaintext exposed.
- **Hybrid crypto:** **AES-256-GCM** for file data; **RSA-2048-OAEP** for wrapping the AES key; **RSA-PSS (SHA-256)** for patient signatures.
- **Proxy re-encryption flow:** Patient re-wraps the AES key for the doctor in the browser; server only stores the new wrapped blob.

## Stack

| Layer | Tech |
|--------|------|
| Frontend | React, Vite, React Router, CSS |
| Crypto | `window.crypto.subtle` |
| Backend | Python, Flask, Flask-CORS |
| Data | SQLite (`vault.db`) |

## Prerequisites

- **Python 3** with `venv`
- **Node.js** and npm (for the Vite app)

## Setup

### Backend

From the repository root:

```bash
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install Flask flask-cors
```

### Frontend

```bash
cd frontend
npm install
```

## Run (two terminals)

**Terminal 1 — API**

```bash
source venv/bin/activate
python3 app.py
```

Serving at **http://127.0.0.1:5000**.

**Terminal 2 — UI**

```bash
cd frontend
npm run dev -- --host
```

Open the HTTPS URL Vite prints (often **https://localhost:5173**). Accept the self-signed certificate — it is required for Web Crypto over a secure origin.

| Route | Purpose |
|--------|---------|
| `/` | Login, patient/doctor vault |
| `/status` | Live vault metadata visualization |

`/api/*` requests from the dev server are **proxied** to Flask (see `frontend/vite.config.js`), so keep both processes running.

## Two-device demo (same network)

1. Start backend and frontend; note the **Network** URL from Vite (e.g. `https://192.168.x.x:5173`).
2. **Doctor:** `https://localhost:5173` — register as Doctor.
3. **Patient:** Network URL on a second device — register as Patient (trust the certificate warning for the demo).
4. Patient uploads a file → doctor sees ciphertext metadata only → **Request Access** → patient **Approve** → doctor **Download** (decrypt + verify signature in-browser).

Optional: leave **`/status`** open on the presenter screen while the demo runs.

## Security note (demo only)

Private keys live in **`sessionStorage`** for convenience. Production systems should use hardware-backed keys, WebAuthn, or other designs that mitigate XSS and device theft — not browser session storage alone.
