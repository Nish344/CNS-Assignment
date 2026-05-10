# Encrypted Medical Records Vault 🏥

A zero-knowledge, end-to-end encrypted web application designed for securely sharing medical records. This project demonstrates advanced cryptographic concepts including **Hybrid Cryptography**, **Proxy Re-encryption**, and **Client-Side Key Management** to ensure that the central server *never* sees the plaintext medical data or the decryption keys.

## 🚀 Key Features

- **Zero-Knowledge Server:** The backend (Flask + SQLite) acts only as a dumb storage vault. It stores base64-encoded ciphertexts and encrypted session keys.
- **Client-Side Encryption:** All cryptographic operations happen exclusively in the browser using the native `window.crypto.subtle` API.
- **Hybrid Cryptography:**
  - Files are encrypted using symmetric **AES-256-GCM** for high performance and authenticated encryption (MAC tag).
  - AES session keys are encrypted ("wrapped") using asymmetric **RSA-2048-OAEP**.
- **Digital Signatures:** Encrypted payloads are signed by the patient using **RSA-PSS (SHA-256)**, allowing the doctor to verify authenticity and detect tampering.
- **Proxy Re-encryption Pattern:** When a doctor requests access, the patient downloads their encrypted AES key, decrypts it locally, and re-encrypts it with the doctor's public key. The server facilitates the key exchange without ever possessing the plaintext key.
- **Role-Based Access Control:** Separate flows for `Patient` and `Doctor` roles.

## 🛠️ Technology Stack

- **Frontend:** React, Vite, Vanilla CSS (Glassmorphism UI)
- **Frontend Crypto:** Web Crypto API (`window.crypto.subtle`)
- **Backend:** Python, Flask, Flask-CORS
- **Database:** SQLite3

## ⚙️ Installation & Setup

### 1. Backend Setup
Create a virtual environment and install the Python dependencies:
```bash
python3 -m venv venv
source venv/bin/activate
pip install Flask flask-cors
```

### 2. Frontend Setup
Navigate to the frontend directory and install the Node modules:
```bash
cd frontend
npm install
```

## 🏃‍♂️ Running the Application

You must run both the backend and the frontend simultaneously. Open two separate terminal windows.

**Terminal 1 (Backend):**
```bash
source venv/bin/activate
python3 app.py
```
*The Flask API will start on `http://127.0.0.1:5000`.*

**Terminal 2 (Frontend):**
```bash
cd frontend
npm run dev -- --host
```
*Vite will start the dev server and automatically generate a local SSL certificate so the Web Crypto API functions properly.*

## 🎬 How to Present the Demo

This application is designed to be demonstrated locally using two devices on the same Wi-Fi network.

1. **Start the servers** using the commands above. The frontend terminal will give you a **Network URL** (e.g., `https://192.168.x.x:5173`).
2. **Device 1 (Doctor):** On your host machine, open your browser to `https://localhost:5173`. Select the **Doctor** role and register.
3. **Device 2 (Patient):** Have a friend connect to your Wi-Fi, open their phone/laptop browser, and navigate to the Network URL (`https://192.168.x.x:5173`). Have them select the **Patient** role and register. *(Note: Accept the "Connection is not private" warning, as this uses a local self-signed certificate for the demo).*
4. **The Flow:**
   - **Upload:** The patient selects a dummy medical record and clicks upload. The browser encrypts it and sends ciphertext to the vault.
   - **Request:** The doctor refreshes their global records list, sees the new encrypted file, and clicks "Request Access".
   - **Approve:** The patient checks pending requests and clicks "Approve". Their browser securely re-encrypts the AES key for the doctor.
   - **Download:** The doctor clicks "Download". Their browser fetches the encrypted file and their specific encrypted AES key, decrypts everything locally, verifies the patient's signature, and triggers a file download of the plaintext record.

## 🔒 Security Notes
*For the purpose of a seamless local demo, RSA private keys are temporarily stored in `sessionStorage`. In a production web application, private keys should be managed via hardware tokens, WebAuthn, or secure enclaves to prevent XSS exfiltration.*
