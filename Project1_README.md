# CryptoVault — ALM Project 2, Project 1

A learning-focused full-stack demo of RSA encryption/signatures, Diffie–Hellman key exchange, ElGamal signatures with SHA-512, account registration, SQLite public-key storage, and X.509 certificate download.

## Requirements
- Python 3.10+
- Node.js 18+
- npm

## Start backend (Terminal 1)
```powershell
cd backend
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python app.py
```
On macOS/Linux, activate with `source .venv/bin/activate`.

## Start frontend (Terminal 2)
```powershell
cd frontend
npm install
npm run dev
```
Open the local URL printed by Vite (usually http://localhost:5173).

## Test in this order
1. Account & Certificate: register a username/password. Save the private key shown; it is not stored in the database. Try downloading the X.509 certificate.
2. RSA Toolkit: enter a short message; encrypt, decrypt, sign, then verify. Decryption/signing need the private key.
3. Diffie–Hellman: click Run Key Exchange and check both shared secrets match.
4. ElGamal & SHA-512: hash/sign, then verify. Change the message and verify again to see failure.

## Important limitations
This is an educational prototype, not production security. The ElGamal and Diffie–Hellman values are small demonstration parameters. Password hashing, token handling, key storage, and certificate issuance must be strengthened before real-world deployment. The certificate is self-signed, so browsers will not automatically trust it.
