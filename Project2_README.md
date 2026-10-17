# SecureTunnel — TLS / SSH / IPsec Visualizer

A full-stack educational demo built with React + Vite and Python FastAPI.

## Requirements
- Python 3.10+ (Python 3.11 recommended)
- Node.js 18+ and npm
- Visual Studio Code

## Run in VS Code

### 1. Open the project
Extract the ZIP file, then open the `securetunnel` folder in VS Code.

### 2. Start the Python backend
Open a VS Code terminal (`Terminal` → `New Terminal`) and run:

**Windows PowerShell**
```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```
If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that terminal, then activate again. Alternatively, use Command Prompt and run `.venv\Scripts\activate.bat`.

**macOS / Linux**
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

Keep this terminal running. API docs are at http://127.0.0.1:8000/docs.

### 3. Start the React frontend
Open a **second** VS Code terminal (leave the backend running), then run:

```bash
cd frontend
npm install
npm run dev
```

Open the local URL printed by Vite, usually http://127.0.0.1:5173.

### 4. Try it
- TLS / SSL: click **Start simulation**, then **Next step** through all five steps.
- SSH: select the SSH tab, start, and advance the five stages.
- IPsec / ESP: switch between Transport mode and Tunnel mode.
- After TLS or SSH completes, type a sample message and click **Encrypt & send** to see AES-GCM encryption/decryption.

## API endpoints
- `POST /api/tls/start`
- `POST /api/tls/next`
- `POST /api/tls/message`
- `POST /api/ssh/start`
- `POST /api/ssh/next`
- `POST /api/ssh/message`
- `GET /api/ipsec/transport`
- `GET /api/ipsec/tunnel`
- `GET /docs` (interactive API documentation)

## Important learning notes
This is a **simulation**, not a production TLS/SSH/IPsec implementation. The TLS module deliberately demonstrates RSA-encrypted pre-master secret transport because it is in the project brief; this is a simplified legacy-style teaching model, not modern TLS 1.3. The generated RSA public key is not a CA-signed certificate and certificate trust is not actually validated. The SSH module uses Diffie–Hellman to demonstrate a shared secret, but it does not implement the SSH wire protocol, host-key trust checks, or real account authentication. Session state is in memory and resets when the backend restarts. Do not expose this demo server to the public internet or use it to protect real data.
