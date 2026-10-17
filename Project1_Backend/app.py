import base64, hashlib, os, secrets, sqlite3, time
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from io import BytesIO

app = Flask(__name__)
CORS(app)
DB = os.path.join(os.path.dirname(__file__), 'cryptovault.db')


def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, public_key TEXT NOT NULL, token TEXT NOT NULL)')


def current_user():
    token = request.headers.get('Authorization', '').replace('Bearer ', '', 1)
    if not token:
        return None
    with db() as conn:
        return conn.execute('SELECT * FROM users WHERE token=?', (token,)).fetchone()


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            return jsonify({'error': 'Please log in first.'}), 401
        return fn(user, *args, **kwargs)
    return wrapped


def private_key_from_pem(pem):
    return load_pem_private_key(pem.encode(), password=None)


def public_key_from_pem(pem):
    return load_pem_public_key(pem.encode())


@app.get('/api/health')
def health():
    return jsonify({'status': 'ok', 'message': 'CryptoVault backend is running'})


@app.post('/api/register')
def register():
    data = request.get_json(force=True)
    username = str(data.get('username', '')).strip()
    password = str(data.get('password', ''))
    if len(username) < 3 or len(password) < 6:
        return jsonify({'error': 'Username must be at least 3 characters and password at least 6 characters.'}), 400
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    public_pem = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    token = secrets.token_urlsafe(32)
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    try:
        with db() as conn:
            conn.execute('INSERT INTO users(username,password_hash,public_key,token) VALUES(?,?,?,?)', (username, password_hash, public_pem, token))
    except sqlite3.IntegrityError:
        return jsonify({'error': 'That username is already registered.'}), 409
    return jsonify({'message': 'Registration successful. Save your private key securely; it is shown only now.', 'token': token, 'username': username, 'public_key': public_pem, 'private_key': private_pem})


@app.post('/api/login')
def login():
    data = request.get_json(force=True)
    username = str(data.get('username', '')).strip()
    password_hash = hashlib.sha256(str(data.get('password', '')).encode()).hexdigest()
    with db() as conn:
        user = conn.execute('SELECT * FROM users WHERE username=? AND password_hash=?', (username, password_hash)).fetchone()
        if not user:
            return jsonify({'error': 'Invalid username or password.'}), 401
        token = secrets.token_urlsafe(32)
        conn.execute('UPDATE users SET token=? WHERE id=?', (token, user['id']))
    return jsonify({'message': 'Login successful.', 'token': token, 'username': username, 'public_key': user['public_key']})


@app.post('/api/certificate')
@login_required
def certificate(user):
    data = request.get_json(force=True)
    try:
        private_key = private_key_from_pem(data['private_key'])
        public_key = private_key.public_key()
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, user['username'])])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(public_key)
                .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .sign(private_key=private_key, algorithm=hashes.SHA256()))
        pem = cert.public_bytes(serialization.Encoding.PEM)
        return send_file(BytesIO(pem), mimetype='application/x-pem-file', as_attachment=True, download_name=f'{user["username"]}_certificate.pem')
    except Exception as e:
        return jsonify({'error': f'Certificate creation failed: {e}'}), 400


@app.post('/api/rsa/encrypt')
def rsa_encrypt():
    data = request.get_json(force=True)
    try:
        pub = public_key_from_pem(data['public_key'])
        ciphertext = pub.encrypt(str(data['message']).encode(), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return jsonify({'ciphertext': base64.b64encode(ciphertext).decode()})
    except Exception as e:
        return jsonify({'error': f'Encryption failed: {e}'}), 400


@app.post('/api/rsa/decrypt')
def rsa_decrypt():
    data = request.get_json(force=True)
    try:
        private = private_key_from_pem(data['private_key'])
        ciphertext = base64.b64decode(data['ciphertext'])
        plaintext = private.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)).decode()
        return jsonify({'plaintext': plaintext})
    except Exception as e:
        return jsonify({'error': f'Decryption failed. Check the private key and ciphertext. Details: {e}'}), 400


@app.post('/api/rsa/sign')
def rsa_sign():
    data = request.get_json(force=True)
    try:
        private = private_key_from_pem(data['private_key'])
        signature = private.sign(str(data['message']).encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return jsonify({'signature': base64.b64encode(signature).decode()})
    except Exception as e:
        return jsonify({'error': f'Signing failed: {e}'}), 400


@app.post('/api/rsa/verify')
def rsa_verify():
    data = request.get_json(force=True)
    try:
        pub = public_key_from_pem(data['public_key'])
        pub.verify(base64.b64decode(data['signature']), str(data['message']).encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return jsonify({'valid': True, 'message': 'Signature is valid.'})
    except Exception:
        return jsonify({'valid': False, 'message': 'Signature is invalid or the message was changed.'})


@app.post('/api/diffie-hellman')
def diffie_hellman():
    # Small values are intentionally used so learners can follow the arithmetic. Not production parameters.
    data = request.get_json(silent=True) or {}
    p, g = 23, 5
    a = int(data.get('alice_private', 6)); b = int(data.get('bob_private', 15))
    if not (1 <= a < p and 1 <= b < p):
        return jsonify({'error': 'Private values must be between 1 and 22 for this demonstration.'}), 400
    A, B = pow(g, a, p), pow(g, b, p)
    return jsonify({'p': p, 'g': g, 'alice_private': a, 'bob_private': b, 'alice_public': A, 'bob_public': B, 'alice_shared': pow(B, a, p), 'bob_shared': pow(A, b, p), 'note': 'Toy values for learning only; do not use for real security.'})


def egcd(a, b):
    if b == 0: return (a, 1, 0)
    gcd, x1, y1 = egcd(b, a % b)
    return (gcd, y1, x1 - (a // b) * y1)


def inverse(a, m):
    gcd, x, _ = egcd(a, m)
    if gcd != 1: raise ValueError('No modular inverse exists')
    return x % m


@app.post('/api/elgamal/sign')
def elgamal_sign():
    data = request.get_json(force=True)
    message = str(data.get('message', ''))
    # Demonstration parameters: p=467, g=2. These are educational, not production-safe.
    p, g = 467, 2
    x = int(data.get('private_key', 127)) % (p - 2) + 1
    y = pow(g, x, p)
    h = int.from_bytes(hashlib.sha512(message.encode()).digest(), 'big') % (p - 1)
    while True:
        k = secrets.randbelow(p - 2) + 1
        if egcd(k, p - 1)[0] == 1: break
    r = pow(g, k, p)
    s = (inverse(k, p - 1) * (h - x * r)) % (p - 1)
    return jsonify({'hash': hashlib.sha512(message.encode()).hexdigest(), 'signature': {'r': r, 's': s}, 'public_key': {'p': p, 'g': g, 'y': y}, 'private_key_used': x, 'note': 'Educational toy parameters only; not for real security.'})


@app.post('/api/elgamal/verify')
def elgamal_verify():
    data = request.get_json(force=True)
    try:
        message = str(data['message']); p = int(data['p']); g = int(data['g']); y = int(data['y'])
        r = int(data['r']); s = int(data['s'])
        if not (0 < r < p and 0 <= s < p - 1): raise ValueError('Signature values out of range')
        h = int.from_bytes(hashlib.sha512(message.encode()).digest(), 'big') % (p - 1)
        valid = pow(g, h, p) == (pow(y, r, p) * pow(r, s, p)) % p
        return jsonify({'valid': valid, 'message': 'Signature is valid.' if valid else 'Signature is invalid or message was changed.', 'hash': hashlib.sha512(message.encode()).hexdigest()})
    except Exception as e:
        return jsonify({'error': f'Verification failed: {e}'}), 400


if __name__ == '__main__':
    init_db()
    print('CryptoVault API running at http://127.0.0.1:5000')
    app.run(debug=True, port=5000)
