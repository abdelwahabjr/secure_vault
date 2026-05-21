import os
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


# ── AES-256 Encryption ────────────────────────────────────────────────────────

def get_aes_key(raw_key: str) -> bytes:
    """Derive a 32-byte AES key from the config string."""
    return hashlib.sha256(raw_key.encode()).digest()


def encrypt_file(file_bytes: bytes, raw_key: str) -> tuple[bytes, str]:
    """Encrypt file bytes with AES-256-CBC. Returns (ciphertext, iv_hex)."""
    key = get_aes_key(raw_key)
    iv  = os.urandom(16)
    # Pad to block size
    pad_len = 16 - (len(file_bytes) % 16)
    padded  = file_bytes + bytes([pad_len] * pad_len)

    cipher     = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor  = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return ciphertext, iv.hex()


def decrypt_file(ciphertext: bytes, iv_hex: str, raw_key: str) -> bytes:
    """Decrypt AES-256-CBC ciphertext. Returns original file bytes."""
    key = get_aes_key(raw_key)
    iv  = bytes.fromhex(iv_hex)

    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded    = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    pad_len = padded[-1]
    return padded[:-pad_len]


# ── SHA-256 Hash ──────────────────────────────────────────────────────────────

def compute_sha256(file_bytes: bytes) -> str:
    """Return hex SHA-256 hash of file bytes."""
    return hashlib.sha256(file_bytes).hexdigest()


# ── RSA Key Management ────────────────────────────────────────────────────────

KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'instance', 'keys')


def _ensure_keys_dir():
    os.makedirs(KEYS_DIR, exist_ok=True)


def generate_rsa_keypair(user_id: int):
    """Generate and persist RSA key pair for a user."""
    _ensure_keys_dir()
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(os.path.join(KEYS_DIR, f'user_{user_id}_private.pem'), 'wb') as f:
        f.write(priv_pem)
    with open(os.path.join(KEYS_DIR, f'user_{user_id}_public.pem'), 'wb') as f:
        f.write(pub_pem)


def _load_private_key(user_id: int):
    path = os.path.join(KEYS_DIR, f'user_{user_id}_private.pem')
    if not os.path.exists(path):
        generate_rsa_keypair(user_id)
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())


def _load_public_key(user_id: int):
    path = os.path.join(KEYS_DIR, f'user_{user_id}_public.pem')
    if not os.path.exists(path):
        generate_rsa_keypair(user_id)
    with open(path, 'rb') as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())


# ── Digital Signature ─────────────────────────────────────────────────────────

def sign_hash(sha256_hex: str, user_id: int) -> str:
    """Sign SHA-256 hash with user's RSA private key. Returns base64 signature."""
    private_key = _load_private_key(user_id)
    signature   = private_key.sign(
        sha256_hex.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()


def verify_signature(sha256_hex: str, signature_b64: str, user_id: int) -> bool:
    """Verify RSA signature. Returns True if valid."""
    try:
        public_key = _load_public_key(user_id)
        signature  = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            sha256_hex.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
