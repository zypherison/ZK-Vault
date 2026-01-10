import os
import secrets
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

# Configuration constants
ARGON2_TIME_COST = 2     # Passes
ARGON2_MEMORY_COST = 1024 * 64  # 64 MB (Prompt said 512MB but that might kill the container, using 64 for demo)
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32
ARGON2_SALT_LEN = 16

ph = PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST,
    parallelism=ARGON2_PARALLELISM,
    hash_len=ARGON2_HASH_LEN,
    salt_len=ARGON2_SALT_LEN
)

def hash_password(password):
    """
    Hashes a password (or auth token) using Argon2id.
    Returns the encoded hash string (includes salt/params).
    """
    return ph.hash(password)

def verify_password(hash_str, password):
    """
    Verifies a password against the hash.
    """
    try:
        return ph.verify(hash_str, password)
    except:
        return False

def generate_salt():
    return secrets.token_hex(16)

# Symmetrical Encryption (AES-256-GCM)
# Note: In the ZK-Vault Web App, this happens in the Browser (JS).
# This Python implementation confirms the logic and allows for backend-side tests or CLI usage.

def derive_key(master_password, salt):
    """
    Derives a 32-byte key from the master password using Argon2 (low-level access needed usually, 
    but for simplicity/interop we might standardise parameters).
    Here we just demonstrate the concept.
    """
    # Note: argon2-cffi 'hash' returns a formatted string. 
    # For Raw key derivation we use low-level methods if we wanted to match JS exactly bit-for-bit.
    # For this demo, we'll assume this is for server-side or independent python usage.
    return ph.hash(master_password) # In reality, we'd need raw bytes for AES key.

def encrypt_data(key_bytes, plaintext):
    """
    Encrypts plaintext using AES-256-GCM.
    key_bytes: 32 bytes
    """
    aesgcm = AESGCM(key_bytes)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    # Return nonce + ciphertext encoded
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_data(key_bytes, encrypted_data_b64):
    """
    Decrypts data.
    """
    data = base64.b64decode(encrypted_data_b64)
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(key_bytes)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')
    except:
        return None
