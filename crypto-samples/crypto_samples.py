# Copyright 2025 Cyber Security Non-Profit (CSNP)
# SPDX-License-Identifier: Apache-2.0

"""
Sample cryptographic code for testing the scanner (Python).
Run: cryptoscan scan ./crypto-samples to see detection results.

This file demonstrates various cryptographic patterns in Python.
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import os


# ============================================================================
# QUANTUM VULNERABLE - Asymmetric Cryptography
# ============================================================================

def generate_rsa_key(key_size: int = 2048):
    """Generate RSA key pair - QUANTUM VULNERABLE"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    return private_key


def generate_weak_rsa_key():
    """Generate weak RSA-1024 key - CRITICAL (classically weak)"""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,  # Too small!
        backend=default_backend()
    )


def generate_ecdsa_key():
    """Generate ECDSA key - QUANTUM VULNERABLE"""
    return ec.generate_private_key(ec.SECP256R1(), default_backend())


def generate_ed25519_key():
    """Generate Ed25519 key - QUANTUM VULNERABLE"""
    return ed25519.Ed25519PrivateKey.generate()


def sign_with_ed25519(private_key, message: bytes) -> bytes:
    """Sign with Ed25519 - QUANTUM VULNERABLE"""
    return private_key.sign(message)


# ============================================================================
# QUANTUM PARTIAL - Symmetric Cryptography
# ============================================================================

def encrypt_aes_256_gcm(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt with AES-256-GCM - QUANTUM PARTIAL (acceptable)"""
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext + encryptor.tag


def encrypt_aes_128(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt with AES-128 - needs upgrade to AES-256"""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key[:16]), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(plaintext) + encryptor.finalize()


# ============================================================================
# BROKEN/WEAK - Should be replaced immediately
# ============================================================================

def hash_md5(data: bytes) -> bytes:
    """Hash with MD5 - BROKEN (collision attacks exist)"""
    return hashlib.md5(data).digest()


def hash_sha1(data: bytes) -> bytes:
    """Hash with SHA-1 - WEAK (collision attacks demonstrated)"""
    return hashlib.sha1(data).digest()


def encrypt_des(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt with DES - BROKEN (56-bit key)"""
    iv = os.urandom(8)
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(plaintext) + encryptor.finalize()


# ============================================================================
# QUANTUM SAFE - Hash functions
# ============================================================================

def hash_sha256(data: bytes) -> bytes:
    """Hash with SHA-256 - QUANTUM SAFE"""
    return hashlib.sha256(data).digest()


def hash_sha512(data: bytes) -> bytes:
    """Hash with SHA-512 - QUANTUM SAFE"""
    return hashlib.sha512(data).digest()


# ============================================================================
# PATTERNS THAT SHOULD BE FILTERED
# ============================================================================

def log_crypto_info():
    """Logs crypto info - should be filtered (print statements)"""
    print("Using Ed25519 for authentication")
    print("Encrypting with AES-256-GCM")


def get_crypto_metadata() -> dict:
    """Returns metadata - should be filtered (string labels)"""
    return {
        "algorithm": "ed25519",
        "key_type": "asymmetric",
        "auth_method": "ecdsa",
    }


def validate_key(key_type: str) -> None:
    """Validates key - should be filtered (error messages)"""
    if not key_type:
        raise ValueError("key_type must be a valid Ed25519 or RSA identifier")
