# Sample file demonstrating Post-Quantum Cryptography algorithms
# For CryptoScan testing

# ============================================
# ML-KEM (FIPS 203) - Key Encapsulation
# ============================================
from liboqs import oqs

# ML-KEM-768 key encapsulation (NIST Level 3)
kem = oqs.KeyEncapsulation("ML-KEM-768")
public_key = kem.generate_keypair()
ciphertext, shared_secret = kem.encap_secret(public_key)

# Also test Kyber naming
kyber_kem = oqs.KeyEncapsulation("Kyber768")

# ============================================
# ML-DSA (FIPS 204) - Digital Signatures
# ============================================

# ML-DSA-65 signature (NIST Level 3)
sig = oqs.Signature("ML-DSA-65")
signer_public_key = sig.generate_keypair()
message = b"Hello, quantum-safe world!"
signature = sig.sign(message)

# Also test Dilithium naming
dilithium_sig = oqs.Signature("Dilithium3")

# ============================================
# SLH-DSA (FIPS 205) - Hash-based Signatures
# ============================================

# SLH-DSA-128f signature (fast variant)
slh_sig = oqs.Signature("SLH-DSA-128f")

# SPHINCS+ naming
sphincs_sig = oqs.Signature("SPHINCS+-SHA2-128f")

# ============================================
# Hybrid Cryptography (Best Practice)
# ============================================

# X25519 + ML-KEM-768 hybrid key exchange
from circl.kem.mlkem import mlkem768
from cryptography.hazmat.primitives.asymmetric import x25519

# Classical key exchange
x25519_private = x25519.X25519PrivateKey.generate()
x25519_public = x25519_private.public_key()

# PQC key encapsulation
mlkem_public, mlkem_private = mlkem768.GenerateKeyPair()

# Hybrid shared secret = HKDF(x25519_shared || mlkem_shared)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ============================================
# LMS/XMSS (SP 800-208) - Stateful Signatures
# ============================================

# XMSS signature (requires state management)
xmss_sig = oqs.Signature("XMSS-SHA2_10_256")

# LMS signature
lms_keypair = generate_lms_keypair()
lms_signature = lms_sign(message, lms_keypair)

print("Post-quantum cryptography sample complete")
