// Sample file demonstrating Hybrid Cryptography and Modern Symmetric
// For CryptoScan testing

const crypto = require('crypto');
const oqs = require('liboqs-node');

// ============================================
// Hybrid Key Exchange (Best Practice for Transition)
// ============================================

async function hybridKeyExchange() {
    // Classical ECDH
    const ecdhAlice = crypto.createECDH('prime256v1');
    const ecdhPublicKeyAlice = ecdhAlice.generateKeys();

    // Post-Quantum ML-KEM-768
    const mlkem = new oqs.KeyEncapsulation('ML-KEM-768');
    const mlkemKeyPair = mlkem.generateKeypair();

    // Combined for hybrid security: X25519MLKEM768
    // Security holds if EITHER algorithm remains secure

    return {
        classical: ecdhPublicKeyAlice,
        pqc: mlkemKeyPair.publicKey
    };
}

// ============================================
// ChaCha20-Poly1305 (RFC 8439)
// ============================================

function encryptWithChaCha20Poly1305(plaintext, key) {
    // ChaCha20-Poly1305 - IETF standard AEAD
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('chacha20-poly1305', key, nonce, {
        authTagLength: 16
    });

    const ciphertext = Buffer.concat([
        cipher.update(plaintext),
        cipher.final()
    ]);

    return {
        nonce,
        ciphertext,
        tag: cipher.getAuthTag()
    };
}

// ============================================
// AES-256-GCM (NIST SP 800-38D)
// ============================================

function encryptWithAESGCM(plaintext, key) {
    // AES-256-GCM - NIST approved AEAD
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    const ciphertext = Buffer.concat([
        cipher.update(plaintext),
        cipher.final()
    ]);

    return {
        iv,
        ciphertext,
        tag: cipher.getAuthTag()
    };
}

// ============================================
// TLS 1.3 with Hybrid Key Exchange
// ============================================

const tls = require('tls');

const tlsOptions = {
    minVersion: 'TLSv1.3',
    maxVersion: 'TLSv1.3',
    // Hybrid key exchange groups (when available)
    // X25519MLKEM768 combines X25519 + ML-KEM-768
    ecdhCurve: 'X25519'  // Until X25519MLKEM768 is widely supported
};

// ============================================
// Composite Signatures (Draft Standard)
// ============================================

async function hybridSign(message) {
    // MLDSA65-ECDSA-P256 composite signature
    // Both signatures must verify for the composite to be valid

    const classicalSig = crypto.createSign('SHA256')
        .update(message)
        .sign(ecdsaPrivateKey);

    const pqcSig = oqs.Signature('ML-DSA-65');
    pqcSig.generateKeypair();
    const mldsaSig = pqcSig.sign(message);

    return {
        ecdsa: classicalSig,
        mldsa: mldsaSig,
        type: 'MLDSA65-ECDSA-P256'
    };
}

module.exports = {
    hybridKeyExchange,
    encryptWithChaCha20Poly1305,
    encryptWithAESGCM,
    hybridSign
};
