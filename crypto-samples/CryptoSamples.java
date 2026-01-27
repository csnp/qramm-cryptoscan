// Copyright 2025 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cryptosamples;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

/**
 * Sample cryptographic code for testing the scanner (Java).
 * Run: cryptoscan scan ./crypto-samples to see detection results.
 */
public class CryptoSamples {

    // ========================================================================
    // QUANTUM VULNERABLE - Asymmetric Cryptography
    // ========================================================================

    /**
     * Generate RSA key pair - QUANTUM VULNERABLE
     * Remediation: Migrate to ML-KEM (FIPS 203)
     */
    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    /**
     * Generate weak RSA-1024 key - CRITICAL (classically weak)
     */
    public static KeyPair generateWeakRSAKey() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024); // Too small!
        return keyGen.generateKeyPair();
    }

    /**
     * Generate ECDSA key - QUANTUM VULNERABLE
     * Remediation: Migrate to ML-DSA (FIPS 204)
     */
    public static KeyPair generateECDSAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        return keyGen.generateKeyPair();
    }

    /**
     * Sign with ECDSA - QUANTUM VULNERABLE
     */
    public static byte[] signWithECDSA(PrivateKey privateKey, byte[] data) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    // ========================================================================
    // QUANTUM PARTIAL - Symmetric Cryptography
    // ========================================================================

    /**
     * Encrypt with AES-256-GCM - QUANTUM PARTIAL (acceptable)
     */
    public static byte[] encryptAES256GCM(byte[] key, byte[] plaintext) throws Exception {
        SecretKey secretKey = new javax.crypto.spec.SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
        return cipher.doFinal(plaintext);
    }

    /**
     * Encrypt with AES-128 - needs upgrade to AES-256
     */
    public static SecretKey generateAES128Key() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // Should be 256
        return keyGen.generateKey();
    }

    // ========================================================================
    // BROKEN/WEAK - Should be replaced immediately
    // ========================================================================

    /**
     * Hash with MD5 - BROKEN (collision attacks exist)
     */
    public static byte[] hashMD5(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }

    /**
     * Hash with SHA-1 - WEAK (collision attacks demonstrated)
     */
    public static byte[] hashSHA1(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(data);
    }

    /**
     * Encrypt with DES - BROKEN (56-bit key)
     */
    public static byte[] encryptDES(byte[] key, byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        // DES is completely broken
        return cipher.doFinal(plaintext);
    }

    /**
     * Encrypt with 3DES - WEAK (deprecated)
     */
    public static byte[] encrypt3DES(byte[] key, byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        return cipher.doFinal(plaintext);
    }

    // ========================================================================
    // QUANTUM SAFE - Hash functions
    // ========================================================================

    /**
     * Hash with SHA-256 - QUANTUM SAFE
     */
    public static byte[] hashSHA256(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }

    /**
     * Hash with SHA-512 - QUANTUM SAFE
     */
    public static byte[] hashSHA512(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        return md.digest(data);
    }

    // ========================================================================
    // PATTERNS THAT SHOULD BE FILTERED
    // ========================================================================

    /**
     * Logs crypto info - should be filtered (print statements)
     */
    public static void logCryptoInfo() {
        System.out.println("Using RSA-2048 for key exchange");
        System.out.println("Signing with ECDSA P-256");
    }

    /**
     * Validates input - should be filtered (error messages)
     */
    public static void validateKeyType(String keyType) {
        if (keyType == null) {
            throw new IllegalArgumentException("keyType must be a valid RSA or ECDSA key");
        }
    }
}
