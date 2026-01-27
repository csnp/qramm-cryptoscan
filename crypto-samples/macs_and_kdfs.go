//go:build ignore
// +build ignore

// Sample file demonstrating MACs and KDFs
// For CryptoScan testing

package samples

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

// ============================================
// HMAC Examples (NIST Approved)
// ============================================

func ExampleHMACSHA256() []byte {
	key := []byte("secret-key")
	message := []byte("message to authenticate")

	// HMAC-SHA256 - NIST approved
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func ExampleHMACSHA512() []byte {
	key := []byte("secret-key")
	message := []byte("message to authenticate")

	// HMAC-SHA512 - NIST approved
	mac := hmac.New(sha512.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func ExampleHMACSHA3() []byte {
	key := []byte("secret-key")
	message := []byte("message to authenticate")

	// HMAC-SHA3-256 - NIST approved
	mac := hmac.New(sha3.New256, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// ============================================
// KMAC Example (SP 800-185 - Quantum Safe)
// ============================================

func ExampleKMAC256() []byte {
	key := []byte("secret-key")
	message := []byte("message to authenticate")
	customization := []byte("My Application")

	// KMAC-256 - quantum-safe MAC
	output := make([]byte, 32)
	kmac := sha3.NewKMAC256(key, customization)
	kmac.Write(message)
	kmac.Read(output)
	return output
}

// ============================================
// KDF Examples
// ============================================

func ExampleHKDF() []byte {
	// HKDF - SP 800-56C - for high-entropy secrets
	secret := []byte("high-entropy-secret")
	salt := []byte("optional-salt")
	info := []byte("context-info")

	hkdfReader := hkdf.New(sha256.New, secret, salt, info)
	derivedKey := make([]byte, 32)
	hkdfReader.Read(derivedKey)
	return derivedKey
}

func ExamplePBKDF2() []byte {
	// PBKDF2 - SP 800-132 - for passwords
	password := []byte("user-password")
	salt := []byte("random-salt-16bytes!")
	iterations := 600000 // OWASP 2024 recommendation

	return pbkdf2.Key(password, salt, iterations, 32, sha256.New)
}

func ExampleArgon2id() []byte {
	// Argon2id - RFC 9106 - recommended for password hashing
	password := []byte("user-password")
	salt := []byte("random-salt-16by")

	// Parameters: time=3, memory=64MB, parallelism=4
	return argon2.IDKey(password, salt, 3, 64*1024, 4, 32)
}

func ExampleBcrypt() ([]byte, error) {
	// bcrypt - industry standard password hashing
	password := []byte("user-password")
	cost := 12 // Recommended minimum

	return bcrypt.GenerateFromPassword(password, cost)
}

// ============================================
// Modern Hash Functions
// ============================================

func ExampleSHA3() []byte {
	// SHA3-256 - FIPS 202
	data := []byte("data to hash")
	hash := sha3.Sum256(data)
	return hash[:]
}

func ExampleSHAKE256() []byte {
	// SHAKE256 - FIPS 202 XOF - quantum-safe
	data := []byte("data to hash")
	output := make([]byte, 64) // Variable length output

	shake := sha3.NewShake256()
	shake.Write(data)
	shake.Read(output)
	return output
}

// Note: BLAKE2 and BLAKE3 are not NIST-approved but widely used
// import "golang.org/x/crypto/blake2b"
// hash := blake2b.Sum256(data)
