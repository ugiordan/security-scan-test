#!/usr/bin/env python3
"""Example Python code with intentional FIPS violations and security issues."""

import hashlib
import md5  # FIPS violation: MD5 is not FIPS-compliant

# Hardcoded secret for testing Gitleaks/TruffleHog
API_KEY = "sk-1234567890abcdef1234567890abcdef"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def hash_password(password: str) -> str:
    """Hash password using MD5 (FIPS violation)."""
    # FIPS violation: MD5 is not approved for cryptographic use
    return hashlib.md5(password.encode()).hexdigest()

def encrypt_data(data: str, key: str) -> bytes:
    """Encrypt data using DES (FIPS violation)."""
    from Crypto.Cipher import DES  # FIPS violation: DES is deprecated
    cipher = DES.new(key.encode()[:8], DES.MODE_ECB)
    return cipher.encrypt(data.encode().ljust(8))

def use_weak_random():
    """Use weak random number generator."""
    import random  # Security issue: Not cryptographically secure
    return random.randint(1, 1000000)

if __name__ == "__main__":
    # Test with hardcoded credentials
    password = "admin123"
    hashed = hash_password(password)
    print(f"Hashed password: {hashed}")

    # Use hardcoded API key
    print(f"Using API key: {API_KEY}")
