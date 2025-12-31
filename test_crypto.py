# Test script for crypto module


import sys
from pathlib import Path

# Add client directory to path
sys.path.insert(0, str(Path(__file__).parent / "client"))

from crypto import (
    generate_session_key,
    encrypt_session_key_with_rsa,
    decrypt_session_key_with_rsa,
    encrypt_message,
    decrypt_message,
    encrypt_message_simple,
    decrypt_message_simple
)
from key_manager import KeyManager


def test_crypto():
    print("=" * 50)
    print("Testing Crypto Module")
    print("=" * 50)

    # Setup: Create key manager for RSA keys
    print("\n1. Setting up RSA keys...")
    km = KeyManager(keys_dir="test_crypto_keys")
    km.get_or_create_keys()

    # Test 1: Session key generation
    print("\n2. Testing session key generation...")
    session_key = generate_session_key()
    print(f"   Session key length: {len(session_key)} bytes (should be 32)")
    print(f"   Session key (hex): {session_key.hex()[:32]}...")

    # Test 2: RSA encryption/decryption of session key
    print("\n3. Testing RSA encryption/decryption of session key...")
    encrypted_key = encrypt_session_key_with_rsa(km.public_key, session_key)
    print(f"   Encrypted key length: {len(encrypted_key)} bytes")
    decrypted_key = decrypt_session_key_with_rsa(km.private_key, encrypted_key)
    print(f"   Keys match: {session_key == decrypted_key} (should be True)")

    # Test 3: AES-GCM message encryption/decryption
    print("\n4. Testing AES-GCM message encryption...")
    test_message = "Hello, this is a secret message!"
    nonce, ciphertext, auth_tag = encrypt_message(session_key, test_message)
    print(f"   Nonce length: {len(nonce)} bytes (should be 12)")
    print(f"   Ciphertext length: {len(ciphertext)} bytes")
    print(f"   Auth tag length: {len(auth_tag)} bytes (should be 16)")

    # Test 4: AES-GCM message decryption
    print("\n5. Testing AES-GCM message decryption...")
    decrypted_message = decrypt_message(session_key, nonce, ciphertext, auth_tag)
    print(f"   Original: {test_message}")
    print(f"   Decrypted: {decrypted_message.decode('utf-8')}")
    print(f"   Match: {test_message == decrypted_message.decode('utf-8')} (should be True)")

    # Test 5: Tamper detection (modify auth tag)
    print("\n6. Testing tamper detection...")
    tampered_tag = bytes([b ^ 1 for b in auth_tag])  # Flip one bit
    try:
        decrypt_message(session_key, nonce, ciphertext, tampered_tag)
        print("   ERROR: Tampered message was accepted!")
    except ValueError as e:
        print(f"   ✓ Tamper detected correctly: {str(e)[:50]}...")

    # Test 6: Simple encryption/decryption functions
    print("\n7. Testing simple encryption functions...")
    test_msg2 = "Another test message with emoji 🚀"
    encrypted_data = encrypt_message_simple(session_key, test_msg2)
    print(f"   Encrypted data keys: {list(encrypted_data.keys())}")
    decrypted_msg2 = decrypt_message_simple(session_key, encrypted_data)
    print(f"   Match: {test_msg2 == decrypted_msg2.decode('utf-8')} (should be True)")

    # Test 7: Multiple messages (each with unique nonce)
    print("\n8. Testing multiple messages (unique nonces)...")
    messages = ["Message 1", "Message 2", "Message 3"]
    nonces = []
    for msg in messages:
        nonce, _, _ = encrypt_message(session_key, msg)
        nonces.append(nonce)
    print(f"   Generated {len(nonces)} nonces")
    print(f"   All nonces unique: {len(set(nonces)) == len(nonces)} (should be True)")

    print("\n" + "=" * 50)
    print("All tests completed!")
    print("=" * 50)


if __name__ == "__main__":
    test_crypto()

