"""
Test script for message protocol
"""

import sys
from pathlib import Path

# Add shared directory to path
sys.path.insert(0, str(Path(__file__).parent / "shared"))

from protocol import (
    PUBLIC_KEY,
    SESSION_KEY,
    MESSAGE,
    DISCONNECT,
    serialize_message,
    deserialize_message,
    create_public_key_message,
    create_session_key_message,
    create_chat_message,
    parse_chat_message,
    create_disconnect_message,
    get_message_type_name
)


def test_protocol():
    print("=" * 50)
    print("Testing Message Protocol")
    print("=" * 50)

    # Test 1: Basic serialization/deserialization
    print("\n1. Testing basic serialization/deserialization...")
    test_payload = b"Hello, this is a test payload!"
    serialized = serialize_message(MESSAGE, test_payload)
    print(f"   Original payload length: {len(test_payload)} bytes")
    print(f"   Serialized message length: {len(serialized)} bytes")
    
    msg_type, payload = deserialize_message(serialized)
    print(f"   Deserialized type: {get_message_type_name(msg_type)}")
    print(f"   Payloads match: {test_payload == payload} (should be True)")

    # Test 2: Public key message
    print("\n2. Testing PUBLIC_KEY message...")
    public_key_bytes = b"-----BEGIN PUBLIC KEY-----\nTest key data\n-----END PUBLIC KEY-----\n"
    pubkey_msg = create_public_key_message(public_key_bytes)
    msg_type, payload = deserialize_message(pubkey_msg)
    print(f"   Type: {get_message_type_name(msg_type)}")
    print(f"   Payload length: {len(payload)} bytes")
    print(f"   Keys match: {public_key_bytes == payload} (should be True)")

    # Test 3: Session key message
    print("\n3. Testing SESSION_KEY message...")
    encrypted_key = b"x" * 256  # Simulated encrypted RSA key
    session_msg = create_session_key_message(encrypted_key)
    msg_type, payload = deserialize_message(session_msg)
    print(f"   Type: {get_message_type_name(msg_type)}")
    print(f"   Payload length: {len(payload)} bytes")
    print(f"   Keys match: {encrypted_key == payload} (should be True)")

    # Test 4: Chat message (with nonce, ciphertext, auth_tag)
    print("\n4. Testing MESSAGE (chat message)...")
    nonce = b"x" * 12
    ciphertext = b"encrypted message data here"
    auth_tag = b"y" * 16
    chat_msg = create_chat_message(nonce, ciphertext, auth_tag)
    msg_type, payload = deserialize_message(chat_msg)
    print(f"   Type: {get_message_type_name(msg_type)}")
    
    # Parse the chat message
    parsed_nonce, parsed_ciphertext, parsed_auth_tag = parse_chat_message(payload)
    print(f"   Nonce match: {nonce == parsed_nonce} (should be True)")
    print(f"   Ciphertext match: {ciphertext == parsed_ciphertext} (should be True)")
    print(f"   Auth tag match: {auth_tag == parsed_auth_tag} (should be True)")

    # Test 5: Disconnect message
    print("\n5. Testing DISCONNECT message...")
    disconnect_msg = create_disconnect_message()
    msg_type, payload = deserialize_message(disconnect_msg)
    print(f"   Type: {get_message_type_name(msg_type)}")
    print(f"   Payload length: {len(payload)} bytes (should be 0)")

    # Test 6: Error handling - incomplete message
    print("\n6. Testing error handling...")
    incomplete = b"\x03\x00\x00\x00\x10"  # Type 3, length 16, but only 5 bytes
    try:
        deserialize_message(incomplete)
        print("   ERROR: Should have raised ValueError!")
    except ValueError as e:
        print(f"   ✓ Correctly caught incomplete message: {str(e)[:50]}...")

    # Test 7: Multiple messages concatenated (simulating network stream)
    print("\n7. Testing multiple messages...")
    msg1 = create_public_key_message(b"key1")
    msg2 = create_session_key_message(b"session_key_data")
    msg3 = create_chat_message(b"x" * 12, b"hello", b"y" * 16)
    
    combined = msg1 + msg2 + msg3
    print(f"   Combined length: {len(combined)} bytes")
    
    # Deserialize first message
    msg_type1, payload1 = deserialize_message(combined)
    print(f"   First message type: {get_message_type_name(msg_type1)}")
    
    # Deserialize second message (skip first message)
    offset = 5 + len(payload1)
    msg_type2, payload2 = deserialize_message(combined[offset:])
    print(f"   Second message type: {get_message_type_name(msg_type2)}")
    
    # Deserialize third message
    offset += 5 + len(payload2)
    msg_type3, payload3 = deserialize_message(combined[offset:])
    print(f"   Third message type: {get_message_type_name(msg_type3)}")

    # Test 8: Real-world example with crypto module
    print("\n8. Testing with real crypto data...")
    try:
        sys.path.insert(0, str(Path(__file__).parent / "client"))
        from crypto import encrypt_message
        
        session_key = b"x" * 32  # 32-byte AES key
        plaintext = "Hello, secure world!"
        nonce, ciphertext, auth_tag = encrypt_message(session_key, plaintext)
        
        # Create message
        real_chat_msg = create_chat_message(nonce, ciphertext, auth_tag)
        msg_type, payload = deserialize_message(real_chat_msg)
        
        # Parse and verify
        parsed_nonce, parsed_ciphertext, parsed_auth_tag = parse_chat_message(payload)
        print(f"   Nonce length: {len(parsed_nonce)} bytes (should be 12)")
        print(f"   Ciphertext length: {len(parsed_ciphertext)} bytes")
        print(f"   Auth tag length: {len(parsed_auth_tag)} bytes (should be 16)")
        print(f"   All components match: {nonce == parsed_nonce and ciphertext == parsed_ciphertext and auth_tag == parsed_auth_tag}")
    except ImportError:
        print("   (Skipping - crypto module not available)")

    print("\n" + "=" * 50)
    print("All tests completed!")
    print("=" * 50)


if __name__ == "__main__":
    test_protocol()

