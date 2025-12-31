
# Test script for KeyManager


import sys
from pathlib import Path

# Add client directory to path
sys.path.insert(0, str(Path(__file__).parent / "client"))

from key_manager import KeyManager

def test_key_manager():
    print("=" * 50)
    print("Testing KeyManager")
    print("=" * 50)
    
    # Test 1: Create KeyManager and generate new keys
    print("\n1. Testing key generation...")
    km1 = KeyManager(keys_dir="test_keys")
    
    # Delete any existing test keys
    if km1.private_key_path.exists():
        km1.private_key_path.unlink()
    if km1.public_key_path.exists():
        km1.public_key_path.unlink()
    
    was_loaded = km1.get_or_create_keys()
    print(f"   Keys were loaded: {was_loaded} (should be False for first run)")
    
    # Test 2: Get public key bytes
    print("\n2. Testing public key bytes retrieval...")
    public_key_bytes = km1.get_public_key_bytes()
    print(f"   Public key length: {len(public_key_bytes)} bytes")
    print(f"   First 50 chars: {public_key_bytes[:50].decode('utf-8')}")
    
    # Test 3: Get fingerprint
    print("\n3. Testing fingerprint...")
    fingerprint = km1.get_public_key_fingerprint()
    print(f"   Fingerprint: {fingerprint}")
    
    # Test 4: Load keys from file
    print("\n4. Testing key loading...")
    km2 = KeyManager(keys_dir="test_keys")
    was_loaded = km2.get_or_create_keys()
    print(f"   Keys were loaded: {was_loaded} (should be True)")
    
    # Test 5: Verify keys are the same
    print("\n5. Verifying keys match...")
    fingerprint2 = km2.get_public_key_fingerprint()
    print(f"   Original fingerprint: {fingerprint}")
    print(f"   Loaded fingerprint: {fingerprint2}")
    print(f"   Match: {fingerprint == fingerprint2} (should be True)")
    
    # Test 6: Load public key from bytes
    print("\n6. Testing loading public key from bytes...")
    peer_public_key = km1.load_public_key_from_bytes(public_key_bytes)
    print(f"   Peer public key loaded successfully: {peer_public_key is not None}")
    
    print("\n" + "=" * 50)
    print("All tests completed!")
    print("=" * 50)

if __name__ == "__main__":
    test_key_manager()

