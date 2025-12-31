
# Cryptography module for RSA and AES-GCM operations.
# Handles encryption/decryption of session keys and messages.


from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
import os


def generate_session_key():
    """
    Generate a random 256-bit (32-byte) AES key for session encryption.
    Returns: 32-byte AES key in bytes
    """
    return os.urandom(32)  # 256 bits = 32 bytes


def encrypt_session_key_with_rsa(public_key, session_key):
    """
    Encrypt an AES session key using RSA public key encryption.
    Args: RSA public key object and AES session key as bytes (32 bytes)
    Returns: Encrypted session key in bytes
    """
    # RSA encryption with OAEP padding (standard recommendation for key exchange)
    encrypted_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key


def decrypt_session_key_with_rsa(private_key, encrypted_session_key):
    """
    Decrypt an AES session key using RSA private key.
    Args: RSA private key object and encrypted session key as bytes
    Returns: Decrypted AES session key in bytes
    """
    try:
        session_key = private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return session_key
    except Exception as e:
        raise ValueError(f"Failed to decrypt session key: {e}")


def encrypt_message(aes_key, plaintext):
    """
    Encrypt a message using AES-GCM.
    Args: AES key (32 bytes for AES-256) and message to encrypt (bytes or str)
    Returns: Tuple of nonce, ciphertext, and auth_tag as bytes. The nonce is 12 bytes (96 bits), auth_tag is 16 bytes
    """
    # AES-GCM provides authenticated encryption:
    #   - Confidentiality: message is encrypted.
    #   - Integrity: auth tag prevents tampering.

    # Convert string to bytes if needed
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')

    # Generate random 96-bit (12-byte) nonce for this message. Each message must have a unique nonce.
    nonce = os.urandom(12)
    
    aesgcm = AESGCM(aes_key)
    
    # Encrypt and authenticate
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    
    # Split ciphertext and auth tag
    ciphertext = ciphertext_with_tag[:-16] # Last 16 bytes are the auth tag.
    auth_tag = ciphertext_with_tag[-16:]   # First 16 bytes are the ciphertext.
    
    return (nonce, ciphertext, auth_tag)


def decrypt_message(aes_key, nonce, ciphertext, auth_tag):
    """
    Decrypt and verify a message using AES-GCM.
    Args: AES key (32 bytes for AES-256), nonce, ciphertext, and auth_tag as bytes
    Returns: Decrypted plaintext in bytes
    ValueError if authentication fails (message was tampered with)
    """

    aesgcm = AESGCM(aes_key)
    ciphertext_with_tag = ciphertext + auth_tag
    
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
        return plaintext
    except Exception as e:
        raise ValueError(f"Decryption failed - message may have been tampered with: {e}")


def encrypt_message_simple(aes_key, plaintext):
    """
    Simplified version that returns all components as a single structure.
    Args: AES key (32 bytes) and message to encrypt (bytes or str)        
    Returns: Dictionary with nonce, ciphertext, and auth_tag as bytes
    """

    nonce, ciphertext, auth_tag = encrypt_message(aes_key, plaintext)

    return {
        'nonce': nonce,
        'ciphertext': ciphertext,
        'auth_tag': auth_tag
    }


def decrypt_message_simple(aes_key, encrypted_data):
    """
    Simplified version that returns the decrypted plaintext as bytes.
    Args: AES key (32 bytes) and encrypted data as dictionary with nonce, ciphertext, and auth_tag as bytes
    Returns: Decrypted plaintext in bytes
    """
    return decrypt_message(
        aes_key,
        encrypted_data['nonce'],
        encrypted_data['ciphertext'],
        encrypted_data['auth_tag']
    )
