# Message protocol for secure chat application.
# Defines message types and serialization/deserialization functions.


import struct

# Message type constants
PUBLIC_KEY = 1
SESSION_KEY = 2
MESSAGE = 3
DISCONNECT = 4

# For Debugging
MESSAGE_TYPE_NAMES = {
    PUBLIC_KEY: "PUBLIC_KEY",
    SESSION_KEY: "SESSION_KEY",
    MESSAGE: "MESSAGE",
    DISCONNECT: "DISCONNECT"
}


def serialize_message(msg_type, payload):
    """
    Serialize a message into bytes format: TYPE|LENGTH|PAYLOAD
    Args: Message type constant (PUBLIC_KEY, SESSION_KEY, etc.) and message payload as bytes
    Returns: Serialized message in bytes
    """
    if not isinstance(payload, bytes):
        raise TypeError("Payload must be bytes")

    # 'B' = unsigned char (1 byte), '>I' = big-endian unsigned int (4 bytes)
    header = struct.pack('>BI', msg_type, len(payload)) 
    return header + payload


def deserialize_message(data):
    """
    Deserialize a message from bytes.
    Args: Serialized message bytes
    Returns: Tuple of message type and payload as bytes
    ValueError if data is too short or invalid
    """
    if len(data) < 5:
        raise ValueError("Message too short: need at least 5 bytes")
    
    msg_type, payload_length = struct.unpack('>BI', data[:5])
    
    if len(data) < 5 + payload_length:
        raise ValueError(f"Message incomplete: expected {5 + payload_length} bytes, got {len(data)}")
    
    payload = data[5:5 + payload_length]
    
    return (msg_type, payload)


def create_public_key_message(public_key_bytes):
    """
    Create a PUBLIC_KEY message.
    Args: RSA public key in PEM format as bytes
    Returns: Serialized message in bytes
    """

    return serialize_message(PUBLIC_KEY, public_key_bytes)


def create_session_key_message(encrypted_session_key):
    """
    Create a SESSION_KEY message.
    Args: Encrypted AES session key as bytes
    Returns: Serialized message in bytes
    """

    return serialize_message(SESSION_KEY, encrypted_session_key)


def create_chat_message(nonce, ciphertext, auth_tag):
    """
    Create a MESSAGE (encrypted chat message).
    The payload format is: NONCE (12 bytes) | CIPHERTEXT | AUTH_TAG (16 bytes)
    Args: 12-byte nonce, encrypted message bytes, and 16-byte authentication tag
    Returns: Serialized message in bytes
    """

    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes")
    if len(auth_tag) != 16:
        raise ValueError("Auth tag must be 16 bytes")
    
    payload = nonce + ciphertext + auth_tag
    return serialize_message(MESSAGE, payload)


def parse_chat_message(payload):
    """
    Parse a MESSAGE payload into components.
    Args: Message payload bytes (nonce + ciphertext + auth_tag)
    Returns: Tuple of nonce, ciphertext, and auth_tag as bytes
    """

    if len(payload) < 28: 
        raise ValueError("Message payload too short")
    
    nonce = payload[:12]
    auth_tag = payload[-16:]
    ciphertext = payload[12:-16]
    
    return (nonce, ciphertext, auth_tag)


def create_disconnect_message():
    """
    Create a DISCONNECT message.
    Returns: Serialized message in bytes
    """
    return serialize_message(DISCONNECT, b'')


def get_message_type_name(msg_type):
    """
    Get human-readable name for message type.
    Args: Message type constant
    Returns: Message type name
    """
    return MESSAGE_TYPE_NAMES.get(msg_type, f"UNKNOWN({msg_type})")

