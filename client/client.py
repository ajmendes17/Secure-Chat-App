
# Client networking module for Secure Chat Application.
# Handles connection to server, key exchange, and encrypted messaging.


import socket
import threading
import sys
import struct
from pathlib import Path

# Add shared directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "shared"))

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

from key_manager import KeyManager
from crypto import (
    generate_session_key,
    encrypt_session_key_with_rsa,
    decrypt_session_key_with_rsa,
    encrypt_message,
    decrypt_message
)


class ChatClient:
    """Client for secure chat application."""

    def __init__(self, host='localhost', port=8888, keys_dir='keys'):
        """
        Initialize the chat client.
        Args: Server host, Server port, Directory for keys
        """
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        self.lock = threading.Lock()

        # Key management
        self.key_manager = KeyManager(keys_dir=keys_dir)
        self.key_manager.get_or_create_keys()

        # Peer's public key (RSA)
        self.peer_public_key = None

        # Session key (AES)
        self.session_key = None
        self.session_key_exchanged = False

        # Callbacks
        self.on_message_received = None  # Callback: (message: str) -> None
        self.on_connection_status = None  # Callback: (connected: bool) -> None
        self.on_error = None  # Callback: (error: str) -> None

        # Thread for receiving messages
        self.receive_thread = None

    def connect(self):
        """
        Connect to the server and start key exchange.
        Returns: True if successful, False otherwise
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))

            # Send public key to server
            public_key_bytes = self.key_manager.get_public_key_bytes()
            message = create_public_key_message(public_key_bytes)
            self.socket.sendall(message)

            # Wait for peer's public key
            self.peer_public_key = self.receive_public_key()
            if not self.peer_public_key:
                raise Exception("Failed to receive peer's public key")

            # Generate and send session key
            self.session_key = generate_session_key()
            encrypted_session_key = encrypt_session_key_with_rsa(
                self.peer_public_key,
                self.session_key
            )
            session_key_msg = create_session_key_message(encrypted_session_key)
            self.socket.sendall(session_key_msg)

            self.connected = True
            self._update_connection_status(True)

            # Start receiving messages in background thread
            self.receive_thread = threading.Thread(
                target=self._receive_loop,
                daemon=True
            )
            self.receive_thread.start()

            return True

        except Exception as e:
            error_msg = f"Connection failed: {e}"
            if self.on_error:
                self.on_error(error_msg)
            print(error_msg)
            self.disconnect()
            return False

    def receive_public_key(self):
        """
        Receive peer's public key from server.
        Returns: Peer's public key object, or None if failed
        """
        try:
            # Receive message header
            header = self._recv_exact(5)
            if not header:
                return None

            msg_type, payload_length = struct.unpack('>BI', header)

            # Receive payload
            payload = self._recv_exact(payload_length)
            if not payload:
                return None

            if msg_type != PUBLIC_KEY:
                print(f"Expected PUBLIC_KEY, got {get_message_type_name(msg_type)}")
                return None

            # Load public key
            peer_key = self.key_manager.load_public_key_from_bytes(payload)
            print(f"Received peer's public key ({len(payload)} bytes)")
            return peer_key

        except Exception as e:
            print(f"Error receiving public key: {e}")
            return None

    def send_message(self, message):
        """
        Encrypt and send a message to the peer.
        Args: Message string to send
        Returns: True if successful, False otherwise
        """
        if not self.connected:
            if self.on_error:
                self.on_error("Not connected to server")
            return False

        if not self.session_key:
            if self.on_error:
                self.on_error("Session key not established")
            return False

        try:
            # Encrypt message
            nonce, ciphertext, auth_tag = encrypt_message(self.session_key, message)

            # Create and send message
            chat_msg = create_chat_message(nonce, ciphertext, auth_tag)
            self.socket.sendall(chat_msg)

            return True

        except Exception as e:
            error_msg = f"Failed to send message: {e}"
            if self.on_error:
                self.on_error(error_msg)
            print(error_msg)
            return False

    def _receive_loop(self):
        """Background thread loop for receiving messages."""
        buffer = b''

        while self.connected:
            try:
                # Receive data
                data = self.socket.recv(4096)
                if not data:
                    break

                buffer += data

                # Process complete messages
                while len(buffer) >= 5:
                    try:
                        msg_type, payload = deserialize_message(buffer)
                        msg_length = 5 + len(payload)

                        # Check if we have the full message
                        if len(buffer) < msg_length:
                            break

                        # Extract message
                        message = buffer[:msg_length]
                        buffer = buffer[msg_length:]

                        # Handle message
                        self._handle_received_message(msg_type, payload)

                    except ValueError:
                        # Incomplete message, wait for more data
                        break

            except socket.error:
                # Socket error, connection likely closed
                break
            except Exception as e:
                error_msg = f"Error in receive loop: {e}"
                if self.on_error:
                    self.on_error(error_msg)
                print(error_msg)
                break

        # Connection closed
        self._handle_disconnect()

    def _handle_received_message(self, msg_type, payload):
        """
        Handle a received message.
        Args: Message type, Message payload
        """
        if msg_type == PUBLIC_KEY:
            # Receive peer's public key (if we connected first)
            try:
                self.peer_public_key = self.key_manager.load_public_key_from_bytes(payload)
                print("Received peer's public key")
            except Exception as e:
                print(f"Error loading peer's public key: {e}")

        elif msg_type == SESSION_KEY:
            # Receive and decrypt session key
            try:
                if not self.key_manager.private_key:
                    raise Exception("No private key available")

                self.session_key = decrypt_session_key_with_rsa(
                    self.key_manager.private_key,
                    payload
                )
                self.session_key_exchanged = True
                print("Session key established")
            except Exception as e:
                error_msg = f"Failed to decrypt session key: {e}"
                if self.on_error:
                    self.on_error(error_msg)
                print(error_msg)

        elif msg_type == MESSAGE:
            # Decrypt and display message
            if not self.session_key:
                print("Received message but no session key available")
                return

            try:
                nonce, ciphertext, auth_tag = parse_chat_message(payload)
                plaintext = decrypt_message(self.session_key, nonce, ciphertext, auth_tag)
                message_text = plaintext.decode('utf-8')

                # Call callback
                if self.on_message_received:
                    self.on_message_received(message_text)
                else:
                    print(f"Received: {message_text}")

            except ValueError as e:
                error_msg = f"Failed to decrypt message: {e}"
                if self.on_error:
                    self.on_error(error_msg)
                print(error_msg)

        elif msg_type == DISCONNECT:
            print("Peer disconnected")
            self._handle_disconnect()

    def _handle_disconnect(self):
        """Handle disconnection from server."""
        self.connected = False
        self._update_connection_status(False)
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass

    def disconnect(self):
        """Disconnect from server."""
        if self.connected:
            try:
                disconnect_msg = create_disconnect_message()
                self.socket.sendall(disconnect_msg)
            except Exception:
                pass

        self._handle_disconnect()

    def _recv_exact(self, n):
        """
        Receive exactly n bytes from socket.
        Args: Number of bytes to receive
        Returns: Received data, or None if connection closed
        """
        data = b''
        while len(data) < n:
            try:
                chunk = self.socket.recv(n - len(data))
                if not chunk:
                    return None
                data += chunk
            except socket.error:
                return None
        return data

    def _update_connection_status(self, connected):
        """Update connection status and call callback."""
        if self.on_connection_status:
            self.on_connection_status(connected)

    def get_public_key_fingerprint(self):
        """Get fingerprint of this client's public key."""
        return self.key_manager.get_public_key_fingerprint()

    def is_connected(self):
        """Check if client is connected."""
        return self.connected

