"""
Simple test script to verify server starts and accepts connections.
Run this in a separate terminal while the server is running.
"""

import socket
import sys
from pathlib import Path

# Add shared directory to path
sys.path.insert(0, str(Path(__file__).parent / "shared"))

from protocol import create_public_key_message, DISCONNECT, create_disconnect_message


def test_server_connection():
    """Test connecting to the server and sending a public key."""
    print("Testing server connection...")

    try:
        # Connect to server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8888))
        print("✓ Connected to server")

        # Send a fake public key
        fake_key = b"-----BEGIN PUBLIC KEY-----\nFAKE KEY FOR TESTING\n-----END PUBLIC KEY-----\n"
        message = create_public_key_message(fake_key)
        sock.sendall(message)
        print("✓ Sent public key")

        # Wait a bit for server to process
        import time
        time.sleep(0.5)

        # Send disconnect
        disconnect_msg = create_disconnect_message()
        sock.sendall(disconnect_msg)
        print("✓ Sent disconnect message")

        sock.close()
        print("✓ Connection closed successfully")

    except ConnectionRefusedError:
        print("✗ Could not connect to server. Is it running?")
        print("  Start the server with: python server/server.py")
    except Exception as e:
        print(f"✗ Error: {e}")


if __name__ == "__main__":
    test_server_connection()

