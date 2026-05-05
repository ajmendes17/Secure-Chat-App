
# Test script for client networking.
# Run this after starting the server.


import sys
import time
from pathlib import Path

# Add client directory to path
sys.path.insert(0, str(Path(__file__).parent / "client"))

from client import ChatClient


def test_client():
    """Test client connection and messaging."""
    print("=" * 50)
    print("Testing Chat Client")
    print("=" * 50)

    # Create client
    print("\n1. Creating client...")
    client = ChatClient(host='localhost', port=8888, keys_dir='test_client_keys')

    # Set up callbacks
    def on_message(msg):
        print(f"\n[Received]: {msg}")

    def on_status(connected):
        status = "connected" if connected else "disconnected"
        print(f"\n[Status]: {status}")

    def on_error(error):
        print(f"\n[Error]: {error}")

    client.on_message_received = on_message
    client.on_connection_status = on_status
    client.on_error = on_error

    # Connect
    print("\n2. Connecting to server...")
    if client.connect():
        print(f"   ✓ Connected! Public key fingerprint: {client.get_public_key_fingerprint()}")

        # Wait a bit for key exchange
        print("\n3. Waiting for key exchange...")
        time.sleep(2)

        if client.is_connected():
            print("   ✓ Key exchange complete!")

            # Test sending a message
            print("\n4. Sending test message...")
            test_message = "Hello from test client!"
            if client.send_message(test_message):
                print(f"   ✓ Sent: {test_message}")

            # Wait for response
            print("\n5. Waiting for messages (press Ctrl+C to exit)...")
            try:
                while client.is_connected():
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nDisconnecting...")
                client.disconnect()
        else:
            print("   ✗ Connection failed")
    else:
        print("   ✗ Failed to connect to server")
        print("   Make sure the server is running: python server/server.py")


if __name__ == "__main__":
    test_client()

