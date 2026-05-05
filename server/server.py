
# TCP Server for Secure Chat Application.
# Relays encrypted messages between clients and facilitates public key exchange.


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
    deserialize_message,
    get_message_type_name,
    create_public_key_message
)


class ChatServer:
    """TCP server that relays encrypted messages between clients."""

    def __init__(self, host='localhost', port=8888):
        """
        Initialize the Chat Server.
        Args: Server host address (default: 'localhost'), Server port (default: 8888)
        """
        self.host = host
        self.port = port
        self.socket = None
        self.clients = {}  # {client_id: {'socket': socket, 'public_key': bytes, 'address': tuple}}
        self.client_counter = 0
        self.lock = threading.Lock()

    def start(self):
        """Start the server and begin accepting connections."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            print(f"Server started on {self.host}:{self.port}")
            print("Waiting for clients to connect...")

            while True:
                client_socket, address = self.socket.accept()
                print(f"New connection from {address}")

                # Assign client ID and create handler thread
                with self.lock:
                    self.client_counter += 1
                    client_id = self.client_counter

                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address, client_id),
                    daemon=True
                )
                client_thread.start()

        except KeyboardInterrupt:
            print("\nShutting down server...")
            self.stop()
        except Exception as e:
            print(f"Server error: {e}")
            self.stop()

    def handle_client(self, client_socket, address, client_id):
        """
        Handle a client connection.
        Args: Client socket, Client address tuple, Unique client identifier
        """
        try:
            # Receive public key from client
            public_key = self.receive_public_key(client_socket, client_id)
            if not public_key:
                return

            # Register client
            with self.lock:
                self.clients[client_id] = {
                    'socket': client_socket,
                    'public_key': public_key,
                    'address': address
                }
                print(f"Client {client_id} registered from {address}")

            # If there's another client, exchange public keys
            self.exchange_public_keys(client_id)

            # Handle messages from this client
            self.receive_messages(client_socket, client_id)

        except Exception as e:
            print(f"Error handling client {client_id}: {e}")
        finally:
            self.disconnect_client(client_id)

    def receive_public_key(self, client_socket, client_id):
        """
        Receive public key from client.
        Args: Client socket, Client identifier
        Returns: Public key bytes, or None if failed
        """
        try:
            # Receive message header (5 bytes: 1 byte type + 4 bytes length)
            header = self.recv_exact(client_socket, 5)
            if not header:
                return None

            # Parse header to get message type and payload length
            msg_type, payload_length = struct.unpack('>BI', header)

            # Receive full payload
            payload = self.recv_exact(client_socket, payload_length)
            if not payload:
                return None

            # Verify it's a PUBLIC_KEY message
            if msg_type != PUBLIC_KEY:
                print(f"Client {client_id} sent wrong message type: {get_message_type_name(msg_type)}")
                return None

            print(f"Received public key from client {client_id} ({len(payload)} bytes)")
            return payload

        except Exception as e:
            print(f"Error receiving public key from client {client_id}: {e}")
            return None

    def exchange_public_keys(self, new_client_id):
        """
        Exchange public keys between clients when a new client connects.
        Args: New client ID
        """
        with self.lock:
            # Get all other clients
            other_clients = [cid for cid in self.clients.keys() if cid != new_client_id]

            if not other_clients:
                print(f"Client {new_client_id} is the first client, waiting for another...")
                return

            # Send new client's public key to all existing clients
            new_client_key = self.clients[new_client_id]['public_key']
            for other_id in other_clients:
                try:
                    self.send_public_key(other_id, new_client_key)
                    print(f"Sent new client's public key to client {other_id}")
                except Exception as e:
                    print(f"Error sending public key to client {other_id}: {e}")

            # Send existing clients' public keys to new client
            for other_id in other_clients:
                try:
                    other_key = self.clients[other_id]['public_key']
                    self.send_public_key(new_client_id, other_key)
                    print(f"Sent client {other_id}'s public key to new client {new_client_id}")
                except Exception as e:
                    print(f"Error sending public key to new client: {e}")

    def send_public_key(self, client_id, public_key_bytes):
        """
        Send a public key to a client.
        Args: Target client ID, Public key to send
        """
        message = create_public_key_message(public_key_bytes)
        client_socket = self.clients[client_id]['socket']
        client_socket.sendall(message)

    def receive_messages(self, client_socket, client_id):
        """
        Receive and relay messages from a client.
        Args: Client socket, Client identifier
        """
        buffer = b''

        while True:
            try:
                # Receive data
                data = client_socket.recv(4096)
                if not data:
                    break

                buffer += data

                # Process complete messages
                while len(buffer) >= 5:
                    try:
                        # Try to deserialize a message
                        msg_type, payload = deserialize_message(buffer)
                        msg_length = 5 + len(payload)

                        # Remove processed message from buffer
                        message = buffer[:msg_length]
                        buffer = buffer[msg_length:]

                        # Handle message
                        if msg_type == DISCONNECT:
                            print(f"Client {client_id} disconnected")
                            return

                        elif msg_type == SESSION_KEY or msg_type == MESSAGE:
                            # Relay to other clients
                            self.relay_message(client_id, message)

                        else:
                            print(f"Unknown message type from client {client_id}: {get_message_type_name(msg_type)}")

                    except ValueError:
                        # Incomplete message, wait for more data
                        break

            except socket.error:
                break
            except Exception as e:
                print(f"Error receiving message from client {client_id}: {e}")
                break

    def relay_message(self, sender_id, message):
        """
        Relay a message to all other clients.
        Args: ID of the client sending the message, Complete serialized message
        """
        with self.lock:
            other_clients = [cid for cid in self.clients.keys() if cid != sender_id]

        for client_id in other_clients:
            try:
                client_socket = self.clients[client_id]['socket']
                client_socket.sendall(message)
            except Exception as e:
                print(f"Error relaying message to client {client_id}: {e}")

    def recv_exact(self, sock, n):
        """
        Receive exactly n bytes from socket.
        Args: Socket to receive from, Number of bytes to receive
        Returns: Received data, or None if connection closed
        """
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def disconnect_client(self, client_id):
        """
        Remove client from registry and close connection.
        Args: Client identifier
        """
        with self.lock:
            if client_id in self.clients:
                try:
                    self.clients[client_id]['socket'].close()
                except Exception:
                    pass
                del self.clients[client_id]
                print(f"Client {client_id} disconnected. Active clients: {len(self.clients)}")

    def stop(self):
        """Stop the server and close all connections."""
        print("Closing all client connections...")
        with self.lock:
            for client_id in list(self.clients.keys()):
                self.disconnect_client(client_id)

        if self.socket:
            self.socket.close()
        print("Server stopped.")


def main():
    """Main entry point for the server."""
    import argparse

    parser = argparse.ArgumentParser(description='Secure Chat Server')
    parser.add_argument('--host', default='localhost', help='Server host (default: localhost)')
    parser.add_argument('--port', type=int, default=8888, help='Server port (default: 8888)')

    args = parser.parse_args()

    server = ChatServer(host=args.host, port=args.port)
    server.start()


if __name__ == "__main__":
    main()
