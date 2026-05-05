# Secure Chat Application

A Python client-server chat application that demonstrates end-to-end encrypted messaging using RSA-OAEP for session key exchange and AES-256-GCM for authenticated message encryption. Built with a Tkinter GUI, custom TCP message protocol, persistent RSA keys, and test coverage for crypto, protocol, client, and server behavior.

## Completion Status

This project is complete as a portfolio-ready educational demo. The core cryptographic flow, client/server networking, GUI, custom protocol, and test scripts are implemented. Future improvements would include peer fingerprint confirmation, encrypted private key storage, TLS transport, reconnect handling, and pytest-based automated tests.

## Features

- **End-to-End Encryption**: Messages are encrypted on the client side and never decrypted by the server
- **RSA Key Exchange**: 2048-bit RSA keys for secure session key exchange
- **AES-GCM Encryption**: 256-bit AES with Galois/Counter Mode for authenticated encryption
- **Key Management**: Automatic RSA keypair generation and persistence
- **GUI Interface**: User-friendly Tkinter-based interface
- **Tamper Detection**: Authentication tags prevent message tampering

## Architecture

The application consists of three main components:

1. **Server** (`server/server.py`): Relays encrypted messages between clients and facilitates public key exchange
2. **Client** (`client/client.py`): Handles encryption, decryption, and network communication
3. **GUI** (`client/gui.py`): User interface for the chat application

### Encryption Flow

```
Client 1                    Server                    Client 2
   |                          |                          |
   |--[RSA Public Key]------->|                          |
   |                          |<--[RSA Public Key]-------|
   |                          |                          |
   |<--[Client 2's Pub Key]---|                          |
   |                          |--[Client 1's Pub Key]--->|
   |                          |                          |
   |--[Encrypted AES Key]----->|--[Encrypted AES Key]---->|
   |                          |                          |
   |<--[Encrypted Message]----|--[Encrypted Message]--->|
```

## Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

### Setup

1. Clone or download this repository

2. Create a virtual environment (recommended):
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Starting the Server

In one terminal, start the server:

```bash
source venv/bin/activate  # If using virtual environment
python server/server.py
```

The server will start on `localhost:8888` by default. You can specify a different host/port:

```bash
python server/server.py --host 0.0.0.0 --port 8888
```

### Starting Clients

In separate terminals, start two client instances:

**Terminal 2 (Client 1):**
```bash
source venv/bin/activate
python run_client.py
```

**Terminal 3 (Client 2):**
```bash
source venv/bin/activate
python run_client.py --keys-dir keys2  # Use different keys directory
```

Or use the GUI module directly:
```bash
python -m client.gui
```

### Using the GUI

1. The GUI will automatically attempt to connect when opened
2. Wait for "Status: Connected" (green) to appear
3. Type messages in the input field and press Enter or click Send
4. Messages from the peer will appear in the chat area
5. Your public key fingerprint is displayed at the top

## Project Structure

```
Secure Chat App/
├── server/
│   ├── __init__.py
│   └── server.py              # TCP server implementation
├── client/
│   ├── __init__.py
│   ├── client.py              # Client networking logic
│   ├── crypto.py              # Encryption/decryption functions
│   ├── key_manager.py         # RSA key management
│   └── gui.py                 # GUI interface
├── shared/
│   ├── __init__.py
│   └── protocol.py            # Message protocol definitions
├── keys/                      # RSA keys (generated automatically)
├── requirements.txt
├── run_client.py             # Client launcher
└── README.md
```

## Security Features

- **RSA-2048**: 2048-bit RSA keys for identity and key exchange
- **AES-256-GCM**: 256-bit AES encryption with authenticated encryption
- **Unique Nonces**: Each message uses a unique 96-bit nonce
- **Authentication Tags**: 16-byte tags verify message integrity
- **Ephemeral Session Keys**: New AES key generated for each session
- **End-to-End**: Server never sees plaintext messages

## Testing

Test scripts are provided for individual components:

```bash
# Test key manager
python test_key_manager.py

# Test crypto module
python test_crypto.py

# Test message protocol
python test_protocol.py

# Test server connection
python test_server.py
```

## Development Notes

- Private keys are stored unencrypted in the `keys/` directory (for demo purposes)
- In production, private keys should be encrypted with a password
- The server is a simple relay and doesn't decrypt messages
- Each client needs its own `keys/` directory to have separate identities

## License

This is a demonstration project for educational purposes.
