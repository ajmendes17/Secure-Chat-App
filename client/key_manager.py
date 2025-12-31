"""
Key Manager for RSA keypair generation and persistence.
"""

import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


class KeyManager:

    def __init__(self, keys_dir="keys"):
        """
        Initialize the KeyManager.

        Args: keys_dir: Directory to store the keys (default: "keys").
        """

        self.keys_dir = Path(keys_dir)
        self.keys_dir.mkdir(exist_ok=True)

        self.private_key_path = self.keys_dir / "private_key.pem"  # .pem is for Privacy-Enhanced Mail, common format for keys.
        self.public_key_path = self.keys_dir / "public_key.pem"    

        self.private_key = None
        self.public_key = None

    def generate_keypair(self):
        """Generate a 2048-bit RSA keypair."""
        print("Generating new RSA keypair")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,  # 65537 is the default public exponent for RSA.
            key_size=2048,          # 2048-bit key size is also standard for RSA.
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def save_keys(self):
        """Save the private and public keys to the keys directory."""
        if not self.private_key or not self.public_key:
            raise ValueError("No keys to save. Generate or load keys first.")
        
        # Save private key
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,           # Standard private key format
            encryption_algorithm=serialization.NoEncryption()   # Plain for this project. For a real project, you would use a password.
        )
        with open(self.private_key_path, 'wb') as f:
            f.write(private_pem)
        print(f"Private key saved to {self.private_key_path}")
        # Could easily add - os.chmod(self.private_key_path, 0o600) to make the file read only by the user.
        # Would also not commit this to the repository. This would only be visible on the host machine.

        # Save public key
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(self.public_key_path, 'wb') as f:
            f.write(public_pem)
        print(f"Public key saved to {self.public_key_path}")

    def load_keys(self):
        """Load existing keys from PEM files. Returns True if loaded, False if not found."""
        if not self.private_key_path.exists() or not self.public_key_path.exists():
            return False
        
        # Load private key
        with open(self.private_key_path, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,  # Again no password for this project.
                backend=default_backend()
            )
        
        # Load public key
        with open(self.public_key_path, 'rb') as f:
            self.public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        
        print("Keys loaded successfully!")
        return True
    
    def get_or_create_keys(self):
        """
        Get existing keys or generate new ones if they don't exist.
        Returns: True if keys were loaded and False if new ones were generated.
        """

        if self.load_keys():
            return True
        else:
            self.generate_keypair()
            self.save_keys()
            return False

    def get_public_key_bytes(self):
        """
        Get the public key as bytes (PEM format) for transmission.      
        Returns: bytes of the Public key in PEM format
        """

        if not self.public_key:
            raise ValueError("No public key available. Load or generate keys first.")

        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def get_public_key_fingerprint(self):
        """
        Get a fingerprint of the public key for display purposes.
        Returns: Hexadecimal fingerprint of the public key
        """

        if not self.public_key:
            raise ValueError("No public key available. Load or generate keys first.")

        public_key_bytes = self.get_public_key_bytes()
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(public_key_bytes)
        fingerprint = digest.finalize()

        return fingerprint.hex()[:16].upper()  # First 16 hex chars for display. I made it hex so it's shorter and easier to read.

    def load_public_key_from_bytes(self, public_key_bytes):
        """
        Load a public key from bytes (received from peer).
        Args: Public key in PEM format as bytes
        Returns: Public key object
        """

        return serialization.load_pem_public_key(
            public_key_bytes,
            backend=default_backend()
        )