"""
GUI for Secure Chat Application using Tkinter.
"""

import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import sys
from pathlib import Path

# Add client directory to path
sys.path.insert(0, str(Path(__file__).parent))

from client import ChatClient


class ChatGUI:
    """GUI interface for secure chat application."""

    def __init__(self, host='localhost', port=8888, keys_dir='keys'):
        """
        Initialize the GUI.
        Args: Server host, Server port, Directory for keys
        """
        self.root = tk.Tk()
        self.root.title("Secure Chat App")
        self.root.geometry("600x700")

        # Client instance
        self.client = ChatClient(host=host, port=port, keys_dir=keys_dir)
        self.client.on_message_received = self.on_message_received
        self.client.on_connection_status = self.on_connection_status
        self.client.on_error = self.on_error

        # GUI components
        self.setup_ui()

        # Auto-connect on startup
        self.connect()

    def setup_ui(self):
        """Set up the user interface."""
        # Top frame for connection info
        top_frame = tk.Frame(self.root, bg='#f0f0f0', pady=10)
        top_frame.pack(fill=tk.X, padx=10, pady=5)

        # Connection status
        self.status_label = tk.Label(
            top_frame,
            text="Status: Disconnected",
            font=('Arial', 10, 'bold'),
            bg='#f0f0f0',
            fg='#d32f2f'
        )
        self.status_label.pack(side=tk.LEFT, padx=10)

        # Public key fingerprint
        fingerprint = self.client.get_public_key_fingerprint()
        self.fingerprint_label = tk.Label(
            top_frame,
            text=f"Key: {fingerprint}",
            font=('Arial', 9),
            bg='#f0f0f0',
            fg='#666'
        )
        self.fingerprint_label.pack(side=tk.RIGHT, padx=10)

        # Connect/Disconnect button
        self.connect_button = tk.Button(
            top_frame,
            text="Connect",
            command=self.toggle_connection,
            bg='#4caf50',
            fg='white',
            font=('Arial', 10, 'bold'),
            padx=15
        )
        self.connect_button.pack(side=tk.RIGHT, padx=5)

        # Messages display area
        messages_frame = tk.Frame(self.root)
        messages_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.messages_text = scrolledtext.ScrolledText(
            messages_frame,
            wrap=tk.WORD,
            font=('Arial', 11),
            bg='#ffffff',
            fg='#000000',
            state=tk.DISABLED,
            padx=10,
            pady=10
        )
        self.messages_text.pack(fill=tk.BOTH, expand=True)

        # Input frame
        input_frame = tk.Frame(self.root, bg='#f0f0f0')
        input_frame.pack(fill=tk.X, padx=10, pady=10)

        # Message input field
        self.input_entry = tk.Entry(
            input_frame,
            font=('Arial', 11),
            bg='#ffffff',
            fg='#000000'
        )
        self.input_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        self.input_entry.bind('<Return>', lambda e: self.send_message())

        # Send button
        self.send_button = tk.Button(
            input_frame,
            text="Send",
            command=self.send_message,
            bg='#2196f3',
            fg='white',
            font=('Arial', 10, 'bold'),
            padx=20,
            state=tk.DISABLED
        )
        self.send_button.pack(side=tk.RIGHT)

    def add_message(self, message, sender="You"):
        """
        Add a message to the display area (thread-safe).
        Args: Message text, Sender name
        """
        def _add():
            self.messages_text.config(state=tk.NORMAL)
            if sender == "You":
                self.messages_text.insert(tk.END, f"{sender}: {message}\n", "sent")
                self.messages_text.tag_config("sent", foreground="#1976d2")
            else:
                self.messages_text.insert(tk.END, f"{sender}: {message}\n", "received")
                self.messages_text.tag_config("received", foreground="#388e3c")
            self.messages_text.config(state=tk.DISABLED)
            self.messages_text.see(tk.END)

        # Thread-safe update
        self.root.after(0, _add)

    def on_message_received(self, message):
        """
        Callback for received messages.
        Args: Message text
        """
        self.add_message(message, sender="Peer")

    def on_connection_status(self, connected):
        """
        Callback for connection status changes.
        Args: Connection status (bool)
        """
        def _update():
            if connected:
                self.status_label.config(text="Status: Connected", fg='#388e3c')
                self.connect_button.config(text="Disconnect", bg='#d32f2f')
                self.send_button.config(state=tk.NORMAL)
                self.input_entry.config(state=tk.NORMAL)
                self.add_message("Connection established. You can now send messages.", sender="System")
            else:
                self.status_label.config(text="Status: Disconnected", fg='#d32f2f')
                self.connect_button.config(text="Connect", bg='#4caf50')
                self.send_button.config(state=tk.DISABLED)
                self.input_entry.config(state=tk.DISABLED)
                self.add_message("Disconnected from server.", sender="System")

        self.root.after(0, _update)

    def on_error(self, error):
        """
        Callback for errors.
        Args: Error message
        """
        def _show_error():
            messagebox.showerror("Error", error)
            self.add_message(f"Error: {error}", sender="System")

        self.root.after(0, _show_error)

    def connect(self):
        """Connect to the server."""
        self.add_message("Connecting to server...", sender="System")
        threading.Thread(target=self.client.connect, daemon=True).start()

    def disconnect(self):
        """Disconnect from the server."""
        self.client.disconnect()

    def toggle_connection(self):
        """Toggle connection status."""
        if self.client.is_connected():
            self.disconnect()
        else:
            self.connect()

    def send_message(self):
        """Send a message."""
        message = self.input_entry.get().strip()
        if not message:
            return

        if not self.client.is_connected():
            messagebox.showwarning("Not Connected", "Please connect to the server first.")
            return

        # Add to display immediately
        self.add_message(message, sender="You")

        # Clear input
        self.input_entry.delete(0, tk.END)

        # Send via client (in background)
        threading.Thread(target=self.client.send_message, args=(message,), daemon=True).start()

    def run(self):
        """Start the GUI main loop."""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

    def on_closing(self):
        """Handle window closing."""
        if self.client.is_connected():
            self.client.disconnect()
        self.root.destroy()


def main():
    """Main entry point for the GUI."""
    import argparse

    parser = argparse.ArgumentParser(description='Secure Chat Client GUI')
    parser.add_argument('--host', default='localhost', help='Server host (default: localhost)')
    parser.add_argument('--port', type=int, default=8888, help='Server port (default: 8888)')
    parser.add_argument('--keys-dir', default='keys', help='Directory for keys (default: keys)')

    args = parser.parse_args()

    app = ChatGUI(host=args.host, port=args.port, keys_dir=args.keys_dir)
    app.run()


if __name__ == "__main__":
    main()

