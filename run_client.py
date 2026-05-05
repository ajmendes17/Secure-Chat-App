"""
Launcher script for the Secure Chat Client GUI.
"""

import sys
from pathlib import Path

# Add client directory to path
sys.path.insert(0, str(Path(__file__).parent / "client"))

from gui import main

if __name__ == "__main__":
    main()

