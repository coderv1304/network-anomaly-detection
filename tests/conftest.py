"""
tests/conftest.py
Configures sys.path so test discovery and execution can import root modules.
"""

import sys
import os

# Insert project root into sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
