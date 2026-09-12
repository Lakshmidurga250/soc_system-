"""
SentinelAI - Enterprise SOC Full Scale Module Synthesizer
Generates comprehensive production modules for SentinelAI.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
BACKEND_APP = BASE_DIR / "backend" / "app"
FRONTEND_SRC = BASE_DIR / "frontend" / "src"

def save_file(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content.strip() + "\n")

print("Generating comprehensive cybersecurity domain packages...")
