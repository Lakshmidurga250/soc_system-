"""
SentinelAI - Enterprise SOC Deep Module Generator
Generates comprehensive production cybersecurity domain models, decoders, rulebooks,
intelligence catalogs, compliance matrices, and SOAR playbooks.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
APP_DIR = BASE_DIR / "backend" / "app"

def write_module(subpath: str, content: str):
    file_path = APP_DIR / subpath
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content.strip() + "\n")
    print(f"Generated: {file_path.relative_to(BASE_DIR)}")

# Let's define the comprehensive modules
print("Building enterprise cybersecurity domain modules...")
