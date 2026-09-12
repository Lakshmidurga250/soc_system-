import ast
import glob
import os
import sys

for root, dirs, files in os.walk("."):
    if ".venv" in root or "node_modules" in root or ".git" in root:
        continue
    for f in files:
        if f.endswith(".py"):
            p = os.path.join(root, f)
            try:
                with open(p, "r", encoding="utf-8") as fh:
                    ast.parse(fh.read())
            except Exception as e:
                print(f"Error in {p}: {e}")
print("Done checking all files.")
