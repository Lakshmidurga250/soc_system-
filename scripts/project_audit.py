"""SentinelAI Project Readiness & Line-of-Code Audit Script."""
import os
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

EXCLUDE_DIRS = {
    ".git", ".venv", "venv", "node_modules", ".pytest_cache",
    "__pycache__", "build", "dist", "storage", "ml_models"
}

EXTENSIONS = {
    ".py": "Python",
    ".ts": "TypeScript",
    ".tsx": "TypeScript React",
    ".js": "JavaScript",
    ".css": "CSS",
    ".html": "HTML",
    ".md": "Markdown",
    ".json": "JSON",
    ".toml": "TOML",
    ".yml": "YAML",
    ".yaml": "YAML",
}

def audit_project():
    print("=" * 60)
    print("[AUDIT] SENTINELAI PROJECT AUDIT & METRICS REPORT")
    print("=" * 60)

    total_files = 0
    total_loc = 0
    by_language = {}

    for root, dirs, files in os.walk(ROOT_DIR):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in EXTENSIONS:
                filepath = Path(root) / f
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as file_obj:
                        lines = [line.strip() for line in file_obj.readlines() if line.strip()]
                        count = len(lines)
                        lang = EXTENSIONS[ext]
                        by_language[lang] = by_language.get(lang, 0) + count
                        total_loc += count
                        total_files += 1
                except Exception:
                    continue

    print(f"Total Evaluated Source Files: {total_files}")
    print(f"Total Non-Empty LOC:          {total_loc:,}")
    print("-" * 60)
    print("Breakdown by Language:")
    for lang, count in sorted(by_language.items(), key=lambda x: x[1], reverse=True):
        print(f"  - {lang:20s}: {count:8,d} lines")
    print("=" * 60)

if __name__ == "__main__":
    audit_project()
