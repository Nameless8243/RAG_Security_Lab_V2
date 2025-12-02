# simulations/reset_data.py

import os
import shutil
from pathlib import Path

BASE_DATA = Path("data")
AUDIT_DIR = BASE_DATA / "audit"
QUARANTINE_DIR = BASE_DATA / "quarantine"

def safe_clean(dir_path: Path):
    """
    Safely remove all contents of a directory without deleting the directory itself.
    """
    if not dir_path.exists():
        dir_path.mkdir(parents=True, exist_ok=True)
        return

    for item in dir_path.iterdir():
        if item.is_file():
            item.unlink()
        elif item.is_dir():
            shutil.rmtree(item)

def main():
    print("=== RAG SECURITY LAB V2 – CLEANUP SCRIPT ===")

    print(f"Cleaning audit logs in: {AUDIT_DIR}")
    safe_clean(AUDIT_DIR)

    print(f"Cleaning quarantine folder in: {QUARANTINE_DIR}")
    safe_clean(QUARANTINE_DIR)

    print("\nCleanup complete. Folders are now empty.\n")

if __name__ == "__main__":
    main()
