import os
import subprocess
import sys


# ---------------------------------------------------------------------------
# Path resolution — always relative to the project root, not the CWD
# ---------------------------------------------------------------------------
SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPTS_DIR, ".."))
TARGET_DIR   = os.path.join(PROJECT_ROOT, "data", "mitre-cti")
REPO_URL     = "https://github.com/mitre/cti.git"


def download_cti_data() -> None:
    """Clone the MITRE CTI repository into data/mitre-cti/ if not present."""

    if os.path.exists(TARGET_DIR) and os.listdir(TARGET_DIR):
        print(f"📦  MITRE CTI data already present at:\n    {TARGET_DIR}")
        print("    Skipping clone. Delete the folder to force a fresh download.")
        return

    os.makedirs(TARGET_DIR, exist_ok=True)
    print(f"📥  Cloning MITRE CTI repository …")
    print(f"    Source : {REPO_URL}")
    print(f"    Target : {TARGET_DIR}\n")

    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", REPO_URL, TARGET_DIR],
            check=True,
        )
        print("\n✅  Clone complete!")
        _print_folder_summary(TARGET_DIR)
    except FileNotFoundError:
        print("❌  git is not installed or not on PATH. Install git and retry.")
        sys.exit(1)
    except subprocess.CalledProcessError as exc:
        print(f"❌  git clone failed (exit code {exc.returncode}).")
        sys.exit(1)


def _print_folder_summary(path: str) -> None:
    """Print a quick inventory of top-level items in the cloned repo."""
    items = sorted(os.listdir(path))
    print(f"\n📂  Contents of {path}:")
    for item in items[:20]:          # Limit output to first 20 entries
        full = os.path.join(path, item)
        tag  = "[DIR] " if os.path.isdir(full) else "      "
        print(f"    {tag}{item}")
    if len(items) > 20:
        print(f"    … and {len(items) - 20} more items.")


if __name__ == "__main__":
    download_cti_data()