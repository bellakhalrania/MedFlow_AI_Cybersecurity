"""
Downloads the official MITRE ATT&CK Enterprise STIX 2.1 bundle from the
mitre/cti GitHub repository, if it isn't already present locally.
"""

import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config


def download_mitre_bundle(force: bool = False) -> Path:
    """Download enterprise-attack.json and return its local path."""
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)

    if config.MITRE_BUNDLE_PATH.exists() and not force:
        print(f"[skip] Bundle already present at {config.MITRE_BUNDLE_PATH}")
        return config.MITRE_BUNDLE_PATH

    print(f"[download] Fetching {config.MITRE_BUNDLE_URL}")
    req = urllib.request.Request(
        config.MITRE_BUNDLE_URL, headers={"User-Agent": "Mozilla/5.0"}
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = resp.read()

    config.MITRE_BUNDLE_PATH.write_bytes(data)
    print(f"[done] Wrote {len(data) / 1e6:.1f} MB to {config.MITRE_BUNDLE_PATH}")
    return config.MITRE_BUNDLE_PATH


def quick_sanity_check(path: Path) -> None:
    """Make sure the file is valid JSON and looks like a STIX bundle."""
    with open(path, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    assert bundle.get("type") == "bundle", "Not a STIX bundle"
    objects = bundle.get("objects", [])
    print(f"[check] {len(objects)} STIX objects loaded.")

    from collections import Counter
    counts = Counter(o["type"] for o in objects)
    for obj_type, count in counts.most_common():
        print(f"        {obj_type:30s} {count}")


if __name__ == "__main__":
    path = download_mitre_bundle()
    quick_sanity_check(path)
