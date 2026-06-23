import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from orchestrator import Orchestrator

BANNER = """
============================================================
  MITRE ATT&CK RAG / Red Team Intelligence Platform
  Agents: [redteam] [cti] [attribution] [detection] [auto]
  Type /quit to exit, /stats for DB stats, /sources to
  toggle showing retrieved source chunks.
============================================================
"""


def main():
    orch = Orchestrator()
    pinned_agent = None  # None == auto-routing
    show_sources = False

    print(BANNER)
    stats = orch.stats()
    if sum(stats.values()) == 0:
        print("[warning] All ChromaDB collections are empty. Run `python ingest.py` first.\n")
    else:
        print(f"[info] Collection sizes: {stats}\n")

    while True:
        try:
            user_input = input(f"({pinned_agent or 'auto'})> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not user_input:
            continue

        if user_input == "/quit":
            break
        elif user_input == "/stats":
            print(orch.stats())
            continue
        elif user_input == "/sources":
            show_sources = not show_sources
            print(f"[info] show_sources = {show_sources}")
            continue
        elif user_input.startswith("/agent"):
            parts = user_input.split()
            if len(parts) != 2 or parts[1] not in (
                "redteam", "cti", "attribution", "detection", "auto"
            ):
                print("Usage: /agent redteam|cti|attribution|detection|auto")
                continue
            pinned_agent = None if parts[1] == "auto" else parts[1]
            print(f"[info] Agent pinned to: {pinned_agent or 'auto-routing'}")
            continue

        result = orch.ask(user_input, agent_key=pinned_agent)

        print(f"\n[{result['agent']}]" + (" (BLOCKED)" if result["blocked"] else ""))
        print(result["answer"])

        if show_sources and result["sources"]:
            print("\n--- Retrieved sources ---")
            for s in result["sources"]:
                meta = s["metadata"]
                label = meta.get("name") or meta.get("attack_id") or "unknown"
                conf = f" conf={s['confidence']}" if "confidence" in s else ""
                print(f"  [{s['collection']}] {label} (dist={s['distance']}{conf})")
        print()


if __name__ == "__main__":
    main()
