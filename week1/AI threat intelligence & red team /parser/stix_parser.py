import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config


def _external_id(stix_obj: Dict[str, Any]) -> Optional[str]:
    """Pull the human-readable ATT&CK ID (T1003, S0154, G0016...) out of
    external_references. Returns None for objects without one (e.g. some
    relationships, deprecated objects)."""
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") in ("mitre-attack", "mitre-ics-attack", "mitre-mobile-attack"):
            return ref.get("external_id")
    return None


def _is_usable(stix_obj: Dict[str, Any]) -> bool:
    """Filter out revoked/deprecated objects -- these are not part of the
    current ATT&CK knowledge base and must never be served to users."""
    if stix_obj.get("revoked"):
        return False
    if stix_obj.get("x_mitre_deprecated"):
        return False
    return True


class StixParser:
    def __init__(self, bundle_path: Path = config.MITRE_BUNDLE_PATH):
        self.bundle_path = bundle_path
        self.objects: List[Dict[str, Any]] = []
        self.by_id: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Step 1-2: load bundle + build lookup table
    # ------------------------------------------------------------------
    def load(self) -> "StixParser":
        with open(self.bundle_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
        self.objects = bundle["objects"]
        self.by_id = {o["id"]: o for o in self.objects if "id" in o}
        print(f"[parser] Loaded {len(self.objects)} STIX objects "
              f"({len(self.by_id)} indexed by id).")
        return self

    def _name_of(self, stix_id: str) -> str:
        obj = self.by_id.get(stix_id)
        if not obj:
            return "Unknown"
        return obj.get("name", "Unknown")

    # ------------------------------------------------------------------
    # Dataset 1: Techniques -> attack_db
    # ------------------------------------------------------------------
    def build_techniques(self) -> List[Dict[str, Any]]:
        records = []
        for obj in self.objects:
            if obj["type"] != "attack-pattern" or not _is_usable(obj):
                continue

            attack_id = _external_id(obj)
            if not attack_id:
                continue  # not a real published technique

            name = obj.get("name", "Unnamed Technique")
            description = obj.get("description", "").strip()
            is_subtechnique = obj.get("x_mitre_is_subtechnique", False)
            platforms = obj.get("x_mitre_platforms", [])
            tactics = [
                phase["phase_name"]
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            ]
            data_sources = obj.get("x_mitre_data_sources", [])

            doc_text = (
                f"Technique {attack_id}: {name}\n"
                f"Tactics: {', '.join(tactics) if tactics else 'N/A'}\n"
                f"Platforms: {', '.join(platforms) if platforms else 'N/A'}\n"
                f"Description: {description}"
            )

            records.append({
                "id": f"technique_{attack_id}",
                "document": doc_text,
                "metadata": {
                    "attack_id": attack_id,
                    "name": name,
                    "type": "technique",
                    "is_subtechnique": bool(is_subtechnique),
                    "tactics": ", ".join(tactics),
                    "platforms": ", ".join(platforms),
                    "data_sources": ", ".join(data_sources)[:500],
                    "stix_id": obj["id"],
                },
            })

        print(f"[parser] Built {len(records)} technique records -> attack_db")
        return records

    # ------------------------------------------------------------------
    # Dataset 2: Procedures -> redteam_db  (relationship_type == "uses")
    # ------------------------------------------------------------------
    def build_procedures(self) -> List[Dict[str, Any]]:
        records = []
        for obj in self.objects:
            if obj["type"] != "relationship" or obj.get("relationship_type") != "uses":
                continue
            if not _is_usable(obj):
                continue

            src = self.by_id.get(obj.get("source_ref", ""))
            tgt = self.by_id.get(obj.get("target_ref", ""))
            if not src or not tgt:
                continue

            # Only keep procedures where the target is an ATT&CK technique --
            # that's what makes this "redteam_db" rather than generic relations.
            if tgt.get("type") != "attack-pattern":
                continue

            src_name = src.get("name", "Unknown")
            src_type = src.get("type", "unknown")
            tgt_id = _external_id(tgt) or "UNKNOWN"
            tgt_name = tgt.get("name", "Unknown")
            description = obj.get("description", "").strip()

            doc_text = (
                f"{src_name} ({src_type}) uses {tgt_name} ({tgt_id}).\n"
                f"Procedure detail: {description if description else 'No additional detail provided.'}"
            )

            records.append({
                "id": f"procedure_{obj['id'].split('--')[-1]}",
                "document": doc_text,
                "metadata": {
                    "source_name": src_name,
                    "source_type": src_type,
                    "target_attack_id": tgt_id,
                    "target_name": tgt_name,
                    "type": "procedure",
                    "stix_id": obj["id"],
                },
            })

        print(f"[parser] Built {len(records)} procedure records -> redteam_db")
        return records

    # ------------------------------------------------------------------
    # Dataset 3: Actors and Tools -> actor_db
    # ------------------------------------------------------------------
    def build_actors_tools(self) -> List[Dict[str, Any]]:
        records = []
        type_map = {
            "intrusion-set": "threat_actor",
            "malware": "malware",
            "tool": "tool",
        }
        for obj in self.objects:
            if obj["type"] not in type_map or not _is_usable(obj):
                continue

            ext_id = _external_id(obj)
            name = obj.get("name", "Unnamed")
            description = obj.get("description", "").strip()
            aliases = obj.get("aliases", []) or obj.get("x_mitre_aliases", [])

            doc_text = (
                f"{type_map[obj['type']].replace('_', ' ').title()}: {name} "
                f"({ext_id or 'no ATT&CK ID'})\n"
                f"Aliases: {', '.join(aliases) if aliases else 'None known'}\n"
                f"Description: {description}"
            )

            records.append({
                "id": f"entity_{obj['id'].split('--')[-1]}",
                "document": doc_text,
                "metadata": {
                    "attack_id": ext_id or "",
                    "name": name,
                    "entity_type": type_map[obj["type"]],
                    "aliases": ", ".join(aliases)[:500],
                    "stix_id": obj["id"],
                },
            })

        print(f"[parser] Built {len(records)} actor/tool/malware records -> actor_db")
        return records

    # ------------------------------------------------------------------
    # Dataset 4: Detection Knowledge -> detection_db
    # ------------------------------------------------------------------
    def build_detection_knowledge(self) -> List[Dict[str, Any]]:
        records = []
        detection_types = {
            "course-of-action": "mitigation",
            "x-mitre-analytic": "analytic",
            "x-mitre-detection-strategy": "detection_strategy",
        }
        for obj in self.objects:
            if obj["type"] not in detection_types or not _is_usable(obj):
                continue

            ext_id = _external_id(obj)
            name = obj.get("name", "Unnamed")
            description = obj.get("description", "").strip()
            log_sources = obj.get("x_mitre_log_source_references", [])

            doc_text = (
                f"{detection_types[obj['type']].replace('_', ' ').title()}: {name} "
                f"({ext_id or 'no ID'})\n"
                f"Description: {description}"
            )
            if log_sources:
                doc_text += f"\nReferenced log sources: {len(log_sources)} source(s)."

            records.append({
                "id": f"detect_{obj['id'].split('--')[-1]}",
                "document": doc_text,
                "metadata": {
                    "attack_id": ext_id or "",
                    "name": name,
                    "detection_type": detection_types[obj["type"]],
                    "stix_id": obj["id"],
                },
            })

        print(f"[parser] Built {len(records)} detection-knowledge records -> detection_db")
        return records

    # ------------------------------------------------------------------
    def build_all(self) -> Dict[str, List[Dict[str, Any]]]:
        if not self.objects:
            self.load()
        return {
            config.COLLECTION_ATTACK: self.build_techniques(),
            config.COLLECTION_REDTEAM: self.build_procedures(),
            config.COLLECTION_ACTOR: self.build_actors_tools(),
            config.COLLECTION_DETECTION: self.build_detection_knowledge(),
        }


def save_datasets(datasets: Dict[str, List[Dict[str, Any]]]) -> None:
    config.PARSED_DATASETS_DIR.mkdir(parents=True, exist_ok=True)
    for name, records in datasets.items():
        out_path = config.PARSED_DATASETS_DIR / f"{name}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2)
        print(f"[save] {len(records):5d} records -> {out_path}")


if __name__ == "__main__":
    parser = StixParser().load()
    datasets = parser.build_all()
    save_datasets(datasets)
