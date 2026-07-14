import re
from typing import List, Dict

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")

# Extensions that look like a TLD to DOMAIN_RE but are actually filenames
NON_TLD_EXTENSIONS = {
    "exe", "dll", "bat", "cmd", "ps1", "sys", "tmp", "log",
    "txt", "doc", "docx", "xls", "xlsx", "pdf", "zip", "rar",
    "jpg", "jpeg", "png", "gif", "bin", "dat", "ini", "cfg",
    "py", "sh", "bak",
}


def extract_iocs(events: List[Dict]) -> List[Dict]:
    seen = set()
    iocs = []
    for event in events:
        blob = " ".join(str(v) for v in event.values() if v)

        for ip in IP_RE.findall(blob):
            _add(iocs, seen, ip, "ip", event)

        for h in SHA256_RE.findall(blob) + SHA1_RE.findall(blob) + MD5_RE.findall(blob):
            _add(iocs, seen, h, "hash", event)

        for url in URL_RE.findall(blob):
            _add(iocs, seen, url, "url", event)

        for domain in DOMAIN_RE.findall(blob):
            if domain in seen:
                continue
            if IP_RE.match(domain):
                continue
            ext = domain.rsplit(".", 1)[-1].lower()
            if ext in NON_TLD_EXTENSIONS:
                continue
            _add(iocs, seen, domain, "domain", event)

    return iocs


def _add(iocs: list, seen: set, value: str, ioc_type: str, event: Dict):
    if value in seen:
        return
    seen.add(value)
    iocs.append(
        {
            "value": value,
            "ioc_type": ioc_type,
            "source_event_id": event.get("event_id"),
        }
    )