from intelligence.ioc_extractor import extract_iocs

def test_ioc_extractor_finds_ip():
    events = [{"event_id": "e1", "src_ip": "1.2.3.4", "process": "cmd.exe"}]
    iocs = extract_iocs(events)
    values = [i["value"] for i in iocs]
    assert "1.2.3.4" in values
