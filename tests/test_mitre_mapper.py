import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.mitre_mapper import get_techniques, ATTACK_MAP, DEFAULT_TECHNIQUE


def test_every_technique_has_confidence_and_evidence():
    for techniques in ATTACK_MAP.values():
        for tech in techniques:
            assert "confidence" in tech
            assert "evidence" in tech
            assert tech["confidence"] in ("high", "medium", "low", "n/a")


def test_known_alert_type_returns_mapped_techniques():
    techniques = get_techniques("Brute Force SSH")
    assert techniques != DEFAULT_TECHNIQUE
    assert any(t["id"] == "T1110" for t in techniques)


def test_malware_detected_process_injection_has_low_confidence():
    techniques = get_techniques("Malware Detected")
    injection = next((t for t in techniques if t["id"] == "T1055"), None)
    assert injection is not None
    assert injection["confidence"] == "low"


def test_unknown_alert_type_returns_default_technique():
    assert get_techniques("Alerta Que No Existe") == DEFAULT_TECHNIQUE
