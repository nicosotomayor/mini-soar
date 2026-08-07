import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.alert_triage import score_alert, escalate_priority


def _base_alert(ioc=None):
    return {
        "severity": "low",
        "asset_criticality": "low",
        "ioc": ioc,
    }


def test_score_alert_no_bonus_without_ioc():
    assert score_alert(_base_alert(ioc=None)) == 1


def test_score_alert_no_bonus_for_invalid_ioc():
    assert score_alert(_base_alert(ioc="no-es-un-ioc-valido")) == 1


def test_score_alert_bonus_for_valid_ioc():
    assert score_alert(_base_alert(ioc="8.8.8.8")) == 3


def test_escalate_priority_upgrades_on_critico():
    assert escalate_priority("P3", "CRITICO") == "P1"


def test_escalate_priority_upgrades_on_alto():
    assert escalate_priority("P4", "ALTO") == "P2"


def test_escalate_priority_never_downgrades_on_sin_datos():
    assert escalate_priority("P1", "SIN DATOS") == "P1"


def test_escalate_priority_keeps_priority_when_already_higher():
    assert escalate_priority("P1", "ALTO") == "P1"


def test_escalate_priority_keeps_priority_when_verdict_is_limpio():
    assert escalate_priority("P3", "LIMPIO") == "P3"
