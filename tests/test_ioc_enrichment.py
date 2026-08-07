import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.ioc_enrichment import (
    _is_valid_ip,
    _hash_algorithm,
    detect_ioc_type,
    score_verdict,
)


def test_valid_ipv4_is_accepted():
    assert _is_valid_ip("8.8.8.8") is True


def test_invalid_ipv4_octet_is_rejected():
    assert _is_valid_ip("999.999.999.999") is False


def test_valid_ipv6_is_accepted():
    assert _is_valid_ip("2001:4860:4860::8888") is True


def test_hash_algorithm_md5():
    assert _hash_algorithm("d41d8cd98f00b204e9800998ecf8427e") == "md5"


def test_hash_algorithm_sha1():
    assert _hash_algorithm("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"


def test_hash_algorithm_sha256():
    assert _hash_algorithm("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "sha256"


def test_hash_algorithm_rejects_wrong_length():
    assert _hash_algorithm("abcd1234") is None


def test_detect_ioc_type_ip():
    assert detect_ioc_type("1.2.3.4") == "ip"


def test_detect_ioc_type_domain():
    assert detect_ioc_type("malicious-domain.com") == "domain"


def test_detect_ioc_type_hash():
    assert detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "hash"


def test_detect_ioc_type_unknown_for_garbage():
    assert detect_ioc_type("no-es-un-ioc-valido") == "unknown"


def test_score_verdict_sin_datos_when_apis_fail():
    verdict, _color = score_verdict(None, None)
    assert verdict == "SIN DATOS"


def test_score_verdict_limpio_when_data_present_but_clean():
    verdict, _color = score_verdict({"malicious": 0, "suspicious": 0}, {"abuseConfidenceScore": 0})
    assert verdict == "LIMPIO"


def test_score_verdict_critico_with_high_detections():
    verdict, _color = score_verdict({"malicious": 10, "suspicious": 0}, None)
    assert verdict == "CRITICO"
