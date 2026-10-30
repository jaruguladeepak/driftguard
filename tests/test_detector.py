import pytest

from driftguard.detector import detect_drift, load_config
from driftguard.policies import evaluate_findings, should_block


def test_detects_changed_setting():
    expected = {"app": {"port": 8000}}
    actual = {"app": {"port": 9000}}

    differences = detect_drift(expected, actual)

    assert len(differences) == 1
    assert differences[0]["setting"] == "app.port"
    assert differences[0]["expected"] == 8000
    assert differences[0]["actual"] == 9000


def test_detects_added_setting():
    expected = {"app": {"port": 8000}}
    actual = {"app": {"port": 8000, "debug": True}}

    differences = detect_drift(expected, actual)

    assert len(differences) == 1
    assert differences[0]["change"] == "added"


def test_detects_removed_setting():
    expected = {"app": {"port": 8000, "debug": False}}
    actual = {"app": {"port": 8000}}

    differences = detect_drift(expected, actual)

    assert len(differences) == 1
    assert differences[0]["change"] == "removed"


def test_critical_finding_blocks_deployment():
    differences = detect_drift(
        {"app": {"debug": False}},
        {"app": {"debug": True}},
    )

    findings = evaluate_findings(differences)

    assert findings[0]["severity"] == "CRITICAL"
    assert should_block(findings)


def test_empty_configurations_have_no_drift():
    assert detect_drift({}, {}) == []


def test_nested_configuration_addition():
    expected = {"app": {"port": 8000}}
    actual = {
        "app": {
            "port": 8000,
            "logging": {"level": "debug"},
        }
    }

    differences = detect_drift(expected, actual)

    assert len(differences) == 1
    assert differences[0]["setting"] == "app.logging"
    assert differences[0]["change"] == "added"


def test_removed_https_setting_is_critical():
    differences = detect_drift(
        {"security": {"https_required": True}},
        {"security": {}},
    )

    findings = evaluate_findings(differences)

    assert findings[0]["severity"] == "CRITICAL"
    assert should_block(findings)


def test_invalid_yaml_shape_is_rejected(tmp_path):
    config_file = tmp_path / "invalid.yaml"
    config_file.write_text("- item1\n- item2\n", encoding="utf-8")

    with pytest.raises(ValueError):
        load_config(config_file)


def test_missing_config_file_raises_error(tmp_path):
    missing_file = tmp_path / "missing.yaml"

    with pytest.raises(FileNotFoundError):
        load_config(missing_file)
