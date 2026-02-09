"""Test action.yml has all required inputs."""
import yaml
import pytest


def test_action_yml_valid():
    with open("action.yml") as f:
        action = yaml.safe_load(f)
    assert "inputs" in action
    assert "runs" in action


def test_all_feature_inputs_exist():
    with open("action.yml") as f:
        action = yaml.safe_load(f)
    inputs = action["inputs"]
    required_inputs = [
        "enable-fuzzing", "enable-runtime-security", "enable-dast",
        "dast-target-url", "enable-supply-chain", "enable-threat-intel",
        "enable-remediation", "enable-regression-testing", "enable-iris",
        "enable-multi-agent", "enable-spontaneous-discovery",
        "enable-collaborative-reasoning", "fuzzing-duration",
        "runtime-monitoring-duration", "severity-filter",
    ]
    for inp in required_inputs:
        assert inp in inputs, f"Missing input: {inp}"


def test_inputs_have_descriptions():
    with open("action.yml") as f:
        action = yaml.safe_load(f)
    for name, config in action["inputs"].items():
        assert "description" in config, f"Input '{name}' missing description"


def test_feature_inputs_have_defaults():
    with open("action.yml") as f:
        action = yaml.safe_load(f)
    for name, config in action["inputs"].items():
        if name.startswith("enable-"):
            assert "default" in config, f"Feature input '{name}' missing default"
