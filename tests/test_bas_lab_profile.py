"""Configurable BAS lab identity (group/network/paw/controller)."""

from __future__ import annotations

from hecate_runner.bas.lab_profile import BasLabProfile, lab_profile_from_settings
from hecate_runner.config import Settings


def test_lab_profile_defaults_match_reviewed_stack():
    profile = BasLabProfile()
    assert profile.agent_group == "hecate-local-lab"
    assert profile.network == "hecate-bas-lab"
    assert profile.paw == "hecate-local-sandbox"
    assert profile.agent_server_url == "http://caldera:8888"
    assert profile.controller_container == "caldera"
    assert profile.sandcat_cmd() == [
        "-server",
        "http://caldera:8888",
        "-group",
        "hecate-local-lab",
        "-paw",
        "hecate-local-sandbox",
    ]


def test_lab_profile_from_settings_overrides_identity():
    settings = Settings(
        _env_file=None,
        caldera_agent_group="custom-group",
        bas_lab_network="custom-net",
        bas_lab_paw="custom-paw",
        bas_agent_server_url="http://caldera.lab:8888",
        bas_caldera_container="caldera-ctrl",
    )
    profile = lab_profile_from_settings(settings)
    assert profile.agent_group == "custom-group"
    assert profile.network == "custom-net"
    assert profile.paw == "custom-paw"
    assert profile.agent_server_url == "http://caldera.lab:8888"
    assert profile.controller_container == "caldera-ctrl"
    assert profile.sandcat_cmd() == [
        "-server",
        "http://caldera.lab:8888",
        "-group",
        "custom-group",
        "-paw",
        "custom-paw",
    ]


def test_empty_settings_fields_fall_back_to_reviewed_defaults():
    settings = Settings(
        _env_file=None,
        caldera_agent_group="  ",
        bas_lab_network="",
        bas_lab_paw="",
        bas_agent_server_url="",
        bas_caldera_container="",
    )
    profile = lab_profile_from_settings(settings)
    assert profile == BasLabProfile()
