"""Configurable identity for the isolated Linux BAS lab topology.

Defaults match the reviewed local stack, but group/network/paw/controller names
are settings-driven so a renamed lab does not hard-fail preflight.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hecate_runner.config import Settings


@dataclass(frozen=True)
class BasLabProfile:
    """Runtime identity the sensor and controller preflight must match."""

    agent_group: str = "hecate-local-lab"
    network: str = "hecate-bas-lab"
    paw: str = "hecate-local-sandbox"
    agent_server_url: str = "http://caldera:8888"
    controller_container: str = "caldera"

    def sandcat_cmd(self) -> list[str]:
        return [
            "-server",
            self.agent_server_url,
            "-group",
            self.agent_group,
            "-paw",
            self.paw,
        ]


def lab_profile_from_settings(settings: Settings) -> BasLabProfile:
    """Build a lab profile from Settings, falling back to reviewed defaults."""
    group = str(getattr(settings, "caldera_agent_group", "") or "").strip() or "hecate-local-lab"
    return BasLabProfile(
        agent_group=group,
        network=str(getattr(settings, "bas_lab_network", "") or "").strip() or "hecate-bas-lab",
        paw=str(getattr(settings, "bas_lab_paw", "") or "").strip() or "hecate-local-sandbox",
        agent_server_url=(
            str(getattr(settings, "bas_agent_server_url", "") or "").strip()
            or "http://caldera:8888"
        ),
        controller_container=(
            str(getattr(settings, "bas_caldera_container", "") or "").strip() or "caldera"
        ),
    )
