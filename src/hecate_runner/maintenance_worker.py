"""Private entry point: one maintenance batch, supervised by the scheduler."""

from __future__ import annotations

import logging
import sys

from hecate_agent.core.workspace import load_workspace_env

from hecate_runner.api_calls import install_api_call_recorder
from hecate_runner.config import Settings
from hecate_runner.maintenance import run_job


def main() -> None:
    load_workspace_env()
    settings = Settings()
    logging.basicConfig(
        level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    install_api_call_recorder(settings.api_calls_file)
    run_job(settings, sys.argv[1])


if __name__ == "__main__":
    main()
