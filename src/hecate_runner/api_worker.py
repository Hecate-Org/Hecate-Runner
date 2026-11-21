"""Private, allowlisted generation worker; stdout carries only a JSON response."""

from __future__ import annotations

import contextlib
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any


def generate(stage: str, arguments: dict[str, Any]) -> dict[str, Any]:
    from hecate_runner.hecate_client import (
        HecateClient,
        HypothesisResult,
        ResearchResult,
        SigmaResult,
    )

    client = HecateClient(Path(sys.executable), Path(os.environ["HECATE_WORKSPACE"]))
    result: ResearchResult | HypothesisResult | SigmaResult
    if stage == "research":
        result = client._research_new_local(**arguments)
    elif stage == "hypothesis":
        result = client._hypothesis_generator_local(**arguments)
    elif stage == "sigma":
        arguments = {**arguments, "out_dir": Path(arguments["out_dir"])}
        result = client._sigma_generator_local(**arguments)
    else:
        raise ValueError("Unsupported generation stage")
    return asdict(result)


def main() -> None:
    # Redirect file descriptors too: native providers and subprocesses can bypass
    # Python's redirect_stdout. Do not buffer unbounded provider diagnostics.
    with os.fdopen(os.dup(sys.stdout.fileno()), "w") as response_stream:
        with open(os.devnull, "w") as sink:
            os.dup2(sink.fileno(), 1)
            os.dup2(sink.fileno(), 2)
            with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
                try:
                    request = json.load(sys.stdin)
                    result = generate(request["stage"], request["arguments"])
                    # Serialize before committing the response; unsupported data
                    # cannot leave a partial success followed by an error envelope.
                    response = json.dumps(
                        {"version": 1, "ok": True, "result": result},
                        default=lambda value: str(value) if isinstance(value, Path) else _invalid(),
                        allow_nan=False,
                    )
                except Exception as exc:
                    usage = getattr(exc, "usage", None)
                    response = json.dumps(
                        {"version": 1, "ok": False, "usage": asdict(usage) if usage else None},
                        allow_nan=False,
                    )
        response_stream.write(response)


def _invalid() -> Any:
    raise TypeError("Unsupported worker result")


if __name__ == "__main__":
    main()
