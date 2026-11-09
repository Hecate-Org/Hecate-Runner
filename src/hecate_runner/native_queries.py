"""Native artifact materialization, compatible with older Core installations."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast


def write_query_if_changed(path: Path, query: str) -> bool:
    try:
        from hecate_agent.core.sigma_transpiler import write_query_if_changed as write
    except ImportError:
        # Older Core still converts correctly; retain no-op writes in Runner.
        content = query.strip() + "\n"
        try:
            if path.read_text(encoding="utf-8") == content:
                return False
        except (FileNotFoundError, UnicodeError):
            pass
        path.write_text(content, encoding="utf-8")
        return True
    return cast(bool, write(path, query))


def transpile_and_write_native(rule_path: Path, rule_yaml: str) -> dict[str, Any]:
    from hecate_agent.api import transpile_sigma_rule

    results = cast(dict[str, Any], transpile_sigma_rule(rule_yaml))
    for result in results.values():
        if getattr(result, "success", False) and getattr(result, "query", None):
            write_query_if_changed(rule_path.with_suffix(result.file_extension), result.query)
    return results
