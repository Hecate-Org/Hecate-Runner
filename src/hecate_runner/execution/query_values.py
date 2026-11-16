"""Typed, bounded literals for automatic queries built from untrusted telemetry."""

from __future__ import annotations

import ipaddress
import json
import re


def entity(value: str) -> str:
    if not isinstance(value, str) or len(value) > 512:
        raise ValueError("Invalid pivot entity")
    if any(ord(char) < 32 or 127 <= ord(char) <= 159 or char in "|;\x60{}[]*?" for char in value):
        raise ValueError("Pivot entity contains a control character or query operator")
    return value


def host(value: str) -> str:
    entity(value)
    if value and (len(value) > 253 or not re.fullmatch(r"[A-Za-z0-9_.:-]+", value)):
        raise ValueError("Invalid pivot host")
    return value


def address(value: str) -> str:
    if not value:
        return ""
    entity(value)
    return str(ipaddress.ip_address(value))


def domain(value: str) -> str:
    if not value:
        return ""
    entity(value)
    clean = value.strip().lower().rstrip(".")
    if len(clean) > 253 or not re.fullmatch(r"[a-z0-9_.-]+", clean):
        raise ValueError("Invalid pivot domain")
    return clean


def basename(value: str) -> str:
    result = entity(value).rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if value and not result:
        raise ValueError("Pivot process has no basename")
    return result


def username(value: str) -> str:
    result = entity(value).split("@")[0].split("\\")[-1]
    if value and not result:
        raise ValueError("Pivot user has no account name")
    return result


def quoted(value: str, dialect: str, *, prefix: str = "", suffix: str = "") -> str:
    value = prefix + entity(value) + suffix
    if dialect in {"sql", "snowflake"}:
        return "'" + value.replace("\\", "\\\\").replace("'", "''") + "'"
    return json.dumps(value, ensure_ascii=False)
