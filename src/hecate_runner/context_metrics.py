"""Payload estimates, explicitly separate from provider-reported prompt usage."""

import logging

log = logging.getLogger(__name__)


def measure_tokens(text: str, model_name: str | None = None) -> int | None:
    """Estimate a payload using a known tokenizer; None means unavailable.

    This excludes prompt templates, loaded context, and chat framing. Unknown
    models never silently use a different model's tokenizer.
    """
    if not text:
        return 0
    if not model_name:
        return None
    try:
        import tiktoken

        encoding = tiktoken.encoding_for_model(model_name)
        return len(encoding.encode(text, disallowed_special=()))
    except (ImportError, KeyError):
        return None
    except Exception as exc:
        log.debug("Payload token estimate unavailable for %s (%s)", model_name, exc)
        return None


def log_payload_metrics(stage: str, text: str, model_name: str | None = None) -> None:
    """Log input size without presenting the payload as a complete model prompt."""
    estimate = measure_tokens(text, model_name)
    log.info(
        "LLM payload estimate: stage=%s model=%s chars=%d payload_tokens=%s "
        "scope=payload_only; excludes Core-added instructions/context and chat framing",
        stage,
        model_name or "workspace_default",
        len(text),
        estimate if estimate is not None else "unavailable",
    )
