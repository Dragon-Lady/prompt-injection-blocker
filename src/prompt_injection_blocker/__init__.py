"""Read-only scanner for prompt-injection and LLM anti-analysis text."""

__version__ = "0.1.4"

from .scanner import RULES, scan_target, scan_text

__all__ = ["RULES", "scan_target", "scan_text", "__version__"]
