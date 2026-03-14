"""Central logging for BOLA AI."""

import logging
import sys

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


def setup_logging(level: str = "INFO") -> logging.Logger:
    """Configure root logger for bola_ai and return the module logger."""
    root = logging.getLogger("bola_ai")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    if not root.handlers:
        h = logging.StreamHandler(sys.stderr)
        h.setFormatter(logging.Formatter(LOG_FORMAT))
        root.addHandler(h)
    return root


def get_logger(name: str) -> logging.Logger:
    """Return a logger for the given module (e.g. 'bola_ai.api')."""
    return logging.getLogger("bola_ai." + name)
