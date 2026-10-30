"""Minimal logging helpers used by the decryption core.

The full application has a much richer logging stack.  The standalone core
intentionally keeps console output quiet so command results stay valid JSON.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path


_CONFIGURED = False


def setup_logging(log_dir: str | Path | None = None) -> Path | None:
    global _CONFIGURED
    if not _CONFIGURED:
        level_name = str(os.environ.get("WCHAT_LOG_LEVEL", "WARNING")).upper()
        level = getattr(logging, level_name, logging.WARNING)
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        )
        root = logging.getLogger()
        root.setLevel(level)
        root.addHandler(handler)
        _CONFIGURED = True
    if log_dir is None:
        return None
    target = Path(log_dir).expanduser()
    target.mkdir(parents=True, exist_ok=True)
    return target


def get_logger(name: str) -> logging.Logger:
    setup_logging()
    return logging.getLogger(name)
