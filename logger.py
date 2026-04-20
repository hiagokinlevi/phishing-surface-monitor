import logging
from typing import Optional


_DEFAULT_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
_DEFAULT_DATEFMT = "%Y-%m-%d %H:%M:%S"


def get_logger(name: Optional[str] = None, level: int = logging.INFO) -> logging.Logger:
    """Return a configured logger with timestamped output.

    This helper ensures a consistent logging format across the project while
    keeping setup minimal. It defaults to INFO level and avoids adding
    duplicate stream handlers on repeated calls.
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(_DEFAULT_FORMAT, datefmt=_DEFAULT_DATEFMT)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    logger.setLevel(level)
    logger.propagate = False
    return logger
