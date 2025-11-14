import logging
from logging.handlers import RotatingFileHandler
from .config import LOG_PATH, ensure_app_dirs

def setup_logging():
    ensure_app_dirs()
    logger = logging.getLogger("remotecli")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = RotatingFileHandler(LOG_PATH, maxBytes=1_000_000, backupCount=3)
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger