from pathlib import Path
import os

APP_DIR = Path.home() / ".remotecli"
DB_PATH = APP_DIR / "remotecli.db"
KEY_PATH = APP_DIR / "secret.key"
LOG_PATH = APP_DIR / "remotecli.log"

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO")
ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL")
SIEM_SYSLOG_HOST = os.getenv("SIEM_SYSLOG_HOST")
SIEM_SYSLOG_PORT = int(os.getenv("SIEM_SYSLOG_PORT", "514"))

def ensure_app_dirs():
    APP_DIR.mkdir(parents=True, exist_ok=True)
    if KEY_PATH.exists():
        KEY_PATH.chmod(0o600)
    if LOG_PATH.exists():
        LOG_PATH.chmod(0o600)