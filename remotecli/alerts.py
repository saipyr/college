import smtplib
from email.mime.text import MIMEText
import requests
import logging
from logging.handlers import SysLogHandler
from .config import SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, ALERT_EMAIL_TO, ALERT_WEBHOOK_URL, SIEM_SYSLOG_HOST, SIEM_SYSLOG_PORT
from .storage import add_alert

_syslog_logger = None

def _ensure_syslog():
    global _syslog_logger
    if _syslog_logger:
        return _syslog_logger
    logger = logging.getLogger("sehcs-syslog")
    logger.setLevel(logging.INFO)
    if SIEM_SYSLOG_HOST:
        handler = SysLogHandler(address=(SIEM_SYSLOG_HOST, SIEM_SYSLOG_PORT))
        logger.addHandler(handler)
    _syslog_logger = logger
    return logger

def _send_email(subject: str, body: str):
    if not (SMTP_HOST and ALERT_EMAIL_TO):
        return
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_USER or "sehcs@localhost"
    msg["To"] = ALERT_EMAIL_TO
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
        if SMTP_USER and SMTP_PASS:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(msg["From"], [ALERT_EMAIL_TO], msg.as_string())

def _send_webhook(payload: dict):
    if not ALERT_WEBHOOK_URL:
        return
    try:
        requests.post(ALERT_WEBHOOK_URL, json=payload, timeout=5)
    except Exception:
        pass

def _send_syslog(message: str):
    logger = _ensure_syslog()
    if logger.handlers:
        logger.info(message)

def emit_alert(level: str, message: str, device_id: str = None):
    add_alert(level=level, message=message, device_id=device_id)
    _send_email(f"[SEHCS] {level}", message)
    _send_webhook({"level": level, "message": message, "device_id": device_id})
    _send_syslog(f"{level} {message} device={device_id}")