# config.py
import os

class Config:
    # ... tes autres configs (SECRET_KEY, SQLALCHEMY_DATABASE_URI, etc.) ...

    # Mail
    MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.getenv("MAIL_PORT", 587))          # 587 (TLS) ou 465 (SSL)
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "1") == "1"  # True si port 587
    MAIL_USE_SSL = os.getenv("MAIL_USE_SSL", "0") == "1"  # True si port 465
    MAIL_USERNAME = os.getenv("eric.rangergmail.com")            # ex: tonadresse@gmail.com
    MAIL_PASSWORD = os.getenv("spyz dwdn fhao ascg ")            # mot de passe d'app/provider
    MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER", os.getenv("MAIL_USERNAME"))
    MAIL_SUPPRESS_SEND = False
