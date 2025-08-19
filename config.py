import os

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
import os

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")

    # ---- DB: accepte "postgres://" de Render et le convertit en "postgresql://" pour SQLAlchemy
    _db_url = os.getenv("DATABASE_URL", "sqlite:///edh.db")
    if _db_url.startswith("postgres://"):
        _db_url = _db_url.replace("postgres://", "postgresql://", 1)
    SQLALCHEMY_DATABASE_URI = _db_url
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Mail
    MAIL_SERVER = os.getenv("MAIL_SERVER", "localhost")
    MAIL_PORT = int(os.getenv("MAIL_PORT", "25"))
    MAIL_USE_TLS = bool(int(os.getenv("MAIL_USE_TLS", "0")))
    MAIL_USE_SSL = bool(int(os.getenv("MAIL_USE_SSL", "0"))) if os.getenv("MAIL_USE_SSL") else False
    MAIL_USERNAME = os.getenv("MAIL_USERNAME")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER")

    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@example.com")

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Mail
    MAIL_SERVER = os.getenv("MAIL_SERVER", "localhost")
    MAIL_PORT = int(os.getenv("MAIL_PORT", "25"))
    MAIL_USE_TLS = bool(int(os.getenv("MAIL_USE_TLS", "0")))
    MAIL_USE_SSL = bool(int(os.getenv("MAIL_USE_SSL", "0"))) if os.getenv("MAIL_USE_SSL") else False
    MAIL_USERNAME = os.getenv("MAIL_USERNAME")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER")

    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@example.com")
