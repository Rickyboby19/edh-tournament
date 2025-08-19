from itsdangerous import URLSafeSerializer
from flask import current_app

def make_token(data: dict) -> str:
    s = URLSafeSerializer(current_app.config["SECRET_KEY"], salt="confirm")
    return s.dumps(data)

def read_token(token: str) -> dict:
    s = URLSafeSerializer(current_app.config["SECRET_KEY"], salt="confirm")
    return s.loads(token)
