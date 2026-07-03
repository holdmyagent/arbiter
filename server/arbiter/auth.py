import secrets

from fastapi import Header, HTTPException


def check_token(authorization: str | None, expected: str) -> None:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    if not secrets.compare_digest(authorization.removeprefix("Bearer "), expected):
        raise HTTPException(status_code=403, detail="invalid token")


def require_agent(cfg):
    def dep(authorization: str | None = Header(default=None)):
        check_token(authorization, cfg.auth.agent_token)
    return dep


def require_app(cfg):
    def dep(authorization: str | None = Header(default=None)):
        check_token(authorization, cfg.auth.app_token)
    return dep
