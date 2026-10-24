"""LLM 配置 API（阶段0）"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models import Config
from app.schemas import ConfigOut, ConfigUpdate

router = APIRouter(prefix="/api/config", tags=["config"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def mask_api_key(key: str) -> str:
    """api_key 脱敏：sk-***xxxx"""
    if not key:
        return ""
    if len(key) <= 4:
        return "sk-***" + key
    return "sk-***" + key[-4:]


def _get_value(db: Session, key: str) -> str:
    row = db.get(Config, key)
    return row.value if row else ""


@router.get("", response_model=ConfigOut)
def get_config(db: Session = Depends(get_db)):
    return ConfigOut(
        base_url=_get_value(db, "base_url"),
        api_key=mask_api_key(_get_value(db, "api_key")),
        model=_get_value(db, "model"),
    )


@router.post("")
def update_config(data: ConfigUpdate, db: Session = Depends(get_db)):
    """更新配置；空值不覆盖已有配置；脱敏值不可写回。"""
    values = {"base_url": data.base_url, "api_key": data.api_key, "model": data.model}
    for k, v in values.items():
        if not v:
            continue
        if v.startswith("sk-***"):
            continue  # 脱敏值不可写回数据库
        row = db.get(Config, k)
        if row is None:
            db.add(Config(key=k, value=v))
        else:
            row.value = v
    db.commit()
    return {"ok": True}
