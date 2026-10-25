"""LLM 配置 API（阶段0）+ Agent 引擎设置（运行时动态可调）"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.agent_settings import AGENT_SETTING_DEFAULTS, SETTING_LABELS, agent_settings
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
    st = agent_settings(db)
    return ConfigOut(
        base_url=_get_value(db, "base_url"),
        api_key=mask_api_key(_get_value(db, "api_key")),
        model=_get_value(db, "model"),
        **{k: str(st[k]) for k in AGENT_SETTING_DEFAULTS},
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
    # Agent 引擎设置：显式传入（非 None）才保存
    for k in AGENT_SETTING_DEFAULTS:
        v = getattr(data, k, None)
        if v is None:
            continue
        if not isinstance(v, int) or v < 1:
            continue  # 非法值（非正整数）忽略
        row = db.get(Config, k)
        if row is None:
            db.add(Config(key=k, value=str(v)))
        else:
            row.value = str(v)
    db.commit()
    return {"ok": True}
