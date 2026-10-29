# -*- coding: utf-8 -*-
"""阶段 7 v5：Engine 注册表与自定义规则包（只读）。"""
import shutil

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.agent_settings import agent_settings
from app.skills import giants  # noqa: F401  触发内置 EngineSpec 注册
from app.skills.engines import CUSTOM_RULES_DIR, all_specs, rule_pack_info
from app.routes.api_config import get_db

router = APIRouter(prefix="/api/engines", tags=["engines"])


@router.get("")
def list_engines(db: Session = Depends(get_db)):
    st = agent_settings(db)
    engines = []
    for s in all_specs():
        engines.append({
            "key": s.key, "name": s.name, "order": s.order,
            "setting_key": s.setting_key, "requires_docker": s.requires_docker,
            "description": s.description,
            "enabled": bool(st.get(s.setting_key, 1)) if s.setting_key else True,
        })
    return {
        "engines": engines,
        "docker": bool(shutil.which("docker")),
        "custom_rules_dir": str(CUSTOM_RULES_DIR),
        "custom_rules": rule_pack_info(),
    }
