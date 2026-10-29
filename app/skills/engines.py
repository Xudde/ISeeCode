# -*- coding: utf-8 -*-
"""阶段 7 v5：Engine 协议/注册表 + 自定义 Semgrep 规则包目录。
不自动执行 data/engines 下的 Python；扩展引擎需在代码中 register(EngineSpec(...))，
自定义静态规则放到 data/rules/*.yaml，由 semgrep 校验后加载。"""
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

BASE_DIR = Path(__file__).resolve().parents[2]
CUSTOM_RULES_DIR = Path(os.environ.get("AUDIT_RULES_DIR", str(BASE_DIR / "data" / "rules")))
MAX_CUSTOM_RULES = int(os.environ.get("AUDIT_MAX_CUSTOM_RULES", "50"))


@dataclass(frozen=True)
class EngineContext:
    workspace: str
    log_fn: Callable
    settings: dict
    task_name: str = ""


@dataclass(frozen=True)
class EngineSpec:
    key: str
    name: str
    run: Callable[[EngineContext], list[dict]]
    order: int = 100
    setting_key: str | None = None
    requires_docker: bool = False
    description: str = ""


_REGISTRY: dict[str, EngineSpec] = {}


def register(spec: EngineSpec) -> EngineSpec:
    _REGISTRY[spec.key] = spec
    return spec


def all_specs() -> list[EngineSpec]:
    return sorted(_REGISTRY.values(), key=lambda s: (s.order, s.key))


def custom_rule_files() -> list[Path]:
    try:
        files = list(CUSTOM_RULES_DIR.glob("*.yaml")) + list(CUSTOM_RULES_DIR.glob("*.yml"))
    except OSError:
        return []
    return sorted((p for p in files if p.is_file()), key=lambda p: p.name)[:MAX_CUSTOM_RULES]


def rule_pack_info() -> list[dict]:
    out = []
    for p in custom_rule_files():
        try:
            size = p.stat().st_size
        except OSError:
            size = 0
        out.append({"name": p.name, "path": str(p), "size": size})
    return out
