# -*- coding: utf-8 -*-
"""阶段 7：Config 敏感值静态加密（AES-256-GCM）。
主密钥优先取 ISEECODE_MASTER_KEY（64 位 hex 或 base64url 32 字节），
否则使用 data/master.key（首次自动生成，0600）。加密失败/依赖缺失时降级为明文并告警。"""
import base64
import logging
import os
import re
from functools import lru_cache

from app.config import DATA_DIR
from app.models import Config

logger = logging.getLogger("secrets")

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    AVAILABLE = True
except Exception:  # pragma: no cover - 依赖缺失时走降级
    AESGCM = None
    AVAILABLE = False

PREFIX = "enc:v1:"
AAD = b"iseecode-config-v1"
SECRET_KEYS = ("api_key", "night_api_key", "intel_webhook_url")


def is_encrypted(value: str) -> bool:
    return bool(value) and str(value).startswith(PREFIX)


def _decode_master(raw: str) -> bytes | None:
    raw = (raw or "").strip()
    if not raw:
        return None
    if re.fullmatch(r"[0-9a-fA-F]{64}", raw):
        return bytes.fromhex(raw)
    try:
        data = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        return data if len(data) == 32 else None
    except Exception:
        return None


@lru_cache(maxsize=1)
def master_key() -> bytes:
    env = _decode_master(os.environ.get("ISEECODE_MASTER_KEY", ""))
    if env:
        return env
    path = DATA_DIR / "master.key"
    try:
        if path.is_file():
            raw = path.read_bytes()
            if len(raw) != 32:
                raise ValueError("master.key 长度不是 32 字节")
            return raw
        raw = os.urandom(32)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
        logger.warning("已生成 data/master.key，请与数据库分开备份；丢失将无法解密已保存的密钥")
        return raw
    except Exception as e:
        logger.error(f"master.key 不可用: {e}；敏感值继续以明文保存")
        raise


def encrypt(value: str) -> str:
    if not value or is_encrypted(value) or not AVAILABLE:
        return value
    try:
        nonce = os.urandom(12)
        ct = AESGCM(master_key()).encrypt(nonce, str(value).encode(), AAD)
        return PREFIX + base64.urlsafe_b64encode(nonce + ct).decode()
    except Exception as e:
        logger.error(f"加密失败，保留明文: {e}")
        return value


def decrypt(value: str) -> str:
    if not value or not is_encrypted(value):
        return value
    if not AVAILABLE:
        logger.error("检测到加密配置但 cryptography 不可用，无法解密")
        return ""
    try:
        raw = base64.urlsafe_b64decode(str(value)[len(PREFIX):])
        nonce, ct = raw[:12], raw[12:]
        return AESGCM(master_key()).decrypt(nonce, ct, AAD).decode()
    except Exception as e:
        logger.error(f"解密失败（主密钥不匹配或数据损坏）: {e}")
        return ""


def get_secret(db, key: str, default: str = "") -> str:
    row = db.get(Config, key) if db is not None else None
    return decrypt(row.value) if row else default


def set_secret(db, key: str, value: str) -> None:
    row = db.get(Config, key)
    stored = encrypt(value)
    if row is None:
        db.add(Config(key=key, value=stored))
    else:
        row.value = stored


def migrate_plaintext(db) -> int:
    """启动时把历史明文敏感值就地加密；幂等，失败不阻断启动。"""
    if not AVAILABLE:
        logger.warning("cryptography 未安装：Config 敏感值保持明文（pip install cryptography 后重启生效）")
        return 0
    changed = 0
    for key in SECRET_KEYS:
        row = db.get(Config, key)
        if row is None or not row.value or is_encrypted(row.value):
            continue
        enc = encrypt(row.value)
        if enc != row.value:
            row.value = enc
            changed += 1
    if changed:
        db.commit()
        logger.info(f"Config 敏感值已加密 {changed} 项")
    return changed
