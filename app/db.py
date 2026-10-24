"""SQLAlchemy 引擎与会话"""
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import DB_URL

engine = create_engine(
    DB_URL,
    connect_args={"check_same_thread": False},
)

# SQLite 启用 WAL 模式：允许读写并发，降低 LLM 长调用期间的锁冲突
import sqlite3  # noqa: E402
from sqlalchemy import event  # noqa: E402


@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def init_db() -> None:
    from app import models  # noqa: F401

    Base.metadata.create_all(engine)
    _migrate()


def _migrate() -> None:
    """轻量列迁移：旧库缺新列时补齐（SQLite ALTER TABLE ADD COLUMN）"""
    import logging
    new_cols = {
        "vulnerabilities": [
            ("agent_status", "VARCHAR(16)"),
            ("agent_evidence", "TEXT"),
            ("agent_confidence", "VARCHAR(8)"),
            ("agent_reason", "TEXT"),
            ("analyzed_at", "DATETIME"),
        ],
        "tasks": [
            ("file_hash", "VARCHAR(64) DEFAULT ''"),
            ("upload_path", "VARCHAR(512) DEFAULT ''"),
            ("cancel_requested", "BOOLEAN DEFAULT 0"),
        ],
    }
    with engine.connect() as conn:
        for table, cols in new_cols.items():
            existing = {row[1] for row in conn.exec_driver_sql(f"PRAGMA table_info({table})")}
            for name, ddl in cols:
                if name not in existing:
                    try:
                        conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
                        logging.getLogger("db").info(f"迁移：{table} 增加 {name}")
                    except Exception as e:
                        logging.getLogger("db").warning(f"迁移 {table}.{name} 失败: {e}")
        conn.commit()
