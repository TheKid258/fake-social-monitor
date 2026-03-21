"""
database.py
Gestão da base de dados SQLite.
Tabelas: logs, phone_numbers, feedback, blacklist
"""

import sqlite3
import json
import logging
from datetime import datetime

DB_NAME = "analysis.db"

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)


def get_connection() -> sqlite3.Connection:
    return sqlite3.connect(DB_NAME)


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            message           TEXT,
            risk_level        TEXT,
            risk_type         TEXT,
            score             INTEGER,
            reasons           TEXT,
            date              TEXT,
            link_results      TEXT,
            educational_alert TEXT,
            uppercase_ratio   REAL,
            exclamations      INTEGER,
            emojis            INTEGER,
            mixed_scripts     INTEGER,
            phone_number      TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS phone_numbers (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            phone_number    TEXT NOT NULL,
            risk_type       TEXT,
            risk_level      TEXT,
            report_count    INTEGER DEFAULT 1,
            first_seen      TEXT,
            last_seen       TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS feedback (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id      INTEGER,
            correct     INTEGER,
            comment     TEXT,
            date        TEXT,
            FOREIGN KEY (log_id) REFERENCES logs(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blacklist (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            phone_number TEXT UNIQUE NOT NULL,
            reason       TEXT,
            added_by     TEXT DEFAULT 'utilizador',
            date_added   TEXT
        )
    """)

    # Migrações
    cursor.execute("PRAGMA table_info(logs)")
    existing_columns = {col[1] for col in cursor.fetchall()}
    new_columns = {
        "link_results": "TEXT", "educational_alert": "TEXT",
        "uppercase_ratio": "REAL", "exclamations": "INTEGER",
        "emojis": "INTEGER", "mixed_scripts": "INTEGER",
        "phone_number": "TEXT",
    }
    for col_name, col_type in new_columns.items():
        if col_name not in existing_columns:
            cursor.execute(f"ALTER TABLE logs ADD COLUMN {col_name} {col_type}")

    conn.commit()
    conn.close()


def save_analysis(text: str, result: dict, phone_number: str = None):
    try:
        init_db()
        conn = get_connection()
        cursor = conn.cursor()
        meta = result.get("meta", {})

        cursor.execute("""
            INSERT INTO logs (
                message, risk_level, risk_type, score, reasons, date,
                link_results, educational_alert,
                uppercase_ratio, exclamations, emojis, mixed_scripts, phone_number
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            text,
            result.get("risk_level", "Desconhecido"),
            result.get("risk_type", "Desconhecido"),
            result.get("score", 0),
            ", ".join(result.get("reasons", [])),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            json.dumps(result.get("link_results", {})),
            result.get("educational_alert", ""),
            meta.get("uppercase_ratio", 0.0),
            meta.get("exclamations", 0),
            meta.get("emojis", 0),
            int(meta.get("mixed_scripts", False)),
            phone_number,
        ))

        log_id = cursor.lastrowid

        if phone_number and phone_number.strip():
            _update_phone_reputation(
                cursor, phone_number.strip(),
                result.get("risk_type", "Desconhecido"),
                result.get("risk_level", "Desconhecido"),
            )

        conn.commit()
        conn.close()
        return log_id

    except Exception as e:
        logger.error(f"Erro ao guardar análise: {e}")
        return None


def _update_phone_reputation(cursor, phone_number, risk_type, risk_level):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("SELECT id FROM phone_numbers WHERE phone_number = ?", (phone_number,))
    row = cursor.fetchone()
    if row:
        cursor.execute("""
            UPDATE phone_numbers
            SET report_count = report_count + 1, last_seen = ?, risk_type = ?, risk_level = ?
            WHERE phone_number = ?
        """, (now, risk_type, risk_level, phone_number))
    else:
        cursor.execute("""
            INSERT INTO phone_numbers (phone_number, risk_type, risk_level, report_count, first_seen, last_seen)
            VALUES (?, ?, ?, 1, ?, ?)
        """, (phone_number, risk_type, risk_level, now, now))


def save_feedback(log_id: int, correct: bool, comment: str = ""):
    try:
        init_db()
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO feedback (log_id, correct, comment, date)
            VALUES (?, ?, ?, ?)
        """, (log_id, int(correct), comment, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Erro ao guardar feedback: {e}")


def add_to_blacklist(phone_number: str, reason: str = ""):
    try:
        init_db()
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR IGNORE INTO blacklist (phone_number, reason, date_added)
            VALUES (?, ?, ?)
        """, (phone_number.strip(), reason, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Erro ao adicionar à blacklist: {e}")
        return False


def remove_from_blacklist(phone_number: str):
    try:
        init_db()
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM blacklist WHERE phone_number = ?", (phone_number.strip(),))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Erro ao remover da blacklist: {e}")
        return False


def is_blacklisted(phone_number: str) -> bool:
    try:
        init_db()
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM blacklist WHERE phone_number = ?", (phone_number.strip(),))
        result = cursor.fetchone()
        conn.close()
        return result is not None
    except Exception as e:
        logger.error(f"Erro ao verificar blacklist: {e}")
        return False


def get_blacklist() -> list:
    try:
        init_db()
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT phone_number, reason, added_by, date_added FROM blacklist ORDER BY date_added DESC")
        results = [
            {"phone_number": r[0], "reason": r[1], "added_by": r[2], "date_added": r[3]}
            for r in cursor.fetchall()
        ]
        conn.close()
        return results
    except Exception as e:
        logger.error(f"Erro ao obter blacklist: {e}")
        return []


def lookup_phone(phone_number: str) -> dict | None:
    try:
        init_db()
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM phone_numbers WHERE phone_number = ?", (phone_number.strip(),))
        rep = cursor.fetchone()
        if not rep:
            conn.close()
            return None

        rep_dict = {
            "phone_number": rep[1], "risk_type": rep[2], "risk_level": rep[3],
            "report_count": rep[4], "first_seen": rep[5], "last_seen": rep[6],
        }

        cursor.execute("""
            SELECT date, message, risk_level, risk_type, score FROM logs
            WHERE phone_number = ? ORDER BY date DESC LIMIT 20
        """, (phone_number.strip(),))

        messages = [
            {"date": r[0], "message": r[1], "risk_level": r[2], "risk_type": r[3], "score": r[4]}
            for r in cursor.fetchall()
        ]

        conn.close()
        return {"reputation": rep_dict, "messages": messages}

    except Exception as e:
        logger.error(f"Erro ao pesquisar número: {e}")
        return None


def get_top_suspicious_numbers(limit: int = 10) -> list:
    try:
        init_db()
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT phone_number, risk_type, risk_level, report_count, last_seen
            FROM phone_numbers ORDER BY report_count DESC LIMIT ?
        """, (limit,))
        results = [
            {"phone_number": r[0], "risk_type": r[1], "risk_level": r[2], "report_count": r[3], "last_seen": r[4]}
            for r in cursor.fetchall()
        ]
        conn.close()
        return results
    except Exception as e:
        logger.error(f"Erro ao obter números suspeitos: {e}")
        return []


def get_feedback_stats() -> dict:
    try:
        init_db()
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*), SUM(correct) FROM feedback")
        row = cursor.fetchone()
        conn.close()
        total = row[0] or 0
        correct = row[1] or 0
        return {
            "total": total,
            "correct": correct,
            "incorrect": total - correct,
            "accuracy": round((correct / total * 100), 1) if total > 0 else 0,
        }
    except Exception as e:
        logger.error(f"Erro ao obter stats de feedback: {e}")
        return {"total": 0, "correct": 0, "incorrect": 0, "accuracy": 0}
