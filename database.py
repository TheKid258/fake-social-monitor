"""
database.py
Gestão de base de dados dual:
  - SQLite (local, rápido, temporário no Streamlit Cloud)
  - Supabase (PostgreSQL na cloud, permanente)
Todas as escritas vão para os dois.
Todas as leituras tentam primeiro o Supabase; se falhar usa o SQLite.
"""

import sqlite3
import json
import logging
import os
from datetime import datetime

logger = logging.getLogger(__name__)

DB_NAME = "analysis.db"

# ============================================================
# CLIENTE SUPABASE
# ============================================================

def _get_supabase():
    """Devolve cliente Supabase ou None se não configurado."""
    url = os.getenv("SUPABASE_URL", "")
    key = os.getenv("SUPABASE_KEY", "")
    if not url or not key:
        return None
    try:
        from supabase import create_client
        return create_client(url, key)
    except Exception as e:
        logger.error(f"Erro ao criar cliente Supabase: {e}")
        return None


# ============================================================
# SQLITE — INICIALIZAÇÃO
# ============================================================

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
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            phone_number TEXT NOT NULL,
            risk_type    TEXT,
            risk_level   TEXT,
            report_count INTEGER DEFAULT 1,
            first_seen   TEXT,
            last_seen    TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS feedback (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id   INTEGER,
            correct  INTEGER,
            comment  TEXT,
            date     TEXT,
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
    existing = {col[1] for col in cursor.fetchall()}
    for col, typ in {
        "link_results": "TEXT", "educational_alert": "TEXT",
        "uppercase_ratio": "REAL", "exclamations": "INTEGER",
        "emojis": "INTEGER", "mixed_scripts": "INTEGER",
        "phone_number": "TEXT",
    }.items():
        if col not in existing:
            cursor.execute(f"ALTER TABLE logs ADD COLUMN {col} {typ}")

    conn.commit()
    conn.close()


# ============================================================
# SINCRONIZAÇÃO: Supabase → SQLite ao arrancar
# ============================================================

def sync_from_supabase():
    """
    Ao iniciar, copia os dados do Supabase para o SQLite local.
    Assim mesmo que o Streamlit reinicie, os dados são restaurados.
    """
    sb = _get_supabase()
    if not sb:
        return

    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        # Sincronizar logs
        rows = sb.table("logs").select("*").order("id").execute().data or []
        for r in rows:
            cursor.execute("SELECT id FROM logs WHERE id = ?", (r.get("id"),))
            if not cursor.fetchone():
                cursor.execute("""
                    INSERT OR IGNORE INTO logs
                    (id, message, risk_level, risk_type, score, reasons, date,
                     link_results, educational_alert, uppercase_ratio,
                     exclamations, emojis, mixed_scripts, phone_number)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    r.get("id"), r.get("message"), r.get("risk_level"),
                    r.get("risk_type"), r.get("score"), r.get("reasons"),
                    r.get("date"), r.get("link_results"), r.get("educational_alert"),
                    r.get("uppercase_ratio", 0), r.get("exclamations", 0),
                    r.get("emojis", 0), r.get("mixed_scripts", 0),
                    r.get("phone_number"),
                ))

        # Sincronizar blacklist
        rows = sb.table("blacklist").select("*").execute().data or []
        for r in rows:
            cursor.execute("""
                INSERT OR IGNORE INTO blacklist (phone_number, reason, date_added)
                VALUES (?, ?, ?)
            """, (r.get("phone_number"), r.get("reason"), r.get("date_added", now)))

        # Sincronizar phone_numbers
        rows = sb.table("phone_numbers").select("*").execute().data or []
        for r in rows:
            cursor.execute("SELECT id FROM phone_numbers WHERE phone_number = ?", (r.get("phone_number"),))
            if not cursor.fetchone():
                cursor.execute("""
                    INSERT OR IGNORE INTO phone_numbers
                    (phone_number, risk_type, risk_level, report_count, first_seen, last_seen)
                    VALUES (?,?,?,?,?,?)
                """, (
                    r.get("phone_number"), r.get("risk_type"), r.get("risk_level"),
                    r.get("report_count", 1), r.get("first_seen", now), r.get("last_seen", now),
                ))

        # Sincronizar feedback
        rows = sb.table("feedback").select("*").execute().data or []
        for r in rows:
            cursor.execute("SELECT id FROM feedback WHERE id = ?", (r.get("id"),))
            if not cursor.fetchone():
                cursor.execute("""
                    INSERT OR IGNORE INTO feedback (id, log_id, correct, comment, date)
                    VALUES (?,?,?,?,?)
                """, (r.get("id"), r.get("log_id"), r.get("correct"), r.get("comment"), r.get("date", now)))

        conn.commit()
        logger.info("Sincronização Supabase → SQLite concluída.")

    except Exception as e:
        logger.error(f"Erro na sincronização do Supabase: {e}")
    finally:
        conn.close()


# ============================================================
# GUARDAR ANÁLISE
# ============================================================

def save_analysis(text: str, result: dict, phone_number: str = None):
    try:
        init_db()
        conn = get_connection()
        cursor = conn.cursor()
        meta = result.get("meta", {})
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute("""
            INSERT INTO logs (
                message, risk_level, risk_type, score, reasons, date,
                link_results, educational_alert,
                uppercase_ratio, exclamations, emojis, mixed_scripts, phone_number
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            text,
            result.get("risk_level", "Desconhecido"),
            result.get("risk_type", "Desconhecido"),
            result.get("score", 0),
            ", ".join(result.get("reasons", [])),
            now,
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

        # Guardar também no Supabase
        _supabase_save_log(log_id, text, result, phone_number, now, meta)

        return log_id

    except Exception as e:
        logger.error(f"Erro ao guardar análise: {e}")
        return None


def _supabase_save_log(log_id, text, result, phone_number, now, meta):
    sb = _get_supabase()
    if not sb:
        return
    try:
        sb.table("logs").insert({
            "id": log_id,
            "message": text,
            "risk_level": result.get("risk_level", "Desconhecido"),
            "risk_type": result.get("risk_type", "Desconhecido"),
            "score": result.get("score", 0),
            "reasons": ", ".join(result.get("reasons", [])),
            "date": now,
            "link_results": json.dumps(result.get("link_results", {})),
            "educational_alert": result.get("educational_alert", ""),
            "uppercase_ratio": meta.get("uppercase_ratio", 0.0),
            "exclamations": meta.get("exclamations", 0),
            "emojis": meta.get("emojis", 0),
            "mixed_scripts": int(meta.get("mixed_scripts", False)),
            "phone_number": phone_number,
        }).execute()

        if phone_number and phone_number.strip():
            _supabase_update_phone(sb, phone_number.strip(), result, now)

    except Exception as e:
        logger.error(f"Erro ao guardar no Supabase: {e}")


def _supabase_update_phone(sb, phone_number, result, now):
    try:
        existing = sb.table("phone_numbers").select("*").eq("phone_number", phone_number).execute().data
        if existing:
            sb.table("phone_numbers").update({
                "report_count": existing[0]["report_count"] + 1,
                "last_seen": now,
                "risk_type": result.get("risk_type"),
                "risk_level": result.get("risk_level"),
            }).eq("phone_number", phone_number).execute()
        else:
            sb.table("phone_numbers").insert({
                "phone_number": phone_number,
                "risk_type": result.get("risk_type", "Desconhecido"),
                "risk_level": result.get("risk_level", "Desconhecido"),
                "report_count": 1,
                "first_seen": now,
                "last_seen": now,
            }).execute()
    except Exception as e:
        logger.error(f"Erro ao actualizar phone no Supabase: {e}")


def _update_phone_reputation(cursor, phone_number, risk_type, risk_level):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("SELECT id FROM phone_numbers WHERE phone_number = ?", (phone_number,))
    if cursor.fetchone():
        cursor.execute("""
            UPDATE phone_numbers
            SET report_count = report_count + 1, last_seen = ?, risk_type = ?, risk_level = ?
            WHERE phone_number = ?
        """, (now, risk_type, risk_level, phone_number))
    else:
        cursor.execute("""
            INSERT INTO phone_numbers (phone_number, risk_type, risk_level, report_count, first_seen, last_seen)
            VALUES (?,?,?,1,?,?)
        """, (phone_number, risk_type, risk_level, now, now))


# ============================================================
# FEEDBACK
# ============================================================

def save_feedback(log_id: int, correct: bool, comment: str = ""):
    try:
        init_db()
        conn = get_connection()
        cursor = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            INSERT INTO feedback (log_id, correct, comment, date)
            VALUES (?,?,?,?)
        """, (log_id, int(correct), comment, now))
        conn.commit()
        fb_id = cursor.lastrowid
        conn.close()

        # Supabase
        sb = _get_supabase()
        if sb:
            try:
                sb.table("feedback").insert({
                    "id": fb_id, "log_id": log_id,
                    "correct": int(correct), "comment": comment, "date": now,
                }).execute()
            except Exception as e:
                logger.error(f"Erro feedback Supabase: {e}")

    except Exception as e:
        logger.error(f"Erro ao guardar feedback: {e}")


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
            "total": total, "correct": correct,
            "incorrect": total - correct,
            "accuracy": round((correct / total * 100), 1) if total > 0 else 0,
        }
    except Exception as e:
        logger.error(f"Erro feedback stats: {e}")
        return {"total": 0, "correct": 0, "incorrect": 0, "accuracy": 0}


# ============================================================
# BLACKLIST
# ============================================================

def add_to_blacklist(phone_number: str, reason: str = ""):
    try:
        init_db()
        conn = get_connection()
        cursor = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            INSERT OR IGNORE INTO blacklist (phone_number, reason, date_added)
            VALUES (?,?,?)
        """, (phone_number.strip(), reason, now))
        conn.commit()
        conn.close()

        sb = _get_supabase()
        if sb:
            try:
                sb.table("blacklist").upsert({
                    "phone_number": phone_number.strip(),
                    "reason": reason,
                    "date_added": now,
                }).execute()
            except Exception as e:
                logger.error(f"Erro blacklist Supabase: {e}")
        return True
    except Exception as e:
        logger.error(f"Erro ao adicionar blacklist: {e}")
        return False


def remove_from_blacklist(phone_number: str):
    try:
        init_db()
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM blacklist WHERE phone_number = ?", (phone_number.strip(),))
        conn.commit()
        conn.close()

        sb = _get_supabase()
        if sb:
            try:
                sb.table("blacklist").delete().eq("phone_number", phone_number.strip()).execute()
            except Exception as e:
                logger.error(f"Erro remover blacklist Supabase: {e}")
        return True
    except Exception as e:
        logger.error(f"Erro ao remover blacklist: {e}")
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
        logger.error(f"Erro is_blacklisted: {e}")
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
        logger.error(f"Erro get_blacklist: {e}")
        return []


# ============================================================
# NÚMEROS DE TELEFONE
# ============================================================

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
        logger.error(f"Erro lookup_phone: {e}")
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
        results = [list(r) for r in cursor.fetchall()]
        conn.close()
        return results
    except Exception as e:
        logger.error(f"Erro top numbers: {e}")
        return []


# ============================================================
# DADOS DE TREINO ML
# ============================================================

def get_training_data() -> tuple[list, list]:
    try:
        init_db()
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT l.message, l.risk_type
            FROM logs l
            INNER JOIN feedback f ON f.log_id = l.id
            WHERE f.correct = 1
            AND l.risk_type IS NOT NULL
            AND l.risk_type != 'Desconhecido'
            AND length(l.message) > 10
        """)
        rows_feedback = cursor.fetchall()

        cursor.execute("""
            SELECT message, risk_type FROM logs
            WHERE risk_level IN ('Alto', 'Médio')
            AND risk_type IS NOT NULL
            AND risk_type != 'Desconhecido'
            AND length(message) > 10
            LIMIT 500
        """)
        rows_high = cursor.fetchall()
        conn.close()

        all_rows = list(set(rows_feedback + rows_high))
        return [r[0] for r in all_rows], [r[1] for r in all_rows]

    except Exception as e:
        logger.error(f"Erro get_training_data: {e}")
        return [], []