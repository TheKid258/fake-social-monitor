import sqlite3
from datetime import datetime
import json  # <-- necessário para converter dict em string

DB_NAME = "analysis.db"

def get_connection():
    return sqlite3.connect(DB_NAME)

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT,
            risk_level TEXT,
            risk_type TEXT,
            score INTEGER,
            reasons TEXT,
            date TEXT
        )
    """)
    
    cursor.execute("PRAGMA table_info(logs)")
    columns = [col[1] for col in cursor.fetchall()]
    if "link_results" not in columns:
        cursor.execute("ALTER TABLE logs ADD COLUMN link_results TEXT")

    conn.commit()
    conn.close()

def save_analysis(text, result):
    init_db()
    conn = get_connection()
    cursor = conn.cursor()

    # Converte dict em string JSON se existir link_results
    link_results_str = json.dumps(result.get("link_results", {}))  

    cursor.execute("""
        INSERT INTO logs (message, risk_level, risk_type, score, reasons, date, link_results)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        text,
        result.get("risk_level", "Desconhecido"),
        result.get("risk_type", "Desconhecido"),
        result.get("score", 0),
        ", ".join(result.get("reasons", [])),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        link_results_str
    ))

    conn.commit()
    conn.close()
