import sqlite3
import json
import os
from datetime import datetime
from contextlib import contextmanager

DB_FILE = 'chat_history.db'


# Connection helper

@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row          # rows behave like dicts
    conn.execute("PRAGMA journal_mode=WAL") # safe concurrent writes
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

#  Schema
def init_db():
    """Create tables if they don't exist. Called once on app startup."""
    with get_conn() as conn:

        # sessions table — one row per chat session
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id   TEXT PRIMARY KEY,
                title        TEXT NOT NULL,
                type         TEXT NOT NULL DEFAULT 'chat',
                display_time TEXT NOT NULL,
                created_at   TEXT NOT NULL
            )
        """)

        # messages table — one row per message, linked to session
        conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id   TEXT NOT NULL,
                role         TEXT NOT NULL,        -- 'user' | 'bot'
                content      TEXT,                 -- message text
                redact_count INTEGER DEFAULT 0,
                file_data    TEXT,                 -- JSON blob for file results
                created_at   TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                    ON DELETE CASCADE
            )
        """)

        # index for fast session lookups
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_messages_session
            ON messages(session_id)
        """)

    print(f"[db] SQLite ready → {os.path.abspath(DB_FILE)}")


#  Session CRUD 

def create_session(session_id: str, title: str,
                   entry_type: str, display_time: str) -> None:
    with get_conn() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO sessions
                (session_id, title, type, display_time, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (session_id, title[:60], entry_type,
              display_time, datetime.now().isoformat()))


def get_all_sessions() -> list:
    """Return all sessions ordered newest first (no messages)."""
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT session_id, title, type, display_time, created_at
            FROM sessions
            ORDER BY created_at DESC
            LIMIT 30
        """).fetchall()
    return [dict(r) for r in rows]


def get_session_with_messages(session_id: str) -> dict | None:
    """Return one session dict including its messages list."""
    with get_conn() as conn:
        row = conn.execute("""
            SELECT session_id, title, type, display_time, created_at
            FROM sessions WHERE session_id = ?
        """, (session_id,)).fetchone()

        if not row:
            return None

        session = dict(row)

        msg_rows = conn.execute("""
            SELECT role, content, redact_count, file_data
            FROM messages
            WHERE session_id = ?
            ORDER BY id ASC
        """, (session_id,)).fetchall()

    messages = []
    for m in msg_rows:
        msg = {
            'role': m['role'],
            'text': m['content'],
            'redact_count': m['redact_count'],
        }
        if m['file_data']:
            msg['file_data'] = json.loads(m['file_data'])
        messages.append(msg)

    session['messages'] = messages
    return session


def save_messages(session_id: str, messages: list) -> None:
    """
    Replace all messages for a session.
    messages = list of dicts:
      { role, text, redact_count, file_data? }
    """
    with get_conn() as conn:
        # Delete old messages for this session
        conn.execute("DELETE FROM messages WHERE session_id = ?", (session_id,))

        # Insert new messages
        for msg in messages:
            file_data_json = None
            if msg.get('file_data'):
                file_data_json = json.dumps(msg['file_data'], ensure_ascii=False)

            conn.execute("""
                INSERT INTO messages
                    (session_id, role, content, redact_count, file_data, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                session_id,
                msg.get('role', 'user'),
                msg.get('text', ''),
                msg.get('redact_count', 0),
                file_data_json,
                datetime.now().isoformat()
            ))


def delete_session(session_id: str) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM messages WHERE session_id = ?", (session_id,))
        conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))


def clear_all_sessions() -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM messages")
        conn.execute("DELETE FROM sessions")