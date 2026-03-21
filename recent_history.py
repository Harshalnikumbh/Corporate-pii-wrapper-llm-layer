import uuid
from datetime import datetime
from flask import Blueprint, jsonify, request
from db import (init_db, create_session, get_all_sessions,
                get_session_with_messages, save_messages,
                delete_session, clear_all_sessions)

history_bp = Blueprint('history', __name__)


# ── Helpers 
def _human_time(dt: datetime) -> str:
    today = datetime.now().date()
    delta = (today - dt.date()).days
    if delta == 0:
        return 'Today'
    elif delta == 1:
        return 'Yesterday'
    elif delta < 7:
        return f'{delta} days ago'
    else:
        return dt.strftime('%d %b %Y')


def add_history_entry(title: str, entry_type: str = 'chat',
                      messages: list = None) -> str:
    """
    Create a new session in SQLite.
    Called from app.py after every /chat and /upload.
    Returns session_id.
    """
    session_id = str(uuid.uuid4())[:8]
    display_time = _human_time(datetime.now())
    create_session(session_id, title, entry_type, display_time)
    if messages:
        save_messages(session_id, messages)
    return session_id


def update_history_messages(session_id: str, messages: list) -> None:
    """Save/overwrite messages for an existing session."""
    save_messages(session_id, messages)


# ── API Routes ─────────────────────────────────────────────────────────────────

@history_bp.route('/history', methods=['GET'])
def get_history():
    """All sessions, no messages (fast sidebar load)."""
    return jsonify(get_all_sessions())


@history_bp.route('/history/<session_id>', methods=['GET'])
def get_session(session_id):
    """One session WITH full messages for replay."""
    session = get_session_with_messages(session_id)
    if not session:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(session)


@history_bp.route('/history/<session_id>/messages', methods=['PUT'])
def put_messages(session_id):
    """Frontend calls this after every exchange to persist messages."""
    data = request.json or {}
    messages = data.get('messages', [])
    save_messages(session_id, messages)
    return jsonify({'success': True, 'saved': len(messages)})


@history_bp.route('/history/<session_id>', methods=['DELETE'])
def delete_entry(session_id):
    delete_session(session_id)
    return jsonify({'success': True})


@history_bp.route('/history', methods=['DELETE'])
def clear_history():
    clear_all_sessions()
    return jsonify({'success': True})