"""Задача 13: SQL-инъекция — уязвимость и защита."""
import sqlite3
from html import escape
from pathlib import Path

from flask import Flask, request

app = Flask(__name__)
DB_PATH = Path(__file__).resolve().parent.parent / "data" / "users.db"


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)")
    conn.execute("DELETE FROM users")
    conn.executemany("INSERT INTO users (id, name) VALUES (?, ?)", [
        (1, "Алиса"), (2, "Боб"), (3, "Чарли"),
    ])
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return """
    <h1>Задача 13: SQL-инъекция</h1>
    <ul>
        <li><a href="/sql?id=1">Уязвимый запрос</a></li>
        <li><a href="/sql_safe?id=1">Защищённый запрос</a></li>
    </ul>
    """


@app.route("/sql")
def sql_vulnerable():
    user_id = request.args.get("id", "1")
    conn = sqlite3.connect(DB_PATH)
    query = f"SELECT id, name FROM users WHERE id = {user_id}"
    try:
        rows = conn.execute(query).fetchall()
        result = "<br>".join(f"ID={r[0]}, Name={r[1]}" for r in rows)
    except sqlite3.Error as e:
        result = f"Ошибка: {e}"
    conn.close()
    return f"""
    <h2>Уязвимый запрос</h2>
    <p>Запрос: <code>{escape(query)}</code></p>
    <p>Результат: {result}</p>
    <p>Попробуйте: <a href="/sql?id=1 OR '1'='1">?id=1 OR '1'='1</a></p>
    """


@app.route("/sql_safe")
def sql_safe():
    user_id = request.args.get("id", "1")
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT id, name FROM users WHERE id = ?", (user_id,)).fetchall()
    conn.close()
    result = "<br>".join(f"ID={r[0]}, Name={r[1]}" for r in rows) or "Не найдено"
    return f"""
    <h2>Защищённый запрос (параметризованный)</h2>
    <p>id = {escape(user_id)}</p>
    <p>Результат: {result}</p>
    <p>Попробуйте: <a href="/sql_safe?id=1 OR '1'='1">?id=1 OR '1'='1</a> — не сработает</p>
    """


if __name__ == "__main__":
    init_db()
    print("Задача 13: http://127.0.0.1:5013")
    app.run(debug=True, port=5013)
