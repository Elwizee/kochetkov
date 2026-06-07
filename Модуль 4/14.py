"""Задача 14: Форма входа с защитой от CSRF."""
import os
import secrets
from html import escape

from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret-key-change-me")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)

    if request.method == "POST":
        token = request.form.get("csrf_token", "")
        if token != session.get("csrf_token"):
            return "<h2>Ошибка: CSRF-токен недействителен!</h2>", 403
        username = request.form.get("username", "")
        return f"<h2>Вход выполнен: {escape(username)}</h2>"

    return f"""
    <h2>Форма входа (CSRF-защита)</h2>
    <form method="POST">
        <input type="hidden" name="csrf_token" value="{session['csrf_token']}">
        <label>Имя: <input name="username" value="admin"></label>
        <button type="submit">Войти</button>
    </form>
    <p>Запрос без токена будет отклонён (HTTP 403).</p>
    """


if __name__ == "__main__":
    print("Задача 14: http://127.0.0.1:5014/login")
    app.run(debug=True, port=5014)
