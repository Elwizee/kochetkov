"""Задача 15: XSS-уязвимость и экранирование."""
from html import escape

from flask import Flask, request

app = Flask(__name__)


@app.route("/")
def index():
    return """
    <h1>Задача 15: XSS</h1>
    <ul>
        <li><a href="/xss">Уязвимый вывод</a></li>
        <li><a href="/xss_safe">Защищённый вывод (escape)</a></li>
    </ul>
    """


@app.route("/xss")
def xss_vulnerable():
    name = request.args.get("name", "Гость")
    return f"""
    <h2>XSS — уязвимый вывод</h2>
    <p>Привет, {name}!</p>
    <form><input name="name" placeholder="Введите имя">
    <button>Отправить</button></form>
    <p>Попробуйте: <a href="/xss?name=<script>alert(1)</script>">
    &lt;script&gt;alert(1)&lt;/script&gt;</a></p>
    """


@app.route("/xss_safe")
def xss_safe():
    name = request.args.get("name", "Гость")
    safe_name = escape(name)
    return f"""
    <h2>XSS — защищённый вывод (escape)</h2>
    <p>Привет, {safe_name}!</p>
    <form><input name="name" placeholder="Введите имя">
    <button>Отправить</button></form>
    <p>Скрипт отображается как текст, не выполняется.</p>
    """


if __name__ == "__main__":
    print("Задача 15: http://127.0.0.1:5015")
    app.run(debug=True, port=5015)
