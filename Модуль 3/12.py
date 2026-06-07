"""Задача 12: Эмулятор сервера и атака по словарю."""
import socket
import threading
import time

HOST = "127.0.0.1"
PORT = 9999
VALID_LOGIN = "admin"
VALID_PASSWORD = "qwerty"
DICTIONARY = ["12345", "password", "qwerty", "admin"]


def run_server(stop_event: threading.Event) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    server.settimeout(1.0)

    while not stop_event.is_set():
        try:
            conn, _ = server.accept()
            with conn:
                data = conn.recv(1024).decode("utf-8").strip()
                parts = data.split()
                if len(parts) >= 2:
                    login, password = parts[0], parts[1]
                    if login == VALID_LOGIN and password == VALID_PASSWORD:
                        conn.sendall(b"SUCCESS")
                    else:
                        conn.sendall(b"FAIL")
                else:
                    conn.sendall(b"FAIL")
        except socket.timeout:
            continue
        except OSError:
            break
    server.close()


def dictionary_attack() -> str | None:
    for pwd in DICTIONARY:
        try:
            with socket.create_connection((HOST, PORT), timeout=2) as sock:
                sock.sendall(f"{VALID_LOGIN} {pwd}".encode("utf-8"))
                response = sock.recv(1024).decode("utf-8").strip()
                print(f"  Попытка: {pwd} -> {response}")
                if response == "SUCCESS":
                    return pwd
        except ConnectionRefusedError:
            time.sleep(0.5)
    return None


if __name__ == "__main__":
    stop = threading.Event()
    server_thread = threading.Thread(target=run_server, args=(stop,), daemon=True)
    server_thread.start()
    time.sleep(0.5)

    print(f"Сервер на {HOST}:{PORT}, логин: {VALID_LOGIN}")
    print("Перебор по словарю:")
    found = dictionary_attack()
    stop.set()
    server_thread.join(timeout=2)
    print(f"Найденный пароль: {found}")
