"""Задача 16: Проверка пароля через Have I Been Pwned API."""
import hashlib

import requests


def check_password_pwned(password: str) -> int:
    """
    k-анонимность: отправляем только первые 5 символов SHA-1.
    Возвращает количество утечек.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    for line in response.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)
    return 0


if __name__ == "__main__":
    test_passwords = ["password", "P@ssw0rd!2024xyz"]
    for pwd in test_passwords:
        try:
            count = check_password_pwned(pwd)
            print(f"Пароль '{pwd}': найден в {count} утечках")
        except requests.RequestException as e:
            print(f"Ошибка API для '{pwd}': {e}")
