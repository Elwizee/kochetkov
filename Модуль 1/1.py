"""Задача 1: Генератор паролей с оценкой стойкости."""
import math
import random
import string


def generate_password(
    length: int = 16,
    use_letters: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    charset = ""
    if use_letters:
        charset += string.ascii_letters
    if use_digits:
        charset += string.digits
    if use_symbols:
        charset += "!@#$%^&*()-_=+[]{}|;:,.<>?"
    if not charset:
        raise ValueError("Нужно выбрать хотя бы один тип символов")
    return "".join(random.choice(charset) for _ in range(length))


def calculate_entropy(password: str) -> float:
    charset_size = 0
    if any(c in string.ascii_lowercase for c in password):
        charset_size += 26
    if any(c in string.ascii_uppercase for c in password):
        charset_size += 26
    if any(c in string.digits for c in password):
        charset_size += 10
    if any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in password):
        charset_size += 24
    if charset_size == 0:
        return 0.0
    return len(password) * math.log2(charset_size)


def assess_strength(password: str) -> str:
    entropy = calculate_entropy(password)
    if entropy < 40:
        return "слабый"
    if entropy < 60:
        return "средний"
    return "сильный"


if __name__ == "__main__":
    pwd = generate_password(20)
    print(f"Пароль: {pwd}")
    print(f"Энтропия: {calculate_entropy(pwd):.2f} бит")
    print(f"Стойкость: {assess_strength(pwd)}")
