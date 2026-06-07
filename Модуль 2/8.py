"""Задача 8: Менеджер ключей через переменные окружения."""
import os
import sys
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def get_secret_key() -> bytes:
    key = os.environ.get("SECRET_KEY", "").strip()
    if not key:
        raise ValueError("SECRET_KEY не задан или пуст. Установите: set SECRET_KEY=your_secret")
    return key.encode("utf-8").ljust(32, b"\0")[:32]


def encrypt_file(input_path: Path, output_path: Path) -> None:
    key = get_secret_key()
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = input_path.read_bytes()
    encrypted = cipher.encrypt(pad(data, AES.block_size))
    output_path.write_bytes(iv + encrypted)
    print(f"Файл зашифрован: {output_path}")


def decrypt_file(input_path: Path, output_path: Path) -> None:
    key = get_secret_key()
    raw = input_path.read_bytes()
    iv, encrypted = raw[:16], raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
    output_path.write_bytes(decrypted)
    print(f"Файл расшифрован: {output_path}")


if __name__ == "__main__":
    data_dir = Path(__file__).resolve().parent.parent / "data"
    out_dir = Path(__file__).resolve().parent.parent / "output"
    out_dir.mkdir(exist_ok=True)

    sample = data_dir / "secret.txt"
    sample.write_text("Конфиденциальные данные для шифрования.", encoding="utf-8")

    if "SECRET_KEY" not in os.environ:
        os.environ["SECRET_KEY"] = "my_super_secret_key_2024"

    enc_path = out_dir / "secret.enc"
    dec_path = out_dir / "secret_decrypted.txt"
    encrypt_file(sample, enc_path)
    decrypt_file(enc_path, dec_path)
    print(f"Проверка: {dec_path.read_text(encoding='utf-8')}")
