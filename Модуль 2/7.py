"""Задача 7: Упрощённый AES в режиме ECB — демонстрация недостатка."""
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PIL import Image


def aes_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, AES.block_size))


def aes_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)


def create_pattern_image(path: Path, size: int = 64) -> None:
    """Изображение с повторяющимся паттерном — ECB сохранит структуру."""
    img = Image.new("RGB", (size, size))
    pixels = img.load()
    for y in range(size):
        for x in range(size):
            if (x // 8 + y // 8) % 2 == 0:
                pixels[x, y] = (200, 50, 50)
            else:
                pixels[x, y] = (50, 50, 200)
    img.save(path)


def encrypt_image_ecb(input_path: Path, output_path: Path, key: bytes) -> None:
    img = Image.open(input_path).convert("RGB")
    data = img.tobytes()
    encrypted = aes_ecb_encrypt(key, data)
    enc_img = Image.frombytes("RGB", img.size, encrypted[: len(data)])
    enc_img.save(output_path)


if __name__ == "__main__":
    out_dir = Path(__file__).resolve().parent.parent / "output"
    out_dir.mkdir(exist_ok=True)
    key = b"0123456789abcdef"
    original = out_dir / "ecb_original.png"
    encrypted_img = out_dir / "ecb_encrypted.png"

    create_pattern_image(original)
    encrypt_image_ecb(original, encrypted_img, key)

    message = b"Secret message for AES ECB demo!"
    ct = aes_ecb_encrypt(key, message)
    pt = aes_ecb_decrypt(key, ct)
    print(f"Сообщение: {message.decode()}")
    print(f"Зашифровано: {ct.hex()[:64]}...")
    print(f"Расшифровано: {pt.decode()}")
    print(f"Оригинал: {original}")
    print(f"Зашифрованное изображение: {encrypted_img}")
    print("Недостаток ECB: повторяющиеся блоки в шифротексте сохраняют структуру изображения.")
