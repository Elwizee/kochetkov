"""Задача 4: Шифр гаммирования (XOR)."""


def xor_cipher(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("Ключ не может быть пустым")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def encrypt_text(text: str, key: str) -> bytes:
    return xor_cipher(text.encode("utf-8"), key.encode("utf-8"))


def decrypt_text(ciphertext: bytes, key: str) -> str:
    return xor_cipher(ciphertext, key.encode("utf-8")).decode("utf-8")


if __name__ == "__main__":
    phrase = "Прикладная информатика"
    key = "ключ123"
    encrypted = encrypt_text(phrase, key)
    decrypted = decrypt_text(encrypted, key)
    print(f"Исходный текст: {phrase}")
    print(f"Ключ: {key}")
    print(f"Зашифровано (hex): {encrypted.hex()}")
    print(f"Расшифровано: {decrypted}")
    print(f"Совпадает: {phrase == decrypted}")
