"""Задача 17: Стеганография LSB в изображении."""
from pathlib import Path

from PIL import Image


def _bytes_to_bits(data: bytes) -> list[int]:
    bits = []
    for byte in data:
        for i in range(8):
            bits.append((byte >> i) & 1)
    return bits


def _bits_to_bytes(bits: list[int]) -> bytes:
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte |= bits[i + j] << j
        result.append(byte)
    return bytes(result)


def hide_message(image_path: Path, message: str, output_path: Path) -> None:
    img = Image.open(image_path).convert("RGB")
    pixels = list(img.getdata())
    msg_bytes = message.encode("utf-8")
    length_bits = len(msg_bytes).to_bytes(4, "big")
    bits = _bytes_to_bits(length_bits + msg_bytes)
    bits.append(0)

    if len(bits) > len(pixels) * 3:
        raise ValueError("Сообщение слишком длинное для изображения")

    new_pixels = []
    bit_idx = 0
    for r, g, b in pixels:
        if bit_idx < len(bits):
            r = (r & 0xFE) | bits[bit_idx]
            bit_idx += 1
        if bit_idx < len(bits):
            g = (g & 0xFE) | bits[bit_idx]
            bit_idx += 1
        if bit_idx < len(bits):
            b = (b & 0xFE) | bits[bit_idx]
            bit_idx += 1
        new_pixels.append((r, g, b))

    new_img = Image.new("RGB", img.size)
    new_img.putdata(new_pixels)
    new_img.save(output_path)


def extract_message(image_path: Path) -> str:
    img = Image.open(image_path).convert("RGB")
    pixels = list(img.getdata())
    bits = []
    for r, g, b in pixels:
        bits.extend([r & 1, g & 1, b & 1])

    length_bits = bits[:32]
    length = int.from_bytes(_bits_to_bytes(length_bits), "big")
    msg_bits = bits[32 : 32 + length * 8]
    return _bits_to_bytes(msg_bits).decode("utf-8")


if __name__ == "__main__":
    out_dir = Path(__file__).resolve().parent.parent / "output"
    out_dir.mkdir(exist_ok=True)
    original = out_dir / "stego_original.png"
    stego = out_dir / "stego_hidden.png"

    img = Image.new("RGB", (200, 200), color=(100, 150, 200))
    img.save(original)

    secret = "Секретное сообщение для LSB-стеганографии"
    hide_message(original, secret, stego)
    extracted = extract_message(stego)
    print(f"Скрытое сообщение: {secret}")
    print(f"Извлечённое: {extracted}")
    print(f"Совпадает: {secret == extracted}")
    print(f"Оригинал: {original}, со стеганографией: {stego}")
