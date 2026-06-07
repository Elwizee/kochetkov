"""Задача 2: Ручное вычисление CRC-32."""
import binascii


def crc32_manual(data: bytes) -> int:
    """CRC-32 (IEEE 802.3) без использования zlib."""
    crc = 0xFFFFFFFF
    poly = 0xEDB88320
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
    return crc ^ 0xFFFFFFFF


def crc32_compare(text: str) -> None:
    data = text.encode("utf-8")
    manual = crc32_manual(data)
    builtin = binascii.crc32(data) & 0xFFFFFFFF
    print(f"Строка: {text!r}")
    print(f"CRC-32 (ручной):   0x{manual:08X}")
    print(f"CRC-32 (встроенный): 0x{builtin:08X}")
    print(f"Совпадают: {manual == builtin}")


if __name__ == "__main__":
    crc32_compare("Прикладная информатика")
