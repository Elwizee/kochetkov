"""Задача 19: Удалённое уничтожение данных (безопасное удаление)."""
import os
from pathlib import Path

from Crypto.Random import get_random_bytes


def secure_delete(file_path: Path, passes: int = 3, block_size: int = 65536) -> None:
    """Перезаписывает файл случайными данными n раз, затем удаляет."""
    if not file_path.exists():
        raise FileNotFoundError(file_path)

    file_size = file_path.stat().st_size
    for pass_num in range(passes):
        with open(file_path, "r+b") as f:
            remaining = file_size
            while remaining > 0:
                chunk = min(block_size, remaining)
                f.write(get_random_bytes(chunk))
                remaining -= chunk
            f.flush()
            os.fsync(f.fileno())
        print(f"  Проход {pass_num + 1}/{passes} завершён")

    file_path.unlink()
    print(f"Файл удалён: {file_path}")


if __name__ == "__main__":
    out_dir = Path(__file__).resolve().parent.parent / "output"
    out_dir.mkdir(exist_ok=True)
    test_file = out_dir / "to_delete.bin"
    test_file.write_bytes(("Secret data " * 1000).encode("utf-8"))
    print(f"Размер файла: {test_file.stat().st_size} байт")
    secure_delete(test_file, passes=3)
    print(f"Существует: {test_file.exists()}")
