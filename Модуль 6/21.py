"""Задача 21: Система контроля целостности файлов (аналог Tripwire)."""
import hashlib
import json
from pathlib import Path


def compute_hashes(directory: Path) -> dict[str, str]:
    hashes = {}
    for file_path in sorted(directory.rglob("*")):
        if file_path.is_file() and file_path.name != "integrity.json":
            rel = str(file_path.relative_to(directory))
            hashes[rel] = hashlib.sha256(file_path.read_bytes()).hexdigest()
    return hashes


def save_baseline(directory: Path, baseline_path: Path) -> dict[str, str]:
    hashes = compute_hashes(directory)
    baseline_path.write_text(json.dumps(hashes, indent=2, ensure_ascii=False), encoding="utf-8")
    return hashes


def compare_integrity(directory: Path, baseline_path: Path) -> dict[str, list[str]]:
    if not baseline_path.exists():
        raise FileNotFoundError("Базовая линия не найдена. Сначала выполните scan --init")

    old = json.loads(baseline_path.read_text(encoding="utf-8"))
    new = compute_hashes(directory)

    modified = [f for f in old if f in new and old[f] != new[f]]
    added = [f for f in new if f not in old]
    deleted = [f for f in old if f not in new]

    return {"modified": modified, "added": added, "deleted": deleted}


if __name__ == "__main__":
    import sys

    data_dir = Path(__file__).resolve().parent.parent / "data" / "watch"
    data_dir.mkdir(parents=True, exist_ok=True)
    baseline = data_dir / "integrity.json"

    (data_dir / "config.txt").write_text("version=1.0\n", encoding="utf-8")
    (data_dir / "readme.txt").write_text("Тестовый файл\n", encoding="utf-8")

    print("=== Первое сканирование ===")
    save_baseline(data_dir, baseline)
    print(f"Базовая линия сохранена: {baseline}")

    (data_dir / "config.txt").write_text("version=1.1\n", encoding="utf-8")
    (data_dir / "new_file.txt").write_text("Новый файл\n", encoding="utf-8")
    (data_dir / "readme.txt").unlink()

    print("\n=== Повторное сканирование ===")
    diff = compare_integrity(data_dir, baseline)
    print(f"Изменённые: {diff['modified']}")
    print(f"Новые: {diff['added']}")
    print(f"Удалённые: {diff['deleted']}")
