"""Задача 18: Анализатор метаданных файлов."""
from pathlib import Path

import exifread


def analyze_metadata(image_path: Path) -> dict:
    with open(image_path, "rb") as f:
        tags = exifread.process_file(f, details=False)

    result = {
        "gps": None,
        "datetime": None,
        "model": None,
        "warnings": [],
    }

    lat = tags.get("GPS GPSLatitude")
    lat_ref = tags.get("GPS GPSLatitudeRef")
    lon = tags.get("GPS GPSLongitude")
    lon_ref = tags.get("GPS GPSLongitudeRef")

    if lat and lon:
        result["gps"] = f"{lat} {lat_ref}, {lon} {lon_ref}"
        result["warnings"].append(
            "ВНИМАНИЕ: GPS-координаты в метаданных — риск утечки местоположения!"
        )

    dt = tags.get("EXIF DateTimeOriginal") or tags.get("Image DateTime")
    if dt:
        result["datetime"] = str(dt)
        result["warnings"].append("Дата съёмки доступна в метаданных.")

    model = tags.get("Image Model")
    if model:
        result["model"] = str(model)
        result["warnings"].append("Модель устройства раскрывает информацию о владельце.")

    if not result["warnings"]:
        result["warnings"].append("Критичных метаданных не обнаружено (или файл без EXIF).")

    return result


if __name__ == "__main__":
    data_dir = Path(__file__).resolve().parent.parent / "data"
    sample = data_dir / "sample_photo.jpg"
    if sample.exists():
        info = analyze_metadata(sample)
        print(f"Файл: {sample}")
        print(f"  GPS: {info['gps']}")
        print(f"  Дата: {info['datetime']}")
        print(f"  Модель: {info['model']}")
        for w in info["warnings"]:
            print(f"  {w}")
    else:
        print(f"Поместите фото с EXIF в {sample} для полной демонстрации.")
        print("Функция analyze_metadata() готова к использованию.")
