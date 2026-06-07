"""Задача 6: Атака перебором на слабый пароль."""


def weak_hash(password: str) -> int:
    return sum(ord(c) for c in password) % 10000


def brute_force_4digit(target_hash: int) -> list[str]:
    """Возвращает все совпадения (слабый хеш допускает коллизии)."""
    return [f"{i:04d}" for i in range(10000) if weak_hash(f"{i:04d}") == target_hash]


def complexity_analysis() -> None:
    space = 10000
    print(f"Пространство поиска: {space} вариантов (0000–9999)")
    print(f"Сложность: O(n), n = {space}")
    print(f"Среднее число попыток: {space // 2}")
    print("Вывод: 4-значный числовой пароль с тривиальным хешем взламывается мгновенно.")


if __name__ == "__main__":
    secret = "4827"
    h = weak_hash(secret)
    print(f"Хеш пароля {secret}: {h}")
    found = brute_force_4digit(h)
    print(f"Найденные пароли с таким хешем: {found[:5]}{'...' if len(found) > 5 else ''}")
    print(f"Всего коллизий: {len(found)} (слабый хеш не гарантирует уникальность)")
    print(f"Исходный пароль среди найденных: {secret in found}")
    complexity_analysis()
