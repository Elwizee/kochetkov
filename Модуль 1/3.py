"""Задача 3: Анализатор логов событий безопасности."""
from collections import Counter
from pathlib import Path


def parse_log_line(line: str) -> tuple[str, str, str, str] | None:
    parts = line.strip().split()
    if len(parts) < 4:
        return None
    date, time, ip = parts[0], parts[1], parts[2]
    event = " ".join(parts[3:])
    return date, time, ip, event


def top_failed_login_ips(log_text: str, top_n: int = 3) -> list[tuple[str, int]]:
    counter: Counter[str] = Counter()
    for line in log_text.splitlines():
        parsed = parse_log_line(line)
        if parsed and parsed[3] == "FAILED_LOGIN":
            counter[parsed[2]] += 1
    return counter.most_common(top_n)


if __name__ == "__main__":
    log_path = Path(__file__).resolve().parent.parent / "data" / "security.log"
    log_content = log_path.read_text(encoding="utf-8")
    top3 = top_failed_login_ips(log_content)
    print("Топ-3 IP с наибольшим числом FAILED_LOGIN:")
    for ip, count in top3:
        print(f"  {ip}: {count}")
