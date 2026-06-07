"""Задача 11: Обнаружение сканирования портов (IDS)."""
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from scapy.all import IP, TCP
from scapy.utils import rdpcap


def detect_port_scan(
    events: list[tuple[str, int, float]],
    port_threshold: int = 5,
    time_window: float = 3.0,
) -> list[str]:
    """
    events: список (src_ip, dst_port, timestamp).
    Предупреждение, если один IP обращается к >5 портам за 3 секунды.
    """
    by_src: dict[str, list[tuple[int, float]]] = defaultdict(list)
    for src, port, ts in events:
        by_src[src].append((port, ts))

    warnings = []
    for src, records in by_src.items():
        records.sort(key=lambda x: x[1])
        for i, (_, start_ts) in enumerate(records):
            window = [(p, t) for p, t in records[i:] if t - start_ts <= time_window]
            unique_ports = {p for p, _ in window}
            if len(unique_ports) > port_threshold:
                warnings.append(
                    f"СКАНИРОВАНИЕ: {src} — {len(unique_ports)} портов за {time_window} сек"
                )
                break
    return warnings


def analyze_pcap_for_scan(pcap_path: Path) -> list[str]:
    packets = rdpcap(str(pcap_path))
    events = []
    for pkt in packets:
        if IP in pkt and TCP in pkt:
            events.append((pkt[IP].src, pkt[TCP].dport, float(pkt.time)))
    return detect_port_scan(events)


def analyze_netstat_log(log_path: Path) -> list[str]:
    events = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        parts = line.strip().split()
        if len(parts) >= 4:
            src, port, ts_str = parts[0], int(parts[1]), parts[2]
            ts = datetime.fromisoformat(ts_str).timestamp()
            events.append((src, port, ts))
    return detect_port_scan(events)


if __name__ == "__main__":
    data_dir = Path(__file__).resolve().parent.parent / "data"
    pcap_path = data_dir / "sample.pcap"

    if pcap_path.exists():
        print("Анализ PCAP:")
        for w in analyze_pcap_for_scan(pcap_path):
            print(f"  {w}")

    netstat_log = data_dir / "netstat.log"
    netstat_log.write_text(
        "10.0.0.99 22 2024-01-15T10:00:00\n"
        "10.0.0.99 23 2024-01-15T10:00:01\n"
        "10.0.0.99 24 2024-01-15T10:00:01\n"
        "10.0.0.99 25 2024-01-15T10:00:02\n"
        "10.0.0.99 26 2024-01-15T10:00:02\n"
        "10.0.0.99 27 2024-01-15T10:00:02\n"
        "192.168.1.1 80 2024-01-15T10:05:00\n",
        encoding="utf-8",
    )
    print("\nАнализ netstat-лога:")
    for w in analyze_netstat_log(netstat_log):
        print(f"  {w}")
