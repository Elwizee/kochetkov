"""Задача 9: Анализ сетевого трафика из PCAP-файла."""
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from scapy.all import IP, TCP, wrpcap
from scapy.utils import rdpcap


def generate_sample_pcap(path: Path) -> None:
    """Генерация учебного PCAP для демонстрации."""
    from scapy.all import Ether

    packets = []
    base_time = datetime(2024, 1, 15, 10, 0, 0)
    attacker = "10.0.0.99"
    targets = ["192.168.1.1", "192.168.1.2", "10.0.0.1"]

    for i, target in enumerate(targets * 5):
        pkt = (
            Ether()
            / IP(src=attacker if i < 8 else "10.0.0.10", dst=target)
            / TCP(sport=40000 + i, dport=80 + i, flags="S")
        )
        pkt.time = base_time.timestamp() + i * 0.5
        packets.append(pkt)

    packets.append(
        Ether() / IP(src="172.16.0.5", dst="192.168.1.1") / TCP(sport=50000, dport=443, flags="S")
    )
    wrpcap(str(path), packets)


def analyze_pcap(pcap_path: Path, syn_threshold: int = 5, time_window: float = 5.0) -> dict:
    packets = rdpcap(str(pcap_path))
    unique_ips: set[str] = set()
    syn_count = 0
    syn_by_src_time: dict[str, list[float]] = defaultdict(list)
    warnings: list[str] = []

    for pkt in packets:
        if IP not in pkt:
            continue
        src, dst = pkt[IP].src, pkt[IP].dst
        unique_ips.add(src)
        unique_ips.add(dst)

        if TCP in pkt and pkt[TCP].flags & 0x02:
            syn_count += 1
            ts = float(pkt.time)
            syn_by_src_time[src].append(ts)

    for src, timestamps in syn_by_src_time.items():
        timestamps.sort()
        for i in range(len(timestamps)):
            window = [t for t in timestamps[i:] if t - timestamps[i] <= time_window]
            if len(window) >= syn_threshold:
                warnings.append(
                    f"ПОДОЗРИТЕЛЬНО: IP {src} отправил {len(window)} SYN за {time_window} сек"
                )
                break

    return {
        "unique_ips": sorted(unique_ips),
        "syn_count": syn_count,
        "warnings": warnings,
    }


if __name__ == "__main__":
    data_dir = Path(__file__).resolve().parent.parent / "data"
    pcap_path = data_dir / "sample.pcap"
    if not pcap_path.exists():
        generate_sample_pcap(pcap_path)

    result = analyze_pcap(pcap_path)
    print("Уникальные IP:", result["unique_ips"])
    print(f"SYN-пакетов: {result['syn_count']}")
    for w in result["warnings"]:
        print(w)
