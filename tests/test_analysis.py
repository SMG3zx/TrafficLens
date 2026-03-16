import struct

from trafficlens_core import analyze_pcap_bytes


def test_analyze_pcap_bytes_extracts_ipv4_tcp_summary():
    packet = _build_ipv4_tcp_frame("192.168.1.10", "192.168.1.20", 12345, 443)
    pcap = _wrap_pcap(packet)

    rows = analyze_pcap_bytes(pcap)

    assert len(rows) == 1
    assert rows[0]["src"] == "192.168.1.10"
    assert rows[0]["dst"] == "192.168.1.20"
    assert rows[0]["proto"] == "TCP"
    assert rows[0]["length"] == len(packet)
    assert rows[0]["info"] == "TCP 192.168.1.10:12345 -> 192.168.1.20:443"


def _wrap_pcap(frame: bytes) -> bytes:
    global_header = struct.pack(
        "<IHHIIII",
        0xA1B2C3D4,
        2,
        4,
        0,
        0,
        65535,
        1,
    )
    packet_header = struct.pack("<IIII", 1, 500000, len(frame), len(frame))
    return global_header + packet_header + frame


def _build_ipv4_tcp_frame(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    ethernet_header = b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + struct.pack(
        "!H", 0x0800
    )
    version_ihl = (4 << 4) | 5
    total_length = 20 + 20
    ipv4_header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,
        total_length,
        0,
        0,
        64,
        6,
        0,
        bytes(int(part) for part in src_ip.split(".")),
        bytes(int(part) for part in dst_ip.split(".")),
    )
    tcp_header = struct.pack("!HHLLBBHHH", src_port, dst_port, 0, 0, 5 << 4, 0, 8192, 0, 0)
    return ethernet_header + ipv4_header + tcp_header
