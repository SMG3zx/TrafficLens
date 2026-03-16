from __future__ import annotations

from dataclasses import asdict, dataclass
import ipaddress
import struct


PCAP_MAGIC_TO_ENDIAN = {
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">",
}

LINKTYPE_ETHERNET = 1

IP_PROTOCOL_NAMES = {
    6: "TCP",
    17: "UDP",
}


@dataclass(slots=True)
class PacketSummary:
    no: int
    time: str
    src: str
    dst: str
    proto: str
    length: int
    info: str

    def to_dict(self) -> dict[str, int | str]:
        return asdict(self)


def analyze_pcap_bytes(data: bytes) -> list[dict[str, int | str]]:
    if len(data) < 24:
        raise ValueError("PCAP file is too small to contain a valid global header.")

    endian = PCAP_MAGIC_TO_ENDIAN.get(data[:4])
    if endian is None:
        raise ValueError("Unsupported PCAP magic number. Only classic PCAP is supported.")

    _magic, _major, _minor, _thiszone, _sigfigs, _snaplen, network = struct.unpack(
        f"{endian}IHHIIII", data[:24]
    )
    if network != LINKTYPE_ETHERNET:
        raise ValueError(
            f"Unsupported PCAP link type {network}. Only Ethernet captures are supported."
        )

    packets: list[dict[str, int | str]] = []
    offset = 24
    first_ts: float | None = None
    packet_no = 0

    while offset + 16 <= len(data):
        ts_sec, ts_usec, incl_len, _orig_len = struct.unpack(
            f"{endian}IIII", data[offset : offset + 16]
        )
        offset += 16

        if offset + incl_len > len(data):
            raise ValueError("PCAP packet record exceeds file length.")

        frame = data[offset : offset + incl_len]
        offset += incl_len
        packet_no += 1

        timestamp = ts_sec + (ts_usec / 1_000_000)
        if first_ts is None:
            first_ts = timestamp

        rel_time = timestamp - first_ts
        packets.append(
            PacketSummary(
                no=packet_no,
                time=f"{rel_time:.6f}",
                src="-",
                dst="-",
                proto="UNKNOWN",
                length=len(frame),
                info=_summarize_frame(frame),
            ).to_dict()
        )

        summary = _parse_frame(frame)
        packets[-1].update(summary)

    return packets


def _summarize_frame(frame: bytes) -> str:
    if not frame:
        return "Empty frame"
    return f"Raw frame ({len(frame)} bytes)"


def _parse_frame(frame: bytes) -> dict[str, str]:
    if len(frame) < 14:
        return {
            "proto": "TRUNCATED",
            "info": "Truncated Ethernet frame",
        }

    ether_type = struct.unpack("!H", frame[12:14])[0]
    if ether_type != 0x0800:
        return {
            "proto": f"ETH:0x{ether_type:04x}",
            "info": f"Non-IPv4 Ethernet frame (ethertype 0x{ether_type:04x})",
        }

    return _parse_ipv4_packet(frame[14:])


def _parse_ipv4_packet(packet: bytes) -> dict[str, str]:
    if len(packet) < 20:
        return {
            "proto": "IPv4",
            "info": "Truncated IPv4 packet",
        }

    version_ihl = packet[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    if version != 4 or len(packet) < ihl:
        return {
            "proto": "IPv4",
            "info": "Invalid IPv4 header",
        }

    protocol_number = packet[9]
    src = str(ipaddress.IPv4Address(packet[12:16]))
    dst = str(ipaddress.IPv4Address(packet[16:20]))
    proto = IP_PROTOCOL_NAMES.get(protocol_number, f"IP:{protocol_number}")
    payload = packet[ihl:]
    info = f"{proto} {src} -> {dst}"

    if protocol_number in (6, 17) and len(payload) >= 4:
        src_port, dst_port = struct.unpack("!HH", payload[:4])
        info = f"{proto} {src}:{src_port} -> {dst}:{dst_port}"

    return {
        "src": src,
        "dst": dst,
        "proto": proto,
        "info": info,
    }
