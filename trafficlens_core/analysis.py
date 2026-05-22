from __future__ import annotations

from dataclasses import asdict, dataclass
import ipaddress
import struct

PCAP_MAGIC_TO_ENDIAN = {
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">",
}

LINKTYPE_ETHERNET = 1

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP  = 0x0806
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_IPV6 = 0x86DD

IP_PROTOCOL_NAMES: dict[int, str] = {
    1:   "ICMP",
    6:   "TCP",
    17:  "UDP",
    47:  "GRE",
    58:  "ICMPv6",
    89:  "OSPF",
    132: "SCTP",
}

ICMP_TYPE_NAMES: dict[int, str] = {
    0:  "Echo Reply",
    3:  "Destination Unreachable",
    5:  "Redirect",
    8:  "Echo Request",
    11: "Time Exceeded",
    12: "Parameter Problem",
}

ICMPV6_TYPE_NAMES: dict[int, str] = {
    1:   "Destination Unreachable",
    2:   "Packet Too Big",
    3:   "Time Exceeded",
    128: "Echo Request",
    129: "Echo Reply",
    133: "Router Solicitation",
    134: "Router Advertisement",
    135: "Neighbor Solicitation",
    136: "Neighbor Advertisement",
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
        raise ValueError(
            "Unsupported PCAP magic number. Only classic PCAP is supported."
        )

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
        summary = PacketSummary(
            no=packet_no,
            time=f"{rel_time:.6f}",
            src="-",
            dst="-",
            proto="UNKNOWN",
            length=len(frame),
            info=f"Raw frame ({len(frame)} bytes)",
        ).to_dict()
        summary.update(_parse_frame(frame))
        packets.append(summary)

    return packets


# ── Ethernet ──────────────────────────────────────────────────────────────────

def _parse_frame(frame: bytes) -> dict[str, str]:
    if len(frame) < 14:
        return {"proto": "TRUNCATED", "info": "Truncated Ethernet frame"}

    ether_type = struct.unpack("!H", frame[12:14])[0]

    # 802.1Q VLAN tag — strip and recurse on inner ethertype
    if ether_type == ETHERTYPE_VLAN:
        if len(frame) < 18:
            return {"proto": "VLAN", "info": "Truncated VLAN frame"}
        ether_type = struct.unpack("!H", frame[16:18])[0]
        return _dispatch_ethertype(ether_type, frame[18:])

    return _dispatch_ethertype(ether_type, frame[14:])


def _dispatch_ethertype(ether_type: int, payload: bytes) -> dict[str, str]:
    if ether_type == ETHERTYPE_IPV4:
        return _parse_ipv4(payload)
    if ether_type == ETHERTYPE_IPV6:
        return _parse_ipv6(payload)
    if ether_type == ETHERTYPE_ARP:
        return _parse_arp(payload)
    return {
        "proto": f"ETH:0x{ether_type:04x}",
        "info": f"Ethertype 0x{ether_type:04x}",
    }


# ── ARP ───────────────────────────────────────────────────────────────────────

def _parse_arp(packet: bytes) -> dict[str, str]:
    if len(packet) < 28:
        return {"proto": "ARP", "info": "Truncated ARP packet"}

    oper = struct.unpack("!H", packet[6:8])[0]
    src_ip = str(ipaddress.IPv4Address(packet[14:18]))
    dst_ip = str(ipaddress.IPv4Address(packet[24:28]))

    if oper == 1:
        info = f"Who has {dst_ip}? Tell {src_ip}"
    elif oper == 2:
        info = f"{src_ip} is at (MAC reply)"
    else:
        info = f"ARP op={oper}: {src_ip} -> {dst_ip}"

    return {"src": src_ip, "dst": dst_ip, "proto": "ARP", "info": info}


# ── IPv4 ──────────────────────────────────────────────────────────────────────

def _parse_ipv4(packet: bytes) -> dict[str, str]:
    if len(packet) < 20:
        return {"proto": "IPv4", "info": "Truncated IPv4 packet"}

    version_ihl = packet[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    if version != 4 or len(packet) < ihl:
        return {"proto": "IPv4", "info": "Invalid IPv4 header"}

    proto_num = packet[9]
    src = str(ipaddress.IPv4Address(packet[12:16]))
    dst = str(ipaddress.IPv4Address(packet[16:20]))
    proto = IP_PROTOCOL_NAMES.get(proto_num, f"IP:{proto_num}")
    payload = packet[ihl:]

    info = _parse_transport(proto_num, src, dst, payload, ipv6=False)
    return {"src": src, "dst": dst, "proto": proto, "info": info}


# ── IPv6 ──────────────────────────────────────────────────────────────────────

def _parse_ipv6(packet: bytes) -> dict[str, str]:
    if len(packet) < 40:
        return {"proto": "IPv6", "info": "Truncated IPv6 packet"}

    _vtcfl, _payload_len, next_header, _hop = struct.unpack("!IHBB", packet[:8])
    src = str(ipaddress.IPv6Address(packet[8:24]))
    dst = str(ipaddress.IPv6Address(packet[24:40]))
    proto = IP_PROTOCOL_NAMES.get(next_header, f"IP:{next_header}")
    payload = packet[40:]

    info = _parse_transport(next_header, src, dst, payload, ipv6=True)
    return {"src": src, "dst": dst, "proto": proto, "info": info}


# ── Transport-layer dispatch ───────────────────────────────────────────────────

def _parse_transport(
    proto_num: int, src: str, dst: str, payload: bytes, *, ipv6: bool
) -> str:
    bracket = ipv6  # wrap IPv6 addresses in brackets for port notation

    if proto_num == 1:  # ICMP
        return _icmp_info(payload, ICMP_TYPE_NAMES)

    if proto_num == 58:  # ICMPv6
        return _icmp_info(payload, ICMPV6_TYPE_NAMES)

    if proto_num in (6, 17) and len(payload) >= 4:
        src_port, dst_port = struct.unpack("!HH", payload[:4])
        proto_name = IP_PROTOCOL_NAMES.get(proto_num, str(proto_num))
        if bracket:
            info = f"{proto_name} [{src}]:{src_port} -> [{dst}]:{dst_port}"
        else:
            info = f"{proto_name} {src}:{src_port} -> {dst}:{dst_port}"

        if proto_num == 17 and (src_port == 53 or dst_port == 53):
            return _dns_info(payload) or info
        return info

    proto_name = IP_PROTOCOL_NAMES.get(proto_num, f"IP:{proto_num}")
    return f"{proto_name} {src} -> {dst}"


# ── ICMP ──────────────────────────────────────────────────────────────────────

def _icmp_info(payload: bytes, names: dict[int, str]) -> str:
    if len(payload) < 2:
        return "ICMP (truncated)"
    icmp_type, code = payload[0], payload[1]
    name = names.get(icmp_type, f"type={icmp_type}")
    return f"ICMP {name} (code={code})"


# ── DNS ───────────────────────────────────────────────────────────────────────

def _dns_info(udp_payload: bytes) -> str | None:
    """Parse enough of a DNS message to produce a one-line summary."""
    dns = udp_payload[8:]  # skip UDP header (8 bytes)
    if len(dns) < 12:
        return None
    tx_id, flags, qdcount = struct.unpack("!HHH", dns[:6])
    qr = (flags >> 15) & 1
    direction = "Response" if qr else "Query"
    return f"DNS {direction} id={tx_id:#06x} questions={qdcount}"
