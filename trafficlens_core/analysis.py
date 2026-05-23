from __future__ import annotations

from dataclasses import asdict, dataclass
import ipaddress
import struct

import structlog

log = structlog.get_logger(__name__)

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

# pcapng block type IDs
_PCAPNG_SHB_TYPE = 0x0A0D0D0A
_PCAPNG_IDB_TYPE = 0x00000001
_PCAPNG_EPB_TYPE = 0x00000006
_PCAPNG_OPB_TYPE = 0x00000002  # obsolete packet block, still produced by some tools

# byte-order magic values (0x1A2B3C4D), interpreted under each endianness
_PCAPNG_BOM_LE = 0x1A2B3C4D
_PCAPNG_BOM_BE = 0x4D3C2B1A

_PCAPNG_IDB_OPT_TSRESOL = 9  # Interface Description Block option: timestamp resolution


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


# ── Public entry point ─────────────────────────────────────────────────────────


def analyze_pcap_bytes(data: bytes) -> list[dict[str, int | str]]:
    if len(data) >= 4 and struct.unpack(">I", data[:4])[0] == _PCAPNG_SHB_TYPE:
        log.debug('pcap.format.detected', format='pcapng', size_bytes=len(data))
        return _analyze_pcapng(data)
    log.debug('pcap.format.detected', format='pcap', size_bytes=len(data))
    return _analyze_classic_pcap(data)


# ── Classic .pcap parser ───────────────────────────────────────────────────────


def _analyze_classic_pcap(data: bytes) -> list[dict[str, int | str]]:
    log.debug('pcap.parse.start', size_bytes=len(data))

    if len(data) < 24:
        log.warning('pcap.parse.too_small', size_bytes=len(data))
        raise ValueError("PCAP file is too small to contain a valid global header.")

    endian = PCAP_MAGIC_TO_ENDIAN.get(data[:4])
    if endian is None:
        log.warning('pcap.parse.bad_magic', magic=data[:4].hex())
        raise ValueError(
            "Unsupported PCAP magic number. Only classic PCAP is supported."
        )

    _magic, _major, _minor, _thiszone, _sigfigs, _snaplen, network = struct.unpack(
        f"{endian}IHHIIII", data[:24]
    )
    log.debug('pcap.parse.header', endian='little' if endian == '<' else 'big',
              link_type=network, version=f"{_major}.{_minor}")

    if network != LINKTYPE_ETHERNET:
        log.warning('pcap.parse.unsupported_link_type', link_type=network)
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
            log.warning('pcap.parse.record_overflow', packet_no=packet_no + 1,
                        offset=offset, incl_len=incl_len)
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
            src="-", dst="-",
            proto="UNKNOWN",
            length=len(frame),
            info=f"Raw frame ({len(frame)} bytes)",
        ).to_dict()
        summary.update(_parse_frame(frame))
        packets.append(summary)

    duration = float(packets[-1]['time']) if packets else 0.0
    log.info('pcap.parse.complete', packet_count=len(packets),
             duration_s=round(duration, 3), size_bytes=len(data))
    return packets


# ── pcapng parser ──────────────────────────────────────────────────────────────


def _analyze_pcapng(data: bytes) -> list[dict[str, int | str]]:
    if len(data) < 12:
        raise ValueError("pcapng file is too small to contain a valid Section Header Block.")

    # Byte-order magic sits at offset 8 inside the first SHB.
    # Reading it as LE tells us the file's own endianness.
    bom = struct.unpack("<I", data[8:12])[0]
    if bom == _PCAPNG_BOM_LE:
        endian = "<"
    elif bom == _PCAPNG_BOM_BE:
        endian = ">"
    else:
        log.warning('pcapng.parse.bad_bom', bom=hex(bom))
        raise ValueError("Invalid pcapng byte-order magic in Section Header Block.")

    log.debug('pcapng.parse.start', endian='little' if endian == '<' else 'big',
              size_bytes=len(data))

    interfaces: list[dict] = []
    packets: list[dict[str, int | str]] = []
    offset = 0
    packet_no = 0
    first_ts: float | None = None

    while offset + 8 <= len(data):
        block_type = struct.unpack(f"{endian}I", data[offset : offset + 4])[0]
        block_len  = struct.unpack(f"{endian}I", data[offset + 4 : offset + 8])[0]

        if block_len < 12 or offset + block_len > len(data):
            log.warning('pcapng.parse.bad_block', offset=offset,
                        block_type=hex(block_type), block_len=block_len)
            break

        # Body sits between the 8-byte header and the 4-byte trailing length copy.
        block_body = data[offset + 8 : offset + block_len - 4]

        if block_type == _PCAPNG_SHB_TYPE:
            interfaces = []  # each SHB starts a new section with fresh interface list
            log.debug('pcapng.shb', offset=offset)

        elif block_type == _PCAPNG_IDB_TYPE:
            iface = _parse_pcapng_idb(block_body, endian)
            interfaces.append(iface)
            log.debug('pcapng.idb', iface_id=len(interfaces) - 1,
                      link_type=iface['link_type'], tsresol=iface['tsresol'])

        elif block_type == _PCAPNG_EPB_TYPE:
            if len(block_body) >= 20:
                iface_id = struct.unpack(f"{endian}I", block_body[:4])[0]
                ts_high  = struct.unpack(f"{endian}I", block_body[4:8])[0]
                ts_low   = struct.unpack(f"{endian}I", block_body[8:12])[0]
                cap_len  = struct.unpack(f"{endian}I", block_body[12:16])[0]
                frame    = block_body[20 : 20 + cap_len]

                iface = interfaces[iface_id] if iface_id < len(interfaces) \
                    else {'link_type': LINKTYPE_ETHERNET, 'tsresol': 1e-6}
                timestamp = ((ts_high << 32) | ts_low) * iface['tsresol']
                if first_ts is None:
                    first_ts = timestamp

                packet_no += 1
                packets.append(_make_packet_summary(
                    packet_no, timestamp - first_ts, frame, iface['link_type']
                ))

        elif block_type == _PCAPNG_OPB_TYPE:
            if len(block_body) >= 20:
                iface_id = struct.unpack(f"{endian}H", block_body[:2])[0]
                ts_high  = struct.unpack(f"{endian}I", block_body[4:8])[0]
                ts_low   = struct.unpack(f"{endian}I", block_body[8:12])[0]
                cap_len  = struct.unpack(f"{endian}I", block_body[12:16])[0]
                frame    = block_body[20 : 20 + cap_len]

                iface = interfaces[iface_id] if iface_id < len(interfaces) \
                    else {'link_type': LINKTYPE_ETHERNET, 'tsresol': 1e-6}
                timestamp = ((ts_high << 32) | ts_low) * iface['tsresol']
                if first_ts is None:
                    first_ts = timestamp

                packet_no += 1
                packets.append(_make_packet_summary(
                    packet_no, timestamp - first_ts, frame, iface['link_type']
                ))

        offset += block_len

    duration = float(packets[-1]['time']) if packets else 0.0
    log.info('pcapng.parse.complete', packet_count=len(packets),
             duration_s=round(duration, 3), size_bytes=len(data))
    return packets


def _parse_pcapng_idb(block_body: bytes, endian: str) -> dict:
    link_type = struct.unpack(f"{endian}H", block_body[:2])[0] \
        if len(block_body) >= 2 else LINKTYPE_ETHERNET
    tsresol = 1e-6  # default: microseconds

    opt_offset = 8  # IDB options start after link_type(2) + reserved(2) + snaplen(4)
    while opt_offset + 4 <= len(block_body):
        opt_code = struct.unpack(f"{endian}H", block_body[opt_offset : opt_offset + 2])[0]
        opt_len  = struct.unpack(f"{endian}H", block_body[opt_offset + 2 : opt_offset + 4])[0]
        opt_val  = block_body[opt_offset + 4 : opt_offset + 4 + opt_len]

        if opt_code == 0:  # opt_endofopt
            break
        if opt_code == _PCAPNG_IDB_OPT_TSRESOL and opt_len == 1:
            b = opt_val[0]
            tsresol = 2 ** (-(b & 0x7F)) if (b & 0x80) else 10 ** (-b)

        opt_offset += 4 + opt_len + ((-opt_len) % 4)  # value + 32-bit padding

    return {'link_type': link_type, 'tsresol': tsresol}


def _make_packet_summary(packet_no: int, rel_time: float,
                          frame: bytes, link_type: int) -> dict:
    summary = PacketSummary(
        no=packet_no,
        time=f"{rel_time:.6f}",
        src="-", dst="-",
        proto="UNKNOWN",
        length=len(frame),
        info=f"Raw frame ({len(frame)} bytes)",
    ).to_dict()
    if link_type == LINKTYPE_ETHERNET:
        summary.update(_parse_frame(frame))
    else:
        summary['proto'] = f"LINKTYPE:{link_type}"
        summary['info'] = f"Unsupported link type {link_type}"
    return summary


# ── Ethernet ──────────────────────────────────────────────────────────────────


def _parse_frame(frame: bytes) -> dict[str, str]:
    if len(frame) < 14:
        log.debug('frame.truncated', frame_len=len(frame))
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
        "info":  f"Ethertype 0x{ether_type:04x}",
    }


# ── ARP ───────────────────────────────────────────────────────────────────────


def _parse_arp(packet: bytes) -> dict[str, str]:
    if len(packet) < 28:
        log.debug('arp.truncated', packet_len=len(packet))
        return {"proto": "ARP", "info": "Truncated ARP packet"}

    oper   = struct.unpack("!H", packet[6:8])[0]
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
        log.debug('ipv4.truncated', packet_len=len(packet))
        return {"proto": "IPv4", "info": "Truncated IPv4 packet"}

    version_ihl = packet[0]
    version = version_ihl >> 4
    ihl     = (version_ihl & 0x0F) * 4
    if version != 4 or len(packet) < ihl:
        log.debug('ipv4.invalid_header', version=version, ihl=ihl, packet_len=len(packet))
        return {"proto": "IPv4", "info": "Invalid IPv4 header"}

    proto_num = packet[9]
    src   = str(ipaddress.IPv4Address(packet[12:16]))
    dst   = str(ipaddress.IPv4Address(packet[16:20]))
    proto = IP_PROTOCOL_NAMES.get(proto_num, f"IP:{proto_num}")
    payload = packet[ihl:]

    info = _parse_transport(proto_num, src, dst, payload, ipv6=False)
    return {"src": src, "dst": dst, "proto": proto, "info": info}


# ── IPv6 ──────────────────────────────────────────────────────────────────────


def _parse_ipv6(packet: bytes) -> dict[str, str]:
    if len(packet) < 40:
        log.debug('ipv6.truncated', packet_len=len(packet))
        return {"proto": "IPv6", "info": "Truncated IPv6 packet"}

    _vtcfl, _payload_len, next_header, _hop = struct.unpack("!IHBB", packet[:8])
    src   = str(ipaddress.IPv6Address(packet[8:24]))
    dst   = str(ipaddress.IPv6Address(packet[24:40]))
    proto = IP_PROTOCOL_NAMES.get(next_header, f"IP:{next_header}")
    payload = packet[40:]

    info = _parse_transport(next_header, src, dst, payload, ipv6=True)
    return {"src": src, "dst": dst, "proto": proto, "info": info}


# ── Transport-layer dispatch ───────────────────────────────────────────────────


def _parse_transport(
    proto_num: int, src: str, dst: str, payload: bytes, *, ipv6: bool
) -> str:
    bracket = ipv6  # wrap IPv6 addresses in brackets for port notation

    if proto_num == 1:   # ICMP
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
    qr        = (flags >> 15) & 1
    direction = "Response" if qr else "Query"
    return f"DNS {direction} id={tx_id:#06x} questions={qdcount}"
