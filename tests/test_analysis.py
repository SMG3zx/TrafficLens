"""Tests for trafficlens_core.analysis."""
from __future__ import annotations

import ipaddress
import struct

import pytest

from trafficlens_core import analyze_pcap_bytes


# ── PCAP / Ethernet helpers ────────────────────────────────────────────────────

_ETH_DST = b"\xff\xff\xff\xff\xff\xff"
_ETH_SRC = b"\x00\x11\x22\x33\x44\x55"


def _make_pcap(*frames: bytes, endian: str = "<") -> bytes:
    magic = b"\xd4\xc3\xb2\xa1" if endian == "<" else b"\xa1\xb2\xc3\xd4"
    glob = magic + struct.pack(f"{endian}HHIIII", 2, 4, 0, 0, 65535, 1)
    recs = b"".join(
        struct.pack(f"{endian}IIII", i, i * 1000, len(f), len(f)) + f
        for i, f in enumerate(frames)
    )
    return glob + recs


def _eth(ethertype: int, payload: bytes) -> bytes:
    return _ETH_DST + _ETH_SRC + struct.pack("!H", ethertype) + payload


def _ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    s = ipaddress.IPv4Address(src).packed
    d = ipaddress.IPv4Address(dst).packed
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, proto, 0, s, d)
    return hdr + payload


def _ipv6(src: str, dst: str, next_header: int, payload: bytes) -> bytes:
    s = ipaddress.IPv6Address(src).packed
    d = ipaddress.IPv6Address(dst).packed
    hdr = struct.pack("!IHBB", 0x60000000, len(payload), next_header, 64)
    return hdr + s + d + payload


def _tcp(src_port: int, dst_port: int) -> bytes:
    return struct.pack("!HHLLBBHHH", src_port, dst_port, 0, 0, 5 << 4, 0, 8192, 0, 0)


def _udp(src_port: int, dst_port: int, app_payload: bytes = b"") -> bytes:
    length = 8 + len(app_payload)
    return struct.pack("!HHHH", src_port, dst_port, length, 0) + app_payload


def _icmp(icmp_type: int, code: int = 0) -> bytes:
    return struct.pack("!BBH", icmp_type, code, 0) + b"\x00" * 4


def _arp(src_ip: str, dst_ip: str, oper: int = 1) -> bytes:
    hdr = struct.pack("!HHBBH", 1, 0x0800, 6, 4, oper)
    sha = b"\x00" * 6
    spa = ipaddress.IPv4Address(src_ip).packed
    tha = b"\x00" * 6
    tpa = ipaddress.IPv4Address(dst_ip).packed
    return hdr + sha + spa + tha + tpa


# ── Global header validation ───────────────────────────────────────────────────

def test_too_small_raises():
    with pytest.raises(ValueError, match="too small"):
        analyze_pcap_bytes(b"\x00" * 10)


def test_bad_magic_raises():
    with pytest.raises(ValueError, match="magic"):
        analyze_pcap_bytes(b"\xde\xad\xbe\xef" + b"\x00" * 20)


def test_non_ethernet_link_type_raises():
    magic = b"\xd4\xc3\xb2\xa1"
    hdr = magic + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 101)
    with pytest.raises(ValueError, match="link type"):
        analyze_pcap_bytes(hdr)


def test_empty_pcap_returns_no_packets():
    assert analyze_pcap_bytes(_make_pcap()) == []


def test_big_endian_pcap():
    frame = _eth(0x0800, _ipv4("10.0.0.1", "10.0.0.2", 6, _tcp(1234, 80)))
    result = analyze_pcap_bytes(_make_pcap(frame, endian=">"))
    assert len(result) == 1
    assert result[0]["proto"] == "TCP"


# ── IPv4 / transport ──────────────────────────────────────────────────────────

def test_ipv4_tcp():
    frame = _eth(0x0800, _ipv4("192.168.1.10", "192.168.1.20", 6, _tcp(12345, 443)))
    p = analyze_pcap_bytes(_make_pcap(frame))[0]
    assert p["src"] == "192.168.1.10"
    assert p["dst"] == "192.168.1.20"
    assert p["proto"] == "TCP"
    assert "12345" in p["info"]
    assert "443" in p["info"]
    assert p["info"] == "TCP 192.168.1.10:12345 -> 192.168.1.20:443"


def test_ipv4_udp():
    frame = _eth(0x0800, _ipv4("10.0.0.1", "8.8.8.8", 17, _udp(5353, 1234)))
    p = analyze_pcap_bytes(_make_pcap(frame))[0]
    assert p["proto"] == "UDP"
    assert p["src"] == "10.0.0.1"
    assert p["dst"] == "8.8.8.8"


def test_ipv4_icmp_echo_request():
    frame = _eth(0x0800, _ipv4("192.168.1.1", "192.168.1.2", 1, _icmp(8)))
    p = analyze_pcap_bytes(_make_pcap(frame))[0]
    assert p["proto"] == "ICMP"
    assert "Echo Request" in p["info"]


def test_ipv4_icmp_echo_reply():
    frame = _eth(0x0800, _ipv4("192.168.1.2", "192.168.1.1", 1, _icmp(0)))
    p = analyze_pcap_bytes(_make_pcap(frame))[0]
    assert p["proto"] == "ICMP"
    assert "Echo Reply" in p["info"]


# ── DNS ───────────────────────────────────────────────────────────────────────

def test_dns_query_detected():
    dns = struct.pack("!HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0)
    frame = _eth(0x0800, _ipv4("192.168.1.1", "8.8.8.8", 17, _udp(54321, 53, dns)))
    p = analyze_pcap_bytes(_make_pcap(frame))[0]
    assert "DNS" in p["info"]
    assert "Query" in p["info"]


def test_dns_response_detected():
    dns = struct.pack("!HHHHHH", 0xABCD, 0x8180, 1, 1, 0, 0)
    frame = _eth(0x0800, _ipv4("8.8.8.8", "192.168.1.1", 17, _udp(53, 54321, dns)))
    p = analyze_pcap_bytes(_make_pcap(frame))[0]
    assert "DNS" in p["info"]
    assert "Response" in p["info"]


# ── ARP ───────────────────────────────────────────────────────────────────────

def test_arp_request():
    frame = _eth(0x0806, _arp("192.168.1.2", "192.168.1.1", oper=1))
    p = analyze_pcap_bytes(_make_pcap(frame))[0]
    assert p["proto"] == "ARP"
    assert "192.168.1.1" in p["info"]
    assert "192.168.1.2" in p["info"]
    assert "Who has" in p["info"]


def test_arp_reply():
    frame = _eth(0x0806, _arp("192.168.1.1", "192.168.1.2", oper=2))
    p = analyze_pcap_bytes(_make_pcap(frame))[0]
    assert p["proto"] == "ARP"
    assert "is at" in p["info"]


# ── IPv6 ──────────────────────────────────────────────────────────────────────

def test_ipv6_tcp():
    frame = _eth(0x86DD, _ipv6("2001:db8::1", "2001:db8::2", 6, _tcp(443, 8443)))
    p = analyze_pcap_bytes(_make_pcap(frame))[0]
    assert p["proto"] == "TCP"
    assert "2001:db8::1" in p["src"]
    assert "443" in p["info"]


def test_ipv6_icmpv6_echo_request():
    frame = _eth(0x86DD, _ipv6("fe80::1", "ff02::1", 58, _icmp(128)))
    p = analyze_pcap_bytes(_make_pcap(frame))[0]
    assert p["proto"] == "ICMPv6"
    assert "Echo Request" in p["info"]


# ── VLAN ──────────────────────────────────────────────────────────────────────

def test_vlan_tagged_ipv4():
    inner = _ipv4("10.0.0.1", "10.0.0.2", 6, _tcp(1234, 80))
    vlan_tag = struct.pack("!HH", 0x0064, 0x0800)  # VLAN id=100, inner=IPv4
    frame = _ETH_DST + _ETH_SRC + struct.pack("!H", 0x8100) + vlan_tag + inner
    p = analyze_pcap_bytes(_make_pcap(frame))[0]
    assert p["proto"] == "TCP"


# ── Packet ordering / timestamps ──────────────────────────────────────────────

def test_multiple_packets_numbered_correctly():
    f1 = _eth(0x0800, _ipv4("10.0.0.1", "10.0.0.2", 6, _tcp(1, 80)))
    f2 = _eth(0x0806, _arp("10.0.0.1", "10.0.0.2"))
    result = analyze_pcap_bytes(_make_pcap(f1, f2))
    assert len(result) == 2
    assert result[0]["no"] == 1
    assert result[1]["no"] == 2


def test_first_packet_time_is_zero():
    f = _eth(0x0800, _ipv4("1.1.1.1", "2.2.2.2", 6, _tcp(1, 2)))
    result = analyze_pcap_bytes(_make_pcap(f, f))
    assert result[0]["time"] == "0.000000"
    assert float(result[1]["time"]) > 0
