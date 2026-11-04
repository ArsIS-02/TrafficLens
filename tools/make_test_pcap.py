#!/usr/bin/env python3
"""Генератор тестового PCAP для проверки TrafficLens «от и до» (без scapy, только стандартная библиотека).

Сценарий (все адреса — документационные диапазоны RFC 5737):
  * 192.168.1.50 резолвит api.evil-c2.example -> 203.0.113.66;
  * 15 TLS-соединений на 203.0.113.66:8443 с SNI api.evil-c2.example каждые 60 с (маячок);
  * HTTP GET http://198.51.100.23/payload.exe — в ответе тестовый файл EICAR;
  * DGA-подобный DNS-запрос с ответом NXDOMAIN;
  * фоновые обращения к example.com.

    python3 make_test_pcap.py test.pcap
    # IOC для сверки: tools/test-iocs.txt -> <data>/ioc/custom/test.txt
"""
from __future__ import annotations

import struct
import sys
import time

MAC_WS, MAC_GW = bytes.fromhex("aabbcc001122"), bytes.fromhex("aabbcc0000fe")
WS, GW = "192.168.1.50", "192.168.1.1"
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def ip2b(ip: str) -> bytes:
    return bytes(int(x) for x in ip.split("."))


def csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


class Pcap:
    def __init__(self, path: str):
        self.path = path
        self.frames: list[tuple[float, int, bytes]] = []   # пишем в конце, отсортировав по времени
        self.ipid = 1000

    def frame(self, ts: float, src: str, dst: str, proto: int, l4: bytes):
        smac, dmac = (MAC_WS, MAC_GW) if src.startswith("192.168.") else (MAC_GW, MAC_WS)
        self.ipid += 1
        hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), self.ipid & 0xFFFF, 0x4000, 64, proto, 0, ip2b(src), ip2b(dst))
        hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
        pkt = dmac + smac + b"\x08\x00" + hdr + l4
        self.frames.append((ts, len(self.frames), pkt))

    def close(self):
        # Zeek ведёт соединения по времени пакетов: PCAP обязан идти строго по возрастанию ts,
        # иначе каждая «отставшая» сессия распадается на отдельные пакеты-соединения.
        with open(self.path, "wb") as fh:
            fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for ts, _, pkt in sorted(self.frames):
                sec, usec = int(ts), int(round((ts % 1) * 1e6))
                if usec >= 1000000:
                    sec, usec = sec + 1, usec - 1000000
                fh.write(struct.pack("<IIII", sec, usec, len(pkt), len(pkt)) + pkt)

    def _pseudo(self, src, dst, proto, length):
        return ip2b(src) + ip2b(dst) + struct.pack("!BBH", 0, proto, length)

    def udp(self, ts, src, sp, dst, dp, payload: bytes):
        u = struct.pack("!HHHH", sp, dp, 8 + len(payload), 0) + payload
        c = csum(self._pseudo(src, dst, 17, len(u)) + u) or 0xFFFF
        self.frame(ts, src, dst, 17, u[:6] + struct.pack("!H", c) + u[8:])

    def tcp(self, ts, src, sp, dst, dp, seq, ack, flags, payload: bytes = b""):
        t = struct.pack("!HHIIBBHHH", sp, dp, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, 64240, 0, 0) + payload
        c = csum(self._pseudo(src, dst, 6, len(t)) + t)
        self.frame(ts, src, dst, 6, t[:16] + struct.pack("!H", c) + t[18:])

    def session(self, ts, src, sp, dst, dp, client: bytes, server: bytes):
        """Полная TCP-сессия: рукопожатие, данные в обе стороны, FIN."""
        S, A, P, F = 0x02, 0x10, 0x08, 0x01
        cs, ss = 1000, 5000
        self.tcp(ts, src, sp, dst, dp, cs, 0, S)
        self.tcp(ts + .01, dst, dp, src, sp, ss, cs + 1, S | A)
        self.tcp(ts + .02, src, sp, dst, dp, cs + 1, ss + 1, A)
        cs += 1
        ss += 1
        t = ts + .03
        if client:
            self.tcp(t, src, sp, dst, dp, cs, ss, P | A, client)
            cs += len(client)
            t += .01
            self.tcp(t, dst, dp, src, sp, ss, cs, A)
        for i in range(0, len(server), 1400):
            chunk = server[i:i + 1400]
            t += .01
            self.tcp(t, dst, dp, src, sp, ss, cs, P | A, chunk)
            ss += len(chunk)
        t += .01
        self.tcp(t, src, sp, dst, dp, cs, ss, A)
        self.tcp(t + .01, src, sp, dst, dp, cs, ss, F | A)
        self.tcp(t + .02, dst, dp, src, sp, ss, cs + 1, F | A)
        self.tcp(t + .03, src, sp, dst, dp, cs + 1, ss + 1, A)


def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"


def dns_query(qid: int, name: str) -> bytes:
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", 1, 1)


def dns_answer(qid: int, name: str, ip: str | None) -> bytes:
    flags = 0x8180 if ip else 0x8183  # NOERROR / NXDOMAIN
    body = struct.pack("!HHHHHH", qid, flags, 1, 1 if ip else 0, 0, 0) + dns_name(name) + struct.pack("!HH", 1, 1)
    if ip:
        body += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + ip2b(ip)
    return body


def client_hello(sni: str) -> bytes:
    host = sni.encode()
    sni_body = struct.pack("!HBH", len(host) + 3, 0, len(host)) + host
    ext = struct.pack("!HH", 0, len(sni_body)) + sni_body
    ext += struct.pack("!HHH", 10, 4, 2) + b"\x00\x1d"            # supported_groups: x25519
    ext += struct.pack("!HHB", 11, 2, 1) + b"\x00"                  # ec_point_formats
    ext += struct.pack("!HHH", 13, 4, 2) + b"\x04\x03"            # signature_algorithms
    ciphers = b"\xc0\x2f\xc0\x30\x00\x9c"
    body = b"\x03\x03" + bytes(range(32)) + b"\x00" + struct.pack("!H", len(ciphers)) + ciphers + b"\x01\x00"
    body += struct.pack("!H", len(ext)) + ext
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def main(path: str):
    p = Pcap(path)
    t0 = time.time() - 3600
    qid = 0x1000
    sport = 49152

    def resolve(ts, name, ip):
        nonlocal qid, sport
        qid += 1
        sport += 1
        p.udp(ts, WS, sport, GW, 53, dns_query(qid, name))
        p.udp(ts + 0.004, GW, 53, WS, sport, dns_answer(qid, name, ip))

    # фон
    for i in range(10):
        ts = t0 + i * 41
        resolve(ts, "example.com", "93.184.216.34")
        sport += 1
        p.session(ts + .05, WS, sport, "93.184.216.34", 443, client_hello("example.com"), b"")
    # маячок на C2
    resolve(t0 + 29, "api.evil-c2.example", "203.0.113.66")
    for i in range(15):
        sport += 1
        p.session(t0 + 30 + i * 60 + (0.2 if i % 2 else -0.1), WS, sport, "203.0.113.66", 8443, client_hello("api.evil-c2.example"), b"")
    # DGA-подобный NXDOMAIN
    resolve(t0 + 100, "xk3j9qz7vbn2lm4pw8.biz", None)
    # загрузка EICAR по HTTP
    sport += 1
    req = b"GET /payload.exe HTTP/1.1\r\nHost: 198.51.100.23\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nAccept: */*\r\n\r\n"
    resp = (b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n"
            b"Content-Disposition: attachment; filename=\"payload.exe\"\r\n\r\n" % len(EICAR)) + EICAR
    p.session(t0 + 200, WS, sport, "198.51.100.23", 80, req, resp)
    p.close()
    print(f"записан {path}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "trafficlens-test.pcap")
