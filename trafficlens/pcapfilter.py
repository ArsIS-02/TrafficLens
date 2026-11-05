"""Обрезка PCAP перед анализом: BPF-фильтр (через tcpdump) и/или окно времени.

Поддерживаются classic pcap (LE/BE, микро- и наносекундные метки) и pcapng
(EPB/PB фильтруются по метке времени, SPB без метки при активном окне
отбрасывается). Ошибки BPF приводят к ValueError — их показывает веб-слой.
"""
from __future__ import annotations

import shutil
import struct
import subprocess
from pathlib import Path

# первые 4 байта файла -> (порядок байт, множитель к секундам)
_PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
_PCAPNG_SHB = 0x0A0D0D0A
_PCAPNG_IDB = 0x00000001
_PCAPNG_PB = 0x00000002   # obsolete Packet Block
_PCAPNG_SPB = 0x00000003
_PCAPNG_EPB = 0x00000006


def _trim_classic(fi, fo, ts_from: float | None, ts_to: float | None) -> tuple[int, int]:
    head = fi.read(24)
    if len(head) < 24:
        raise ValueError("файл слишком короткий для pcap")
    endian, mult = _PCAP_MAGIC[head[:4]]
    fo.write(head)
    kept = total = 0
    while True:
        rh = fi.read(16)
        if not rh:
            break
        if len(rh) < 16:
            break
        sec, frac, incl, _orig = struct.unpack(endian + "IIII", rh)
        data = fi.read(incl)
        if len(data) < incl:
            break
        total += 1
        ts = sec + frac * mult
        if (ts_from is None or ts >= ts_from) and (ts_to is None or ts < ts_to):
            fo.write(rh + data)
            kept += 1
    return kept, total


def _tsresol(body: bytes, endian: str) -> float:
    """Разрешение меток интерфейса из опций IDB (if_tsresol, код 9)."""
    opts = body[8:]
    while len(opts) >= 4:
        code, ln = struct.unpack(endian + "HH", opts[:4])
        val = opts[4:4 + ln]
        if code == 0:
            break
        if code == 9 and val:
            b = val[0]
            return 2.0 ** -(b & 0x7F) if b & 0x80 else 10.0 ** -b
        opts = opts[4 + ((ln + 3) & ~3):]
    return 1e-6


def _trim_pcapng(fi, fo, ts_from: float | None, ts_to: float | None) -> tuple[int, int]:
    kept = total = 0
    resol: dict[int, float] = {}
    endian = "<"
    while True:
        bh = fi.read(8)
        if len(bh) < 8:
            break
        btype, blen = struct.unpack(endian + "II", bh)
        if blen < 12 or blen > 64 * 1024 * 1024:
            btype_be, blen_be = struct.unpack(">II", bh)
            if endian == "<" and btype_be == _PCAPNG_SHB and 28 <= blen_be <= 64 * 1024 * 1024:
                btype, blen, endian = btype_be, blen_be, ">"  # секция big-endian
            else:
                break
        rest = fi.read(blen - 8)
        if len(rest) < blen - 8:
            break
        body = rest[:-4]
        if btype == _PCAPNG_SHB:
            endian = ">" if body[:4] == b"\x1a\x2b\x3c\x4d" else "<"  # byte-order magic
            resol = {}
            fo.write(bh + rest)
        elif btype == _PCAPNG_IDB:
            if len(body) >= 8:
                resol[len(resol)] = _tsresol(body, endian)
            fo.write(bh + rest)
        elif btype in (_PCAPNG_EPB, _PCAPNG_PB) and len(body) >= 20:
            if btype == _PCAPNG_EPB:
                iface, tsh, tsl = struct.unpack(endian + "III", body[:12])
            else:
                iface, tsh, tsl = struct.unpack(endian + "HxxII", body[:12])
            total += 1
            ts = ((tsh << 32) | tsl) * resol.get(iface, 1e-6)
            if (ts_from is None or ts >= ts_from) and (ts_to is None or ts < ts_to):
                fo.write(bh + rest)
                kept += 1
        elif btype == _PCAPNG_SPB:
            total += 1  # у SPB нет метки времени — при активном окне отбрасываем
        else:
            fo.write(bh + rest)
    return kept, total


def trim_time(src: Path, dst: Path, ts_from: float | None, ts_to: float | None) -> tuple[int, int]:
    """Оставить пакеты в окне [ts_from, ts_to). Возвращает (оставлено, было)."""
    with src.open("rb") as fi:
        magic = fi.read(4)
        fi.seek(0)
        with dst.open("wb") as fo:
            if magic in _PCAP_MAGIC:
                return _trim_classic(fi, fo, ts_from, ts_to)
            if magic == b"\x0a\x0d\x0d\x0a":
                return _trim_pcapng(fi, fo, ts_from, ts_to)
    raise ValueError("неизвестный формат: не pcap/pcapng")


def run_bpf(src: Path, dst: Path, bpf: str) -> None:
    """Применить BPF-выражение через tcpdump. Невалидное выражение -> ValueError."""
    import shlex

    tcpdump = shutil.which("tcpdump")
    if not tcpdump:
        raise ValueError("tcpdump не найден")
    try:
        tokens = shlex.split(bpf)
    except ValueError as e:
        raise ValueError(f"некорректное выражение: {e}") from None
    p = subprocess.run([tcpdump, "-r", str(src), "-w", str(dst), *tokens],
                       capture_output=True, text=True, timeout=300)
    if p.returncode != 0:
        tail = (p.stderr or "").strip().splitlines()
        raise ValueError(tail[-1][:200] if tail else f"tcpdump rc={p.returncode}")


def filter_pcap(src: Path, dst: Path, bpf: str = "", ts_from: float | None = None, ts_to: float | None = None) -> dict:
    """Применить BPF и/или окно времени. Возвращает описание фильтра для сводки задачи."""
    if not bpf and ts_from is None and ts_to is None:
        shutil.copyfile(src, dst)
        return {}
    cur = src
    tmp = dst.with_suffix(dst.suffix + ".bpf")
    try:
        if bpf:
            run_bpf(cur, tmp, bpf)
            cur = tmp
        if ts_from is not None or ts_to is not None:
            trim_time(cur, dst, ts_from, ts_to)
        elif cur != dst:
            shutil.move(str(cur), str(dst))
    finally:
        tmp.unlink(missing_ok=True)
    return {"bpf": bpf, "from": ts_from, "to": ts_to}
