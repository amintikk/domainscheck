#!/usr/bin/env python3
"""Domain availability checker via WHOIS (async, no deps)."""
from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


NOT_FOUND_PHRASES = [
    "no match for",
    "not found",
    "no data found",
    "no entries found",
    "status: free",
    "status: available",
    "domain status: available",
    "the queried object does not exist",
    "domain name not known",
    "no such domain",
]

RATE_LIMIT_PHRASES = [
    "limit exceeded",
    "quota exceeded",
    "too many requests",
    "maximum of",
    "try again later",
    "temporarily restricted",
]

COMMON_WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "biz": "whois.biz",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "ai": "whois.nic.ai",
    "app": "whois.nic.google",
    "dev": "whois.nic.google",
}

FIELD_PATTERNS = {
    "registrar": [r"Registrar:\s*(.+)", r"Sponsoring Registrar:\s*(.+)"],
    "created": [
        r"Creation Date:\s*(.+)",
        r"Created On:\s*(.+)",
        r"Domain Registration Date:\s*(.+)",
        r"created:\s*(.+)",
    ],
    "expires": [
        r"Registry Expiry Date:\s*(.+)",
        r"Expiration Date:\s*(.+)",
        r"Expiry Date:\s*(.+)",
        r"paid-till:\s*(.+)",
        r"expires:\s*(.+)",
    ],
    "updated": [
        r"Updated Date:\s*(.+)",
        r"Last Updated On:\s*(.+)",
        r"changed:\s*(.+)",
    ],
}


@dataclass
class Result:
    domain: str
    available: Optional[bool]
    whois_server: str
    raw: str
    order: int
    registrar: Optional[str] = None
    created: Optional[str] = None
    expires: Optional[str] = None
    updated: Optional[str] = None
    note: Optional[str] = None


class Ansi:
    RESET = "\x1b[0m"
    BOLD = "\x1b[1m"
    DIM = "\x1b[2m"
    RED = "\x1b[31m"
    GREEN = "\x1b[32m"
    YELLOW = "\x1b[33m"
    CYAN = "\x1b[36m"
    GRAY = "\x1b[90m"


def enable_ansi() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_ulong()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)) == 0:
            return False
        mode.value |= 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        if kernel32.SetConsoleMode(handle, mode) == 0:
            return False
        return True
    except Exception:
        return False


def c(text: str, color: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{color}{text}{Ansi.RESET}"


def sanitize_domain(line: str) -> Optional[str]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    # Keep first token, remove protocol and paths
    token = line.split()[0]
    token = re.sub(r"^https?://", "", token, flags=re.I)
    token = token.split("/")[0]
    token = token.strip(".")
    if not token:
        return None
    return token.lower()


async def query_whois(server: str, query: str, timeout: float) -> str:
    async def _do() -> str:
        reader, writer = await asyncio.open_connection(server, 43)
        writer.write((query + "\r\n").encode("utf-8", errors="ignore"))
        await writer.drain()
        data = bytearray()
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                break
            data.extend(chunk)
        writer.close()
        if hasattr(writer, "wait_closed"):
            await writer.wait_closed()
        return data.decode("utf-8", errors="replace")

    return await asyncio.wait_for(_do(), timeout=timeout)


def parse_first(patterns: List[str], text: str) -> Optional[str]:
    for pat in patterns:
        m = re.search(pat, text, flags=re.I)
        if not m:
            continue
        if m.lastindex:
            for i in range(1, m.lastindex + 1):
                value = m.group(i)
                if value:
                    return value.strip()
        return m.group(0).strip()
    return None


def detect_rate_limit(text: str) -> bool:
    t = text.lower()
    return any(p in t for p in RATE_LIMIT_PHRASES)


def detect_available(text: str, server: str, domain: str) -> Optional[bool]:
    t = text.lower()
    if any(p in t for p in NOT_FOUND_PHRASES):
        # Heuristic: if it explicitly says not found / available
        return True
    if server == "whois.iana.org" and "." in domain:
        return None

    taken_signals = [
        "registry domain id",
        "registrar:",
        "creation date:",
        "created on:",
        "updated date:",
        "expiry date:",
        "expiration date:",
        "registrant:",
        "name server:",
        "nserver:",
    ]
    if "domain name:" in t and any(s in t for s in taken_signals):
        return False
    if "domain:" in t and any(s in t for s in taken_signals):
        return False
    return None


async def query_whois_with_retries(
    server: str,
    query: str,
    timeout: float,
    retries: int = 2,
    backoff: float = 0.35,
) -> str:
    last_exc: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            return await query_whois(server, query, timeout=timeout)
        except Exception as exc:
            last_exc = exc
            if attempt < retries:
                await asyncio.sleep(backoff * (attempt + 1))
                continue
            raise
    assert last_exc is not None
    raise last_exc


async def get_whois_server(tld: str, cache: Dict[str, str], timeout: float) -> str:
    if tld in cache:
        return cache[tld]
    if tld in COMMON_WHOIS_SERVERS:
        cache[tld] = COMMON_WHOIS_SERVERS[tld]
        return cache[tld]
    try:
        resp = await query_whois_with_retries("whois.iana.org", tld, timeout=timeout, retries=1)
    except Exception:
        cache[tld] = "whois.iana.org"
        return cache[tld]
    m = re.search(r"refer:\s*(\S+)", resp, flags=re.I)
    if not m:
        m = re.search(r"whois:\s*(\S+)", resp, flags=re.I)
    server = m.group(1).strip() if m else "whois.iana.org"
    cache[tld] = server
    return server


async def check_domain(
    domain: str,
    order: int,
    cache: Dict[str, str],
    timeout: float,
    sem: asyncio.Semaphore,
) -> Result:
    tld = domain.rsplit(".", 1)[-1]
    async with sem:
        server = await get_whois_server(tld, cache, timeout)
        try:
            resp = await query_whois_with_retries(server, domain, timeout=timeout, retries=2)
        except asyncio.TimeoutError:
            return Result(
                domain=domain,
                available=None,
                whois_server=server,
                raw="",
                order=order,
                note="timeout",
            )
        except Exception as exc:
            return Result(
                domain=domain,
                available=None,
                whois_server=server,
                raw="",
                order=order,
                note=f"error: {exc}",
            )

    result = Result(domain=domain, available=None, whois_server=server, raw=resp, order=order)

    if detect_rate_limit(resp):
        result.available = None
        result.note = "rate limit"
        return result

    result.available = detect_available(resp, server, domain)

    if result.available is None and server == "whois.iana.org":
        result.note = "iana fallback"

    if result.available is False:
        result.registrar = parse_first(FIELD_PATTERNS["registrar"], resp)
        result.created = parse_first(FIELD_PATTERNS["created"], resp)
        result.expires = parse_first(FIELD_PATTERNS["expires"], resp)
        result.updated = parse_first(FIELD_PATTERNS["updated"], resp)

    return result


def format_result(result: Result, width: int, use_color: bool) -> str:
    if result.available is True:
        status = c("[OK]", Ansi.GREEN, use_color)
        state = c("AVAILABLE", Ansi.GREEN, use_color)
    elif result.available is False:
        status = c("[X]", Ansi.RED, use_color)
        state = c("TAKEN", Ansi.RED, use_color)
    else:
        status = c("[?]", Ansi.YELLOW, use_color)
        state = c("UNKNOWN", Ansi.YELLOW, use_color)

    domain_col = result.domain.ljust(width)
    parts = [status, domain_col, state]

    meta: List[str] = []
    meta.append(f"WHOIS: {result.whois_server}")
    if result.registrar:
        meta.append(f"Registrar: {result.registrar}")
    if result.created:
        meta.append(f"Created: {result.created}")
    if result.expires:
        meta.append(f"Expires: {result.expires}")
    if result.updated:
        meta.append(f"Updated: {result.updated}")
    if result.note:
        meta.append(f"Note: {result.note}")

    meta_str = " | ".join(meta)
    if meta_str:
        meta_str = " " + c(meta_str, Ansi.GRAY, use_color)

    return " ".join(parts) + meta_str


def print_header(width: int, use_color: bool) -> None:
    line = f"{'':3} {'DOMAIN'.ljust(width)} STATUS  DETAILS"
    print(c(line, Ansi.CYAN, use_color))
    print(c("-" * (3 + 1 + width + 1 + 6 + 2 + 7), Ansi.GRAY, use_color))


def load_domains(path: Path) -> List[str]:
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")
    items: List[str] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        d = sanitize_domain(line)
        if d:
            items.append(d)
    # de-dup while preserving order
    seen = set()
    result = []
    for d in items:
        if d in seen:
            continue
        seen.add(d)
        result.append(d)
    return result


async def main_async(args: argparse.Namespace) -> int:
    domains = load_domains(Path(args.input))
    if not domains:
        print("No domains found in input.")
        return 1

    use_color = args.color and enable_ansi()

    width = max(len(d) for d in domains)
    width = max(width, 8)

    sem = asyncio.Semaphore(args.concurrency)
    cache: Dict[str, str] = {}

    print_header(width, use_color)

    tasks = [check_domain(d, i, cache, args.timeout, sem) for i, d in enumerate(domains)]
    results: List[Result] = []

    for coro in asyncio.as_completed(tasks):
        res = await coro
        results.append(res)
        print(format_result(res, width, use_color))

    available = [r.domain for r in sorted(results, key=lambda r: r.order) if r.available is True]

    if args.output:
        Path(args.output).write_text("\n".join(available) + ("\n" if available else ""), encoding="utf-8")
        print(c(f"\nSaved {len(available)} available domains to {args.output}", Ansi.CYAN, use_color))

    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Check domain availability from a .txt list using WHOIS (async, no deps)."
    )
    p.add_argument("input", help="Input .txt with one domain per line")
    p.add_argument("-o", "--output", default="available.txt", help="Output .txt for available domains")
    p.add_argument("-c", "--concurrency", type=int, default=12, help="Concurrent WHOIS queries")
    p.add_argument("-t", "--timeout", type=float, default=10.0, help="Timeout per WHOIS query (seconds)")
    p.add_argument("--no-color", dest="color", action="store_false", help="Disable colored output")
    p.set_defaults(color=True)
    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
