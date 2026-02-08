# DomainsCheck

![Python](https://img.shields.io/badge/python-3.8+-blue)
![Async](https://img.shields.io/badge/asyncio-fast-green)
![WHOIS](https://img.shields.io/badge/whois-no%20deps-orange)

A fast, clean WHOIS-based domain availability checker that reads a list of domains,
prints a polished result table in the terminal, and writes available domains to a file.

## Features
- Async WHOIS lookups for speed
- Clean, colored terminal output with status icons
- Writes a plain text list of available domains
- No external dependencies

## Quick Start
```bash
python check_domains.py domains.txt -o available.txt
```

## Input File
- One domain per line
- Comments with `#` are ignored
- URLs are accepted and cleaned (http/https and paths are removed)

## Output File
- `available.txt` contains only available domains, one per line

## Options
```bash
python check_domains.py domains.txt -o available.txt -c 12 -t 10
```
- `-c, --concurrency` number of concurrent WHOIS queries
- `-t, --timeout` timeout per WHOIS query (seconds)
- `--no-color` disable ANSI colors

## Notes
WHOIS servers can rate-limit or drop connections if you query too fast.
If you see UNKNOWN results, lower concurrency and increase timeout.
