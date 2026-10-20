#!/usr/bin/env python3
"""Fetch the VPN Gate public list (CSV) and write a compact JSON (no OpenVPN configs)."""
import csv, io, json, os, sys, urllib.request
from datetime import datetime, timezone

SOURCES = ["http://www.vpngate.net/api/iphone/", "https://www.vpngate.net/api/iphone/"]
OUT = sys.argv[1] if len(sys.argv) > 1 else "data/vpngate.json"


def num(v, cast=int):
    try:
        return cast(v)
    except (TypeError, ValueError):
        return None


def fetch():
    last = None
    for url in SOURCES:
        for _ in range(3):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "list-fetcher/1.0"})
                with urllib.request.urlopen(req, timeout=60) as r:
                    return r.read().decode("utf-8", "replace")
            except Exception as e:  # noqa: BLE001
                last = e
                print(f"warn: {url}: {e}", file=sys.stderr)
    raise SystemExit(f"all sources failed: {last}")


def main():
    text = fetch()
    lines = [l for l in text.splitlines() if l.strip() and not l.startswith("*")]
    if not lines or not lines[0].startswith("#"):
        raise SystemExit("unexpected format")
    lines[0] = lines[0][1:]
    servers, seen = [], set()
    for row in csv.DictReader(io.StringIO("\n".join(lines))):
        ip = (row.get("IP") or "").strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)
        h = (row.get("HostName") or "").strip()
        servers.append({
            "hostname": f"{h}.opengw.net" if h else ip,
            "ip": ip,
            "country": (row.get("CountryShort") or "").strip()[:2].upper(),
            "score": num(row.get("Score")),
            "ping": num(row.get("Ping")),
            "speed": num(row.get("Speed")),
            "uptime": num(row.get("Uptime")),
        })
    if len(servers) < 5:
        raise SystemExit(f"too few servers ({len(servers)}), not overwriting")
    servers.sort(key=lambda s: -(s["score"] or 0))
    doc = {"version": 1, "source": "vpngate",
           "fetched_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
           "count": len(servers), "servers": servers}
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(doc, f, separators=(",", ":"))
        f.write("\n")
    print(f"wrote {len(servers)} servers to {OUT}")


if __name__ == "__main__":
    main()
