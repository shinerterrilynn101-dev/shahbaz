#!/usr/bin/env python3
"""Merge results/*.json with data/vpngate.json into data/list.json and sign it (Ed25519)."""
import base64, glob, json, os, statistics, sys
from datetime import datetime, timezone, timedelta

MAX_AGE = timedelta(hours=3)   # ignore scanner results older than this
TOP = 100


def parse_ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(d):
    return d.isoformat().replace("+00:00", "Z")


def main():
    vg = {}
    try:
        with open("data/vpngate.json", encoding="utf-8") as f:
            for s in json.load(f).get("servers", []):
                vg[s["ip"]] = s
    except FileNotFoundError:
        pass

    t = now()
    agg, scanners = {}, []
    for path in sorted(glob.glob("results/*.json")):
        try:
            with open(path, encoding="utf-8") as f:
                r = json.load(f)
            ts = parse_ts(r["generated_at"])
        except Exception as e:  # noqa: BLE001
            print(f"skip {path}: {e}", file=sys.stderr)
            continue
        if t - ts > MAX_AGE:
            print(f"skip stale {path} ({r['generated_at']})", file=sys.stderr)
            continue
        scanners.append(r.get("scanner_id") or os.path.basename(path)[:-5])
        for x in r.get("results", []):
            key = (x["ip"], int(x.get("port", 443)))
            a = agg.setdefault(key, {"host": x.get("host") or x["ip"], "ok": 0, "n": 0,
                                     "lat": [], "last_ok": None, "scanners_ok": 0})
            att = int(x.get("attempts", 1))
            ok = int(x.get("ok", 0))
            a["n"] += att
            a["ok"] += ok
            if ok:
                a["scanners_ok"] += 1
                if x.get("latency_ms") is not None:
                    a["lat"].append(float(x["latency_ms"]))
                if a["last_ok"] is None or ts > a["last_ok"]:
                    a["last_ok"] = ts

    servers = []
    for (ip, port), a in agg.items():
        if not a["ok"] or not a["n"]:
            continue
        rate = a["ok"] / a["n"]
        lat = round(statistics.median(a["lat"])) if a["lat"] else 2000
        score = 100.0 * rate * min(1.0, max(0.05, 1 - lat / 2000.0))
        v = vg.get(ip, {})
        servers.append({
            "host": a["host"], "ip": ip, "port": port,
            "country": v.get("country", ""),
            "latency_ms": lat, "success_rate": round(rate, 2), "score": round(score, 1),
            "last_ok": iso(a["last_ok"]) if a["last_ok"] else None,
            "scanners_ok": a["scanners_ok"],
            "vpngate_score": v.get("score"), "speed": v.get("speed"),
        })
    servers.sort(key=lambda s: (-s["score"], s["latency_ms"]))
    servers = servers[:TOP]

    doc = {"version": 1, "generated_at": iso(t), "scanner_id": "agg",
           "scanners": sorted(scanners), "count": len(servers), "servers": servers}
    data = (json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")

    seed_b64 = os.environ.get("SIGNING_KEY", "").strip()
    if not seed_b64:
        raise SystemExit("SIGNING_KEY not set")
    import nacl.signing
    sk = nacl.signing.SigningKey(base64.b64decode(seed_b64))
    sig = base64.b64encode(sk.sign(data).signature).decode()
    pub = base64.b64encode(bytes(sk.verify_key)).decode()
    with open("data/public_key.txt", encoding="utf-8") as f:
        if f.read().strip() != pub:
            raise SystemExit("SIGNING_KEY does not match data/public_key.txt")

    with open("data/list.json", "wb") as f:
        f.write(data)
    with open("data/list.json.sig", "w") as f:
        f.write(sig + "\n")
    print(f"list.json: {len(servers)} servers from scanners {scanners}")


if __name__ == "__main__":
    main()
