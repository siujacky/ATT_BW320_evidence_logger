# Natural Earth 1:110m countries (world-atlas 2.0.2 TopoJSON, public domain data, ISC packaging)
# -> Equal Earth projection -> SVG paths keyed by ISO 3166-1 alpha-2, Antarctica left out.
import json
import math
import sys

import pycountry

SRC = sys.argv[1]
OUT = sys.argv[2]
WIDTH = 1000.0

topo = json.load(open(SRC, encoding="utf-8"))
sx, sy = topo["transform"]["scale"]
tx, ty = topo["transform"]["translate"]

arcs = []
for arc in topo["arcs"]:
    x = y = 0
    pts = []
    for dx, dy in arc:
        x += dx
        y += dy
        pts.append((x * sx + tx, y * sy + ty))
    arcs.append(pts)

A1, A2, A3, A4 = 1.340264, -0.081106, 0.000893, 0.003796
M = math.sqrt(3) / 2


def equal_earth(lon, lat):
    lam, phi = math.radians(lon), math.radians(lat)
    th = math.asin(M * math.sin(phi))
    t2 = th * th
    t6 = t2 * t2 * t2
    x = 2 * math.sqrt(3) * lam * math.cos(th) / (3 * (9 * A4 * t6 * t2 + 7 * A3 * t6 + 3 * A2 * t2 + A1))
    y = th * (A4 * t6 * t2 + A3 * t6 + A2 * t2 + A1)
    return x, y


XMAX = equal_earth(180, 0)[0]
YMAX = equal_earth(0, 90)[1]
K = WIDTH / (2 * XMAX)


def ring_points(ring):
    pts = []
    for i, a in enumerate(ring):
        seq = arcs[a] if a >= 0 else list(reversed(arcs[~a]))
        pts.extend(seq if i == 0 else seq[1:])
    return pts


def unwrap(pts):
    """Make a ring continuous in longitude across the antimeridian (may leave [-180, 180])."""
    out = [pts[0]]
    shift = 0.0
    for (lon0, _), (lon, lat) in zip(pts, pts[1:]):
        d = lon - lon0
        if d > 180:
            shift -= 360
        elif d < -180:
            shift += 360
        out.append((lon + shift, lat))
    return out


def clip(pts, lo, hi):
    """Sutherland-Hodgman clip of a closed ring to lo <= lon <= hi."""
    def cut(ring, inside, edge):
        res = []
        n = len(ring)
        for i in range(n):
            cur, prev = ring[i], ring[i - 1]
            ci, pi = inside(cur), inside(prev)
            if ci:
                if not pi:
                    res.append(edge(prev, cur))
                res.append(cur)
            elif pi:
                res.append(edge(prev, cur))
        return res

    def at(lon_edge):
        def f(a, b):
            t = (lon_edge - a[0]) / (b[0] - a[0])
            return (lon_edge, a[1] + t * (b[1] - a[1]))
        return f

    r = cut(pts, lambda p: p[0] >= lo, at(lo))
    if r:
        r = cut(r, lambda p: p[0] <= hi, at(hi))
    return r


def pieces(ring):
    """The ring as one or more rings inside [-180, 180]."""
    u = unwrap(ring)
    lo, hi = min(p[0] for p in u), max(p[0] for p in u)
    if lo >= -180 and hi <= 180:
        return [u]
    out = []
    for k in range(-2, 3):
        off = 360 * k
        part = clip(u, -180 + off, 180 + off)
        if len(part) >= 3:
            out.append([(lon - off, lat) for lon, lat in part])
    return out


def project(pts):
    out = []
    for lon, lat in pts:
        x, y = equal_earth(lon, lat)
        out.append(((x + XMAX) * K, (YMAX - y) * K))
    return out


numeric = {c.numeric: c for c in pycountry.countries}
special = {"N. Cyprus": "CY", "Somaliland": "SO", "Kosovo": "XK"}

countries = []
ymax_seen = 0.0
for g in topo["objects"]["countries"]["geometries"]:
    name = g.get("properties", {}).get("name", "")
    cid = g.get("id")
    if cid == "010":  # Antarctica
        continue
    if cid and cid in numeric:
        a2 = numeric[cid].alpha_2
    elif name in special:
        a2 = special[name]
    else:
        print("no ISO code for", cid, name, file=sys.stderr)
        continue
    polys = g["arcs"] if g["type"] == "MultiPolygon" else [g["arcs"]] if g["type"] == "Polygon" else []
    parts = []
    for poly in polys:
        for ring0 in poly:
          for piece in pieces(ring_points(ring0)):
            pts = project(piece)
            # Drop consecutive duplicates after rounding to 0.1 px.
            r = []
            for x, y in pts:
                p = (round(x, 1), round(y, 1))
                if not r or r[-1] != p:
                    r.append(p)
            if len(r) < 3:
                continue
            ymax_seen = max(ymax_seen, max(p[1] for p in r))
            d = "M" + " ".join("%g,%g" % p for p in r[:1]) + "L" + " ".join("%g,%g" % p for p in r[1:]) + "Z"
            parts.append(d)
    if parts:
        countries.append({"id": a2, "n": name, "d": "".join(parts)})

height = math.ceil(ymax_seen + 2)
# world-atlas's ISC licence asks for its copyright and permission notice in every copy: the map
# carries it (THIRD_PARTY_NOTICES.md at the top of the repository has it too).
LICENSE = ("world-atlas 2.0.2: Copyright 2013-2019 Michael Bostock. Permission to use, copy, modify, and/or distribute this software "
           "for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission "
           "notice appear in all copies. THE SOFTWARE IS PROVIDED \"AS IS\" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO "
           "THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR "
           "ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR "
           "PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE "
           "USE OR PERFORMANCE OF THIS SOFTWARE. (THIRD_PARTY_NOTICES.md)")
out = {"source": "Natural Earth 1:110m Admin 0 countries v4.1.0 (public domain) via world-atlas 2.0.2 (ISC); Equal Earth projection; Antarctica omitted; licence: see \"license\" and THIRD_PARTY_NOTICES.md",
       "license": LICENSE, "w": int(WIDTH), "h": height, "countries": sorted(countries, key=lambda c: c["id"])}
json.dump(out, open(OUT, "w", encoding="utf-8"), separators=(",", ":"), ensure_ascii=False)
print("countries:", len(countries), "| viewBox 0 0", int(WIDTH), height, "| bytes:", len(json.dumps(out, separators=(",", ":"))))
