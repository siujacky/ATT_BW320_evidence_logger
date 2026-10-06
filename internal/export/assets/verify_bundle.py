#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_bundle.py - independent verifier for att-monitor evidence bundles.

Usage:
    python verify_bundle.py BUNDLE.zip              verify a bundle (zip or extracted folder)
    python verify_bundle.py --inspect-token FILE    show the content of an RFC 3161 token

Requires Python 3.9 or newer and nothing else. Optional extras:
  * the 'cryptography' package (pip install cryptography) to check Ed25519 signatures quickly,
    or --pure-python-ed25519 to check them with the slow built-in RFC 8032 implementation;
  * 'openssl' (OpenSSL 1.1.1 or newer) on PATH to verify the RFC 3161 time-stamp tokens: their
    TSA signatures and certificate chains, at each token's own time, against keys/tsa-roots.pem.

What is checked:
  1. MANIFEST.sha256 lists every file of the bundle and every SHA-256 matches.
  2. Every ledger record (one JSON envelope per line): sha256(b) == h.
  3. The hash chain: seq increases by exactly 1 and prev == h of the previous record, inside each
     segment and across consecutive segments; every segment_open record matches the previous
     segment's SHA-256, record count and last seq. A bundle holds the genesis segment plus one
     contiguous run of daily segments: segments left out between the two are reported as a
     note (the chain across them can only be checked on the full ledger), a segment missing
     anywhere else means it was removed from the bundle and is a failure.
  4. Every blob referenced by a record exists as blobs/<sha256> and matches its hash.
  5. Ed25519 signatures, with the public key from the genesis record (seq 0).
  6. Anchor records: head_hash equals the hash of record head_seq; the token file is the one the
     record names (token_sha256); the RFC 3161 token's message imprint equals head_hash
     (built-in DER reader). With openssl, every token (see --openssl-limit) is verified with
         openssl ts -verify -attime <genTime as Unix seconds> -digest <head_hash>
                 -in <token> -CAfile <trusted TSA roots>
     (TSA signature, certificate chain at the token's genTime, message imprint). The trusted
     roots are the certificates of keys/tsa-roots.pem whose SHA-256 is one of the default TSA
     roots known to this script (DigiCert Trusted Root G4, FreeTSA) or is named with
     --trust-root: the bundle's producer writes keys/tsa-roots.pem, so any other root in it
     is NOT trusted - a token that verifies only against such a root is not proof of time (a
     warning says so). A token that fails against every root is not proof of time and the
     bundle FAILS. Without openssl or the roots file the TSA signatures and chains are NOT
     verified (a warning says so; the command is printed). Time-stamps are labelled with the
     subject of the certificate that signed the token, not with the TSA the record names.
     An anchor record stating that the monitoring computer could not verify the TSA certificate
     chain when the token was obtained (chain_ok=false) is listed in the notes with its chain_note.
  7. Record times against the trusted time-stamps (the checks of the att-monitor ledger
     verifier, failure class ts_contradiction, tolerance 5 minutes). A time-stamp is trusted
     when openssl verified its token against a trusted TSA root (see 6) - or, when openssl does
     not run, when its anchor record states that the token verified and its TSA certificate
     chained when it was obtained (verified and chain_ok) - and its head check and token passed
     the built-in checks. An anchor record holds the SHA-256 of a token that did not exist before
     the token's genTime, so every record from that anchor record on (itself included) was
     written after that genTime: a record dated more than 5 minutes before the latest trusted
     genTime preceding it FAILS (back-dated, or the clock was behind). The token time-stamps the
     hash of record head_seq, which commits to every earlier record: a record up to head_seq
     dated more than 5 minutes after that genTime FAILS (forward-dated, or the clock was ahead).
     Contradictions over consecutive anchoring windows are one failure, naming the worst record.
     Record times that go back more than 5 minutes against an earlier record are listed in the
     notes, with the clock_jump record or the writer's integrity_alert about the clock that
     documents the step, if any.
  8. REPORT.html, report.json and README.txt are NOT verified: their figures were computed by
     the exporting software, and MANIFEST.sha256 cannot protect them (anyone can recompute
     it). This script cannot re-run the report's analysis: it checks that report.json
     describes the ledger records of this bundle and says plainly that its figures were not
     verified; 'att-monitor verify-bundle' recomputes the report from the records and fails if
     any figure differs.
  9. Syslog chunks (syslog/<name>: the gateway's syslog messages as the monitoring computer's
     syslog store kept them, gzip, one JSON message per line): each must be named by a
     syslog_chunk record of this bundle, decompress, and match the SHA-256, size and message
     (line) count of the uncompressed content that record states. Chunks of the period
     (report.json) that are not in the bundle are listed in the notes, not failed: deleted by the
     store's retention limit (a syslog_prune record of this bundle names them) or no longer kept
     at export; their records still state their SHA-256.

Exit code: 0 = every check that ran passed, 1 = at least one check failed, 2 = usage or I/O error.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import calendar
import datetime as _dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unicodedata
import zipfile
import zlib
from array import array

VERSION = "1.3"
ZERO_HASH = "0" * 64
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SEGMENT_RE = re.compile(r"^ledger/(ledger-[0-9]{4}-[0-9]{2}-[0-9]{2})\.jsonl$")
MANIFEST = "MANIFEST.sha256"
MANIFEST_LINE = re.compile(r"^([0-9a-f]{64}) [ *](.+)$")
PUBKEY_LINE = re.compile(r"^Public key \(base64\):\s*(\S+)\s*$", re.M)

ROOTS = "keys/tsa-roots.pem"
PEM_CERT = re.compile(rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", re.S)
# Root certificates of the default Time-Stamp Authorities (SHA-256 of the DER certificate), as
# published by DigiCert and FreeTSA.
KNOWN_ROOTS = {
    "552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988": "DigiCert Trusted Root G4",
    "a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc": "FreeTSA root CA (www.freetsa.org)",
}
OID_NAMES = {"2.5.4.3": "CN", "2.5.4.11": "OU", "2.5.4.10": "O", "2.5.4.7": "L", "2.5.4.6": "C"}

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"


# ---------------------------------------------------------------------------- results


class Results:
    """Collects failures (verification fails), warnings (not checked) and notes."""

    def __init__(self):
        self.failures = []
        self.warnings = []
        self.notes = []
        self.lines = []

    def fail(self, msg):
        self.failures.append(msg)

    def warn(self, msg):
        self.warnings.append(msg)

    def note(self, msg):
        self.notes.append(msg)

    def say(self, label, text):
        self.lines.append("%-17s %s" % (label, text))


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def group4(hexstr):
    return " ".join(hexstr[i:i + 4] for i in range(0, len(hexstr), 4))


def one_line(text, limit=400):
    """Recorded text for one output line: control and format characters become spaces."""
    text = "".join(" " if unicodedata.category(ch)[0] == "C" else ch for ch in str(text))
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit] + "..."


def terminal_text(text):
    """text as it may be printed: every control, format or other non-printing character (Unicode
    category C) is shown as an escape such as \\x1b or \\u202e. Names and values taken from a bundle
    can therefore not move the cursor, erase or hide lines (a forged "RESULT: PASS") or reorder the
    output, whatever check prints them."""
    out = []
    for ch in str(text):
        if unicodedata.category(ch)[0] != "C":
            out.append(ch)
            continue
        o = ord(ch)
        out.append("\\x%02x" % o if o < 0x100 else "\\u%04x" % o if o < 0x10000 else "\\U%08x" % o)
    return "".join(out)


# ---------------------------------------------------------------------------- bundle access


# Control, format, private-use and surrogate characters (Unicode category C less the unassigned
# code points, as the Go verifier's unicode.C): never part of a name att-monitor writes.
UNSAFE_NAME_CATEGORIES = ("Cc", "Cf", "Co", "Cs")


def safe_name(name):
    """True for a relative, forward-slash path without '..', drive letters, or control, format or
    other non-printing characters."""
    if not name or "\\" in name or "\x00" in name or name.startswith("/"):
        return False
    if re.match(r"^[A-Za-z]:", name):
        return False
    if any(unicodedata.category(ch) in UNSAFE_NAME_CATEGORIES for ch in name):
        return False
    parts = name.split("/")
    return all(p not in ("", ".", "..") for p in parts)


class Source:
    """Read-only access to a bundle given as a .zip file or as an extracted folder."""

    def __init__(self, path):
        self.path = path
        self.zip = None
        self.root = None
        self.names = []
        self.duplicates = []
        if os.path.isdir(path):
            self.root = path
            for dirpath, dirnames, filenames in os.walk(path):
                dirnames.sort()
                for fn in sorted(filenames):
                    full = os.path.join(dirpath, fn)
                    self.names.append(os.path.relpath(full, path).replace(os.sep, "/"))
        else:
            self.zip = zipfile.ZipFile(path)
            seen = set()
            for info in self.zip.infolist():
                n = info.filename
                if n.endswith("/"):
                    continue
                if n in seen:
                    self.duplicates.append(n)
                seen.add(n)
                self.names.append(n)
        self.nameset = set(self.names)

    @property
    def is_zip(self):
        return self.zip is not None

    def _open(self, name):
        if self.zip is not None:
            return self.zip.open(name)
        return open(os.path.join(self.root, *name.split("/")), "rb")

    def read(self, name):
        with self._open(name) as f:
            return f.read()

    def sha256(self, name):
        h = hashlib.sha256()
        with self._open(name) as f:
            while True:
                chunk = f.read(1 << 20)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def close(self):
        if self.zip is not None:
            self.zip.close()


# ---------------------------------------------------------------------------- 1. manifest


def check_manifest(src, res):
    for n in src.duplicates:
        res.fail("archive contains more than one entry named %r (ambiguous content)" % n)
    for n in src.names:
        if not safe_name(n):
            res.fail("unsafe file name in bundle: %r" % n)
    if MANIFEST not in src.nameset:
        res.fail("MANIFEST.sha256 is missing")
        res.say("Manifest", "MISSING")
        return
    try:
        text = src.read(MANIFEST).decode("utf-8")
    except (UnicodeDecodeError, OSError, zipfile.BadZipFile) as e:
        res.fail("MANIFEST.sha256 unreadable: %s" % e)
        return
    listed = {}
    for i, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        m = MANIFEST_LINE.match(line)
        if not m:
            res.fail("MANIFEST.sha256 line %d is malformed: %r" % (i, line[:120]))
            continue
        digest, path = m.group(1), m.group(2)
        if path in listed:
            res.fail("MANIFEST.sha256 lists %s twice" % path)
        listed[path] = digest
    bad = 0
    for path in sorted(listed):
        if path == MANIFEST:
            res.fail("MANIFEST.sha256 lists itself")
            continue
        if path not in src.nameset:
            res.fail("file listed in MANIFEST.sha256 is missing: %s" % path)
            bad += 1
            continue
        try:
            actual = src.sha256(path)
        except (OSError, zipfile.BadZipFile) as e:
            res.fail("cannot read %s: %s" % (path, e))
            bad += 1
            continue
        if actual != listed[path]:
            res.fail("SHA-256 mismatch for %s (manifest %s, actual %s)" % (path, listed[path], actual))
            bad += 1
    for n in src.names:
        if n != MANIFEST and n not in listed:
            msg = "file not listed in MANIFEST.sha256: %s" % n
            if src.is_zip:
                res.fail(msg)
            else:
                res.warn(msg + " (extra file in the folder)")
            bad += 1
    res.say("Manifest", ("OK (%d files)" % len(listed)) if bad == 0 else "FAILED (%d problems)" % bad)


# ---------------------------------------------------------------------------- 5. signatures

# Pure-Python Ed25519 verification (RFC 8032 section 6 reference algorithm, verify only).
_P = 2 ** 255 - 19
_Q = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, _P - 2, _P)


_D = -121665 * _inv(121666) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1)
    if x2 == 0:
        if sign:
            return None
        return 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * _inv(5) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _add(p1, p2):
    a = (p1[1] - p1[0]) * (p2[1] - p2[0]) % _P
    b = (p1[1] + p1[0]) * (p2[1] + p2[0]) % _P
    c = 2 * p1[3] * p2[3] * _D % _P
    d = 2 * p1[2] * p2[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s, pt):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, pt)
        pt = _add(pt, pt)
        s >>= 1
    return q


def _equal(p1, p2):
    if (p1[0] * p2[2] - p2[0] * p1[2]) % _P != 0:
        return False
    return (p1[1] * p2[2] - p2[1] * p1[2]) % _P == 0


def _decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def ed25519_verify_pure(public, msg, sig):
    """RFC 8032 Ed25519 verification ([S]B == R + [k]A), pure Python (slow)."""
    if len(public) != 32 or len(sig) != 64:
        return False
    a = _decompress(public)
    if a is None:
        return False
    r = _decompress(sig[:32])
    if r is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _Q:
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + public + msg).digest(), "little") % _Q
    return _equal(_mul(s, _G), _add(r, _mul(k, a)))


def signature_backend(force_pure):
    """Returns (name, factory) where factory(public_key_bytes) -> verify(sig, msg) -> bool."""
    if not force_pure:
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except ImportError:
            pass
        else:
            def factory(pub):
                key = Ed25519PublicKey.from_public_bytes(pub)

                def verify(sig, msg):
                    try:
                        key.verify(sig, msg)
                        return True
                    except InvalidSignature:
                        return False
                return verify
            return "cryptography", factory
    if force_pure:
        def factory_pure(pub):
            return lambda sig, msg: ed25519_verify_pure(pub, msg, sig)
        return "built-in pure-Python RFC 8032", factory_pure
    return None, None


# ---------------------------------------------------------------------------- 6. RFC 3161 tokens


class TokenError(Exception):
    pass


def _tlv(buf, pos, end):
    """Reads one DER TLV at pos; returns (tag, content_start, content_end)."""
    if pos >= end:
        raise TokenError("truncated DER")
    tag = buf[pos]
    pos += 1
    if tag & 0x1F == 0x1F:  # high tag number form
        while True:
            if pos >= end:
                raise TokenError("truncated DER tag")
            b = buf[pos]
            pos += 1
            if not b & 0x80:
                break
    if pos >= end:
        raise TokenError("truncated DER length")
    ln = buf[pos]
    pos += 1
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4 or pos + n > end:
            raise TokenError("unsupported DER length")
        ln = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    if pos + ln > end:
        raise TokenError("DER length exceeds data")
    return tag, pos, pos + ln


def _children(buf, start, end):
    out = []
    pos = start
    while pos < end:
        tag, cs, ce = _tlv(buf, pos, end)
        out.append((tag, cs, ce))
        pos = ce
    return out


def _children_tlv(buf, start, end):
    """Like _children, with the start of each element's header: (tag, header_start, content_start, end)."""
    out = []
    pos = start
    while pos < end:
        tag, cs, ce = _tlv(buf, pos, end)
        out.append((tag, pos, cs, ce))
        pos = ce
    return out


def _oid(raw):
    if not raw:
        raise TokenError("empty OID")
    first = raw[0]
    parts = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    val = 0
    for b in raw[1:]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(val)
            val = 0
    return ".".join(str(p) for p in parts)


def _octets(buf, tag, cs, ce):
    if tag == 0x04:
        return buf[cs:ce]
    if tag == 0x24:  # constructed OCTET STRING (BER)
        return b"".join(_octets(buf, t, s, e) for t, s, e in _children(buf, cs, ce))
    raise TokenError("expected OCTET STRING, found tag 0x%02x" % tag)


def _gentime(raw):
    s = raw.decode("ascii", "replace")
    m = re.match(r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$", s)
    if not m:
        return s
    return "%s-%s-%sT%s:%s:%s%sZ" % (m.group(1), m.group(2), m.group(3), m.group(4),
                                     m.group(5), m.group(6), m.group(7) or "")


def parse_token(data):
    """Parses a DER TimeStampResp (or a bare TimeStampToken) without verifying signatures."""
    tag, cs, ce = _tlv(data, 0, len(data))
    if tag != 0x30:
        raise TokenError("not a DER SEQUENCE")
    kids = _children(data, cs, ce)
    if not kids:
        raise TokenError("empty response")
    status = None
    if kids[0][0] == 0x06:  # bare ContentInfo
        ci = (tag, cs, ce)
    else:
        st = _children(data, kids[0][1], kids[0][2])
        if not st or st[0][0] != 0x02:
            raise TokenError("malformed PKIStatusInfo")
        status = int.from_bytes(data[st[0][1]:st[0][2]], "big", signed=True)
        if status not in (0, 1):
            raise TokenError("TSA did not grant the request (status %d)" % status)
        if len(kids) < 2:
            raise TokenError("response contains no time-stamp token")
        ci = kids[1]
    ci_kids = _children(data, ci[1], ci[2])
    if len(ci_kids) < 2 or ci_kids[0][0] != 0x06 or _oid(data[ci_kids[0][1]:ci_kids[0][2]]) != OID_SIGNED_DATA:
        raise TokenError("token is not CMS SignedData")
    if ci_kids[1][0] != 0xA0:
        raise TokenError("malformed ContentInfo")
    sd = _children(data, ci_kids[1][1], ci_kids[1][2])
    if not sd or sd[0][0] != 0x30:
        raise TokenError("malformed SignedData")
    sd_kids = _children(data, sd[0][1], sd[0][2])
    if len(sd_kids) < 3 or sd_kids[2][0] != 0x30:
        raise TokenError("malformed SignedData")
    eci = _children(data, sd_kids[2][1], sd_kids[2][2])
    if len(eci) < 2 or eci[0][0] != 0x06 or _oid(data[eci[0][1]:eci[0][2]]) != OID_TST_INFO:
        raise TokenError("encapsulated content is not TSTInfo")
    if eci[1][0] != 0xA0:
        raise TokenError("malformed encapsulated content")
    inner = _children(data, eci[1][1], eci[1][2])
    if not inner:
        raise TokenError("empty TSTInfo")
    tst = _octets(data, *inner[0])
    t_tag, t_cs, t_ce = _tlv(tst, 0, len(tst))
    if t_tag != 0x30:
        raise TokenError("malformed TSTInfo")
    f = _children(tst, t_cs, t_ce)
    if len(f) < 5:
        raise TokenError("TSTInfo too short")
    policy = _oid(tst[f[1][1]:f[1][2]])
    mi = _children(tst, f[2][1], f[2][2])
    if len(mi) != 2:
        raise TokenError("malformed messageImprint")
    alg = _children(tst, mi[0][1], mi[0][2])
    hash_oid = _oid(tst[alg[0][1]:alg[0][2]]) if alg else ""
    imprint = tst[mi[1][1]:mi[1][2]].hex()
    serial = tst[f[3][1]:f[3][2]].hex()
    if f[4][0] != 0x18:
        raise TokenError("TSTInfo genTime missing")
    gen_time = _gentime(tst[f[4][1]:f[4][2]])
    nonce = ""
    for tg, s, e in f[5:]:
        if tg == 0x02:
            nonce = tst[s:e].hex()
    return {
        "status": status,
        "policy": policy,
        "hash_algorithm": hash_oid,
        "imprint": imprint,
        "serial": serial,
        "gen_time": gen_time,
        "nonce": nonce,
    }


def _parse_iso(s):
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$", s or "")
    if not m:
        return None
    frac = (m.group(7) or "0")[:6].ljust(6, "0")
    dt = _dt.datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)),
                      int(m.group(5)), int(m.group(6)), int(frac), tzinfo=_dt.timezone.utc)
    tz = m.group(8)
    if tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        dt -= sign * _dt.timedelta(hours=int(tz[1:3]), minutes=int(tz[4:6]))
    return dt


def openssl_inspect(openssl, data):
    """Runs 'openssl ts -reply -in TOKEN -text'; returns (gen_time, imprint_hex, error)."""
    tmpdir = tempfile.mkdtemp(prefix="attmon-tsr-")
    try:
        path = os.path.join(tmpdir, "token.tsr")
        with open(path, "wb") as fh:
            fh.write(data)
        try:
            cp = subprocess.run([openssl, "ts", "-reply", "-in", path, "-text"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        except (OSError, subprocess.SubprocessError) as e:
            return None, None, str(e)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    out = cp.stdout.decode("utf-8", "replace")
    if cp.returncode != 0:
        return None, None, (cp.stderr.decode("utf-8", "replace").strip() or "exit %d" % cp.returncode)[:300]
    gt = re.search(r"^Time stamp:\s*(.+?)\s*$", out, re.M)
    imprint = ""
    lines = out.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == "Message data:":
            for nxt in lines[i + 1:]:
                m = re.match(r"^\s*[0-9a-fA-F]{4} - (.{0,48})", nxt)
                if not m:
                    break
                imprint += "".join(re.findall(r"[0-9a-fA-F]{2}", m.group(1)))
            break
    return (gt.group(1) if gt else ""), imprint.lower(), None


def colon_hex(h):
    h = h.upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def gen_time_unix(s):
    """The genTime of a token (RFC 3339 text) in Unix seconds, or None."""
    dt = _parse_iso(s)
    if dt is None:
        return None
    return calendar.timegm(dt.utctimetuple())


def pem_certificates(data):
    """DER certificates of a PEM file."""
    out = []
    for m in PEM_CERT.finditer(data):
        try:
            out.append(base64.b64decode(b"".join(m.group(1).split()), validate=True))
        except (binascii.Error, ValueError):
            continue
    return out


def cert_subject(der):
    """Main subject attributes of a DER certificate ("CN=..., O=..."), or "" if unreadable."""
    try:
        _, cs, ce = _tlv(der, 0, len(der))
        cert = _children(der, cs, ce)
        tbs = _children(der, cert[0][1], cert[0][2])
        i = 1 if tbs and tbs[0][0] == 0xA0 else 0  # optional [0] version
        subject = tbs[i + 4]  # serialNumber, signature, issuer, validity, subject
        parts = []
        for _, ss, se in _children(der, subject[1], subject[2]):
            for _, a_s, a_e in _children(der, ss, se):
                kids = _children(der, a_s, a_e)
                if len(kids) < 2 or kids[0][0] != 0x06:
                    continue
                key = OID_NAMES.get(_oid(der[kids[0][1]:kids[0][2]]))
                if not key:
                    continue
                vt, vs, ve = kids[1]
                raw = der[vs:ve]
                val = raw.decode("utf-16-be", "replace") if vt == 0x1E else raw.decode("utf-8", "replace")
                parts.append("%s=%s" % (key, val))
        return ", ".join(parts)
    except (TokenError, IndexError):
        return ""


OID_SKI = "2.5.29.14"


def _cert_ids(der):
    """(issuer DER, serial bytes, subject key identifier or b"") of a DER certificate."""
    _, cs, ce = _tlv(der, 0, len(der))
    cert = _children(der, cs, ce)
    tbs = _children_tlv(der, cert[0][1], cert[0][2])
    i = 1 if tbs and tbs[0][0] == 0xA0 else 0
    serial = der[tbs[i][2]:tbs[i][3]]
    issuer = der[tbs[i + 2][1]:tbs[i + 2][3]]
    ski = b""
    for tag, _, s, e in tbs[i + 6:]:
        if tag != 0xA3:  # [3] extensions
            continue
        for _, xs, xe in _children(der, *_children(der, s, e)[0][1:]):
            ext = _children(der, xs, xe)
            if ext and ext[0][0] == 0x06 and _oid(der[ext[0][1]:ext[0][2]]) == OID_SKI:
                octets = der[ext[-1][1]:ext[-1][2]]
                _, os_, oe = _tlv(octets, 0, len(octets))
                ski = octets[os_:oe]
    return issuer, serial, ski


def token_signer(data):
    """Subject of the certificate that signed an RFC 3161 token, found among the certificates the
    token embeds by the signer's identifier (issuer and serial number, or subject key identifier);
    "" when it cannot be determined. This is what the token itself says, unlike the TSA named by
    the anchor record, which the bundle's producer writes."""
    try:
        tag, cs, ce = _tlv(data, 0, len(data))
        kids = _children(data, cs, ce)
        ci = (tag, cs, ce) if kids[0][0] == 0x06 else kids[1]
        ci_kids = _children(data, ci[1], ci[2])
        sd = _children(data, ci_kids[1][1], ci_kids[1][2])
        certs, infos = [], None
        for tg, hs, s, e in _children_tlv(data, sd[0][1], sd[0][2])[3:]:
            if tg == 0xA0:
                certs = [data[h:ee] for t2, h, s2, ee in _children_tlv(data, s, e) if t2 == 0x30]
            elif tg == 0x31:
                infos = (s, e)
        if infos is None:
            return ""
        signer = _children_tlv(data, *_children(data, *infos)[0][1:])
        sid_tag, sid_h, sid_s, sid_e = signer[1]
        for der in certs:
            issuer, serial, ski = _cert_ids(der)
            if sid_tag == 0x30:
                sid = _children_tlv(data, sid_s, sid_e)
                if data[sid[0][1]:sid[0][3]] == issuer and data[sid[1][2]:sid[1][3]] == serial:
                    return cert_subject(der)
            elif sid_tag == 0x80 and ski and data[sid_s:sid_e] == ski:
                return cert_subject(der)
        return cert_subject(certs[0]) if len(certs) == 1 else ""
    except (TokenError, IndexError, ValueError):
        return ""


def der_to_pem(ders):
    """PEM text of DER certificates."""
    out = []
    for der in ders:
        b64 = base64.b64encode(der).decode("ascii")
        out.append("-----BEGIN CERTIFICATE-----\n" + "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64)) +
                   "\n-----END CERTIFICATE-----\n")
    return "".join(out).encode("ascii")


def parse_fingerprint(text):
    """A SHA-256 fingerprint given on the command line (hex, colons and spaces allowed), lower case."""
    fp = re.sub(r"[\s:]", "", text or "").lower()
    if not HEX64.match(fp):
        raise argparse.ArgumentTypeError("not a SHA-256 fingerprint (64 hex digits): %r" % text)
    return fp


def openssl_version(openssl):
    """Returns (version text, usable, why not). 'ts -verify -attime' with ESS signing-certificate
    v2 attributes needs OpenSSL 1.1.1 or newer; LibreSSL's ts command has no -attime."""
    try:
        cp = subprocess.run([openssl, "version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        return "", False, "openssl could not be run: %s" % e
    text = cp.stdout.decode("utf-8", "replace").strip()
    if text.startswith("LibreSSL"):
        return text, False, ("%s cannot check a time-stamp token at its own time (its 'ts' command has no -attime "
                             "option); install OpenSSL 1.1.1 or newer" % text)
    m = re.match(r"^OpenSSL (\d+)\.(\d+)\.(\d+)", text)
    if not m:
        return text, False, "unrecognised openssl version %r; OpenSSL 1.1.1 or newer is needed" % text[:60]
    if tuple(int(x) for x in m.groups()) < (1, 1, 1):
        return text, False, ("%s is too old to verify RFC 3161 tokens (-attime and ESS signing-certificate v2 need "
                             "OpenSSL 1.1.1 or newer)" % text)
    return text, True, ""


def openssl_verify(openssl, token_file, head_hash, attime, roots_file, bare):
    """openssl ts -verify -attime ... -CAfile ...; returns (ok, problem)."""
    cmd = [openssl, "ts", "-verify", "-attime", str(attime), "-digest", head_hash, "-in", token_file,
           "-CAfile", roots_file]
    if bare:
        cmd.append("-token_in")
    try:
        cp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        return False, "openssl could not be run: %s" % e
    out = (cp.stdout + b"\n" + cp.stderr).decode("utf-8", "replace")
    if cp.returncode == 0 and "Verification: OK" in out:
        return True, ""
    lines = [ln.strip() for ln in out.splitlines() if ln.strip() and not ln.startswith("Using configuration")]
    detail = "; ".join(ln for ln in lines if "error" in ln.lower() or "FAILED" in ln)
    return False, (detail or "exit status %d" % cp.returncode)[:400]


def load_roots(src, res, trust):
    """Reads keys/tsa-roots.pem. Returns (trusted, untrusted) DER certificates, or (None, None)
    when the file is absent or unusable. Trusted are the default TSA roots known to this script
    and the certificates named with --trust-root (trust: set of SHA-256 fingerprints); the
    bundle's producer writes this file, so no other certificate in it is trusted."""
    if ROOTS not in src.nameset:
        return None, None
    try:
        data = src.read(ROOTS)
    except (OSError, zipfile.BadZipFile) as e:
        res.fail("%s cannot be read: %s" % (ROOTS, e))
        return None, None
    certs = pem_certificates(data)
    if not certs:
        res.fail("%s contains no PEM certificate, so no time-stamp token can be verified against it" % ROOTS)
        return None, None
    res.say("TSA roots", "%s: %d certificate(s); only those known to this verifier or named with --trust-root are "
            "trusted" % (ROOTS, len(certs)))
    trusted, untrusted = [], []
    for der in certs:
        fp = sha256_hex(der)
        subject = cert_subject(der) or "(subject not decoded)"
        known = KNOWN_ROOTS.get(fp)
        if known:
            trusted.append(der)
            how = "  (= %s, known to this verifier: trusted)" % known
        elif fp in trust:
            trusted.append(der)
            how = "  (trusted with --trust-root)"
        else:
            untrusted.append(der)
            how = "  (NOT trusted: not a TSA root known to this verifier)"
        res.lines.append("    %s" % subject)
        res.lines.append("      SHA-256 %s%s" % (colon_hex(fp), how))
        if not known and fp not in trust:
            res.warn("%s contains a certificate that is not one of the TSA roots known to this verifier (%s, SHA-256 %s): it is "
                     "NOT used as a trusted root, so a time-stamp that chains only to it is not proof of time. If you have "
                     "checked that it is the genuine root certificate a TSA publishes, re-run with --trust-root %s"
                     % (ROOTS, subject, colon_hex(fp), fp))
    return trusted, untrusted


# ---------------------------------------------------------------------------- 2-6. ledger


class Seg:
    def __init__(self, name, sha, records, last_seq):
        self.name = name
        self.sha = sha
        self.records = records
        self.last_seq = last_seq


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def check_ledger(src, res, args):
    """Checks the ledger segments (items 2-6). Returns what report.json must describe: the
    number of lines, the last parsed record (seq, h) and each segment's (sha256, lines); and the
    syslog_chunk and syslog_prune records (seq, type, data, where) for item 9."""
    facts = {"lines": 0, "last": None, "segments": {}, "syslog": []}
    seg_paths = sorted(n for n in src.names if SEGMENT_RE.match(n))
    if not seg_paths:
        res.fail("no ledger segments (ledger/ledger-YYYY-MM-DD.jsonl) in bundle")
        return facts
    backend_name, backend = signature_backend(args.pure_python_ed25519)
    verify_sig = None
    pub = None
    seq_hash = {}
    blob_refs = {}
    token_refs = set()
    anchors = []
    prev = None          # (seq, h) of the previous parsed record
    prev_seg = None      # Seg of the previous segment
    total = 0
    bad_hash = bad_sig = sig_ok = 0
    chain_problems = 0
    first_seq = last_seq_all = None
    first_ts = last_ts = ""
    times = RecordTimes()  # for the record-time checks (item 7)
    seg_names = []

    for si, path in enumerate(seg_paths):
        name = SEGMENT_RE.match(path).group(1)
        seg_names.append(name)
        try:
            data = src.read(path)
        except (OSError, zipfile.BadZipFile) as e:
            res.fail("%s: cannot read: %s" % (path, e))
            prev = None
            prev_seg = None
            continue
        seg_sha = sha256_hex(data)
        if data and not data.endswith(b"\n"):
            res.fail("%s: last line is not terminated by a newline (truncated segment)" % name)
        lines = data.split(b"\n")
        if lines and lines[-1] == b"":
            lines.pop()
        count = 0
        seg_last = None
        for ln, raw in enumerate(lines, 1):
            where = "%s line %d" % (name, ln)
            count += 1
            try:
                env = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as e:
                res.fail("%s: not a JSON envelope (%s)" % (where, e))
                prev = None
                continue
            if not isinstance(env, dict) or not all(isinstance(env.get(k), str) for k in ("h", "s", "b")):
                res.fail("%s: envelope must have string fields h, s, b" % where)
                prev = None
                continue
            try:
                b_bytes = env["b"].encode("utf-8")
            except UnicodeEncodeError:
                res.fail("%s: body is not valid UTF-8 text" % where)
                prev = None
                continue
            if sha256_hex(b_bytes) != env["h"]:
                res.fail("%s: hash mismatch: sha256(b) != h" % where)
                bad_hash += 1
            try:
                body = json.loads(env["b"])
            except ValueError as e:
                res.fail("%s: body is not JSON (%s)" % (where, e))
                prev = None
                continue
            if not isinstance(body, dict):
                res.fail("%s: body is not a JSON object" % where)
                prev = None
                continue
            seq = body.get("seq")
            typ = body.get("type")
            bprev = body.get("prev")
            if not _is_int(seq) or seq < 0 or not isinstance(typ, str) or not isinstance(bprev, str):
                res.fail("%s: body lacks a valid seq/type/prev" % where)
                prev = None
                continue
            if body.get("v") != 1:
                res.fail("%s (seq %d): unsupported format version %r" % (where, seq, body.get("v")))
            where = "%s (seq %d, %s)" % (where, seq, typ)
            total += 1
            flags = 0
            if typ == "genesis":
                flags |= F_GENESIS
            elif typ == "clock_jump":
                flags |= F_CLOCK_JUMP
            elif typ == "integrity_alert":
                details = body.get("data").get("details") if isinstance(body.get("data"), dict) else None
                if isinstance(details, list) and any(isinstance(d, str) and d.startswith(CLOCK_BEHIND_PREFIX) for d in details):
                    flags |= F_CLOCK_ALERT
            ts_ns = parse_ts_ns(body.get("ts"))
            if ts_ns is None:
                res.fail("%s: ts %r is not an RFC 3339 time" % (where, one_line(body.get("ts"), 60)))
            rec_idx = times.add(seq, ts_ns, si, ln, flags)
            if first_seq is None:
                first_seq, first_ts = seq, str(body.get("ts", ""))
            last_seq_all, last_ts = seq, str(body.get("ts", ""))

            # --- genesis and chain linkage
            if si == 0 and ln == 1:
                if seq != 0 or typ != "genesis" or bprev != ZERO_HASH:
                    res.fail("%s: the first record of the bundle must be the genesis record (seq 0)" % where)
                    chain_problems += 1
                else:
                    pub = load_genesis(src, res, body, env, where)
                    if pub is not None and backend is not None:
                        verify_sig = backend(pub)
            elif ln == 1:
                d = body.get("data") if isinstance(body.get("data"), dict) else {}
                if typ != "segment_open":
                    res.fail("%s: first record of a segment must be segment_open" % where)
                    chain_problems += 1
                elif d.get("segment") != name:
                    res.fail("%s: segment_open names segment %r" % (where, d.get("segment")))
                    chain_problems += 1
                contiguous = prev_seg is not None and d.get("prev_segment") == prev_seg.name
                if contiguous:
                    if d.get("prev_segment_sha256") != prev_seg.sha:
                        res.fail("%s: prev_segment_sha256 does not match %s.jsonl (%s)" % (where, prev_seg.name, prev_seg.sha))
                        chain_problems += 1
                    if d.get("prev_segment_records") != prev_seg.records:
                        res.fail("%s: prev_segment_records %r != %d" % (where, d.get("prev_segment_records"), prev_seg.records))
                        chain_problems += 1
                    if d.get("prev_segment_last_seq") != prev_seg.last_seq:
                        res.fail("%s: prev_segment_last_seq %r != %r" % (where, d.get("prev_segment_last_seq"), prev_seg.last_seq))
                        chain_problems += 1
                    if prev is not None:
                        if seq != prev[0] + 1:
                            res.fail("%s: seq gap (expected %d)" % (where, prev[0] + 1))
                            chain_problems += 1
                        if bprev != prev[1]:
                            res.fail("%s: prev does not equal h of seq %d" % (where, prev[0]))
                            chain_problems += 1
                else:
                    before = prev_seg.name if prev_seg is not None else "(start)"
                    gap = ""
                    if prev is not None:
                        gap = " (records %d..%d)" % (prev[0] + 1, seq - 1)
                    if si == 1:
                        # Between the genesis segment and the exported period: expected.
                        res.note("segment(s) between %s and %s (%r) are not part of this bundle%s; "
                                 "the chain across them can only be checked on the full ledger"
                                 % (before, name, d.get("prev_segment"), gap))
                    else:
                        res.fail("%s: segment(s) between %s and %s (%r) are missing from the middle of the bundle%s; "
                                 "an exported bundle holds the genesis segment plus one contiguous run of segments, "
                                 "so they were removed after the export" % (where, before, name, d.get("prev_segment"), gap))
                        chain_problems += 1
                    if prev is not None and seq <= prev[0]:
                        res.fail("%s: seq does not increase across omitted segments" % where)
                        chain_problems += 1
            elif prev is not None:
                if seq != prev[0] + 1:
                    res.fail("%s: seq gap (expected %d)" % (where, prev[0] + 1))
                    chain_problems += 1
                if bprev != prev[1]:
                    res.fail("%s: prev does not equal h of seq %d" % (where, prev[0]))
                    chain_problems += 1

            # --- signature
            if verify_sig is not None:
                try:
                    sig = base64.b64decode(env["s"], validate=True)
                except (binascii.Error, ValueError):
                    sig = b""
                if len(sig) == 64 and verify_sig(sig, b_bytes):
                    sig_ok += 1
                else:
                    res.fail("%s: Ed25519 signature does not verify" % where)
                    bad_sig += 1

            # --- blobs and anchors
            blobs = body.get("blobs") or []
            if not isinstance(blobs, list):
                res.fail("%s: blobs is not a list" % where)
                blobs = []
            for bid in blobs:
                if not isinstance(bid, str) or not HEX64.match(bid):
                    res.fail("%s: invalid blob id %r" % (where, bid))
                    continue
                blob_refs.setdefault(bid, where)
            if typ == "anchor":
                adata = body.get("data") if isinstance(body.get("data"), dict) else {}
                anchors.append((where, seq, adata, rec_idx))
                if isinstance(adata.get("token_sha256"), str):
                    token_refs.add(adata["token_sha256"])
            elif typ in ("syslog_chunk", "syslog_prune"):
                facts["syslog"].append((seq, typ, body.get("data"), where))
            if seq in seq_hash:
                res.fail("%s: duplicate seq" % where)
            seq_hash[seq] = env["h"]
            prev = (seq, env["h"])
            seg_last = seq
        prev_seg = Seg(name, seg_sha, count, seg_last)
        facts["segments"][name] = (seg_sha, count)
        facts["lines"] += count
        res.say("Segment", "%s.jsonl  %d records  sha256 %s" % (name, count, seg_sha))

    res.say("Records", "%d (seq %s..%s, %s .. %s)" % (total, first_seq, last_seq_all, first_ts, last_ts))
    res.say("Envelope hashes", "OK" if bad_hash == 0 else "FAILED (%d)" % bad_hash)
    res.say("Hash chain", "OK" if chain_problems == 0 else "FAILED (%d problems)" % chain_problems)
    if pub is None:
        res.fail("no valid genesis record: the ledger public key is unknown, signatures cannot be checked")
        res.say("Signatures", "NOT CHECKED (no genesis key)")
    elif backend is None:
        res.warn("Ed25519 signatures were NOT checked: install the 'cryptography' package "
                 "(pip install cryptography) or re-run with --pure-python-ed25519 (slow)")
        res.say("Signatures", "NOT CHECKED (see warning)")
    else:
        res.say("Signatures", ("OK (%d, %s)" % (sig_ok, backend_name)) if bad_sig == 0
                else "FAILED (%d bad, %d ok)" % (bad_sig, sig_ok))
    check_blobs(src, res, blob_refs, token_refs)
    trust = check_anchors(src, res, args, anchors, seq_hash)
    check_record_times(res, times, seg_names, trust)
    facts["last"] = prev
    return facts


# ---------------------------------------------------------------------------- 7. report files


def check_report(src, res, facts):
    """REPORT.html, report.json and README.txt are summaries computed by the exporting software.
    This script does not recompute their figures, and MANIFEST.sha256 cannot protect them (anyone
    can edit them and recompute it), so it says plainly that they were not verified. It checks
    that report.json describes the ledger records of this bundle (a report of other records is a
    failure)."""
    res.warn("REPORT.html, report.json and README.txt were NOT verified by this script: their figures (outage times, "
             "availability, incidents and their attribution) were computed by the exporting software, and MANIFEST.sha256 "
             "does not protect them - anyone can edit them and recompute the manifest. This script verifies the ledger "
             "records, which are the evidence; 'att-monitor verify-bundle' recomputes the report from those records and "
             "fails if any figure differs.")
    if "report.json" not in src.nameset:
        res.fail("report.json is missing")
        res.say("Report files", "report.json MISSING")
        return
    try:
        doc = json.loads(src.read("report.json").decode("utf-8"))
    except (UnicodeDecodeError, ValueError, OSError, zipfile.BadZipFile) as e:
        res.fail("report.json cannot be read: %s" % e)
        res.say("Report files", "report.json UNREADABLE")
        return
    ledger = doc.get("ledger") if isinstance(doc, dict) else None
    problems = []
    if not isinstance(ledger, dict):
        problems.append("it has no ledger section")
    else:
        if ledger.get("records") != facts["lines"]:
            problems.append("it counts %r records, the bundle holds %d" % (ledger.get("records"), facts["lines"]))
        head = ledger.get("head") if isinstance(ledger.get("head"), dict) else {}
        last = facts["last"]
        if last is not None and (head.get("seq") != last[0] or head.get("hash") != last[1]):
            problems.append("its last record is seq %r (%s), the bundle's is seq %d (%s)"
                            % (head.get("seq"), one_line(head.get("hash"), 80), last[0], last[1]))
        listed = {}
        for e in ledger.get("segments") or []:
            if isinstance(e, dict) and isinstance(e.get("name"), str):
                listed[e["name"]] = e
        if sorted(listed) != sorted(facts["segments"]):
            problems.append("it lists the segments %s, the bundle holds %s"
                            % (", ".join(sorted(listed)) or "none", ", ".join(sorted(facts["segments"])) or "none"))
        for name, (sha, count) in sorted(facts["segments"].items()):
            e = listed.get(name)
            if e is not None and (e.get("sha256") != sha or e.get("records") != count):
                problems.append("segment %s: sha256 %s and %r records, the bundle's file has sha256 %s and %d records"
                                % (name, one_line(e.get("sha256"), 80), e.get("records"), sha, count))
    if problems:
        res.fail("report.json does not describe the ledger records of this bundle: " + "; ".join(problems))
        res.say("Report files", "FAILED (report.json describes other records)")
        return
    res.say("Report files", "NOT VERIFIED by this script: REPORT.html, report.json and README.txt (it cannot re-run the "
            "report's analysis; 'att-monitor verify-bundle' recomputes them from the records and verifies them). report.json "
            "describes the ledger records of this bundle.")


def load_genesis(src, res, body, env, where):
    data = body.get("data") if isinstance(body.get("data"), dict) else {}
    try:
        pub = base64.b64decode(data.get("public_key", ""), validate=True)
    except (binascii.Error, ValueError):
        pub = b""
    if len(pub) != 32:
        res.fail("%s: genesis public_key is not a 32-byte Ed25519 key" % where)
        return None
    fp = sha256_hex(pub)
    if data.get("fingerprint") != fp:
        res.fail("%s: genesis fingerprint does not match its public key" % where)
    if sha256_hex(env["b"].encode("utf-8")) != env["h"]:
        res.fail("%s: genesis record hash mismatch; its public key is not trusted" % where)
        return None
    res.say("Ledger key", "Ed25519, fingerprint %s" % group4(fp))
    if "keys/public-key.txt" in src.nameset:
        try:
            m = PUBKEY_LINE.search(src.read("keys/public-key.txt").decode("utf-8", "replace"))
        except (OSError, zipfile.BadZipFile):
            m = None
        if not m or m.group(1) != data.get("public_key"):
            res.fail("keys/public-key.txt does not match the genesis public key")
    else:
        res.warn("keys/public-key.txt is missing")
    return pub


def check_blobs(src, res, blob_refs, token_refs):
    bad = 0
    for bid in sorted(blob_refs):
        path = "blobs/" + bid
        if path not in src.nameset:
            res.fail("blob %s referenced by %s is missing" % (bid, blob_refs[bid]))
            bad += 1
            continue
        try:
            actual = src.sha256(path)
        except (OSError, zipfile.BadZipFile) as e:
            res.fail("blob %s unreadable: %s" % (bid, e))
            bad += 1
            continue
        if actual != bid:
            res.fail("blob %s content does not match its name (sha256 %s)" % (bid, actual))
            bad += 1
    extra = [n for n in src.names if n.startswith("blobs/") and n[6:] not in blob_refs and n[6:] not in token_refs]
    if extra:
        res.note("%d file(s) in blobs/ are not referenced by any record in this bundle" % len(extra))
    res.say("Blobs", ("%d referenced, all present, hashes OK" % len(blob_refs)) if bad == 0
            else "FAILED (%d of %d)" % (bad, len(blob_refs)))


def check_anchors(src, res, args, anchors, seq_hash):
    """Checks the anchor records (item 6) and returns the time-stamps trusted for the record-time
    checks (item 7): {"bounds": {record index: (anchor seq, head_seq, TSA label, genTime ns)},
    "basis": "openssl" | "flags", "unverified": tokens openssl did not get to check}."""
    trust = {"bounds": {}, "basis": "flags", "unverified": 0}
    if not anchors:
        res.say("Anchors", "none in this bundle (records are not externally time-stamped here)")
        return trust
    openssl = shutil.which("openssl") if args.openssl_limit != 0 else None
    usable, why = False, ""
    if openssl:
        version, usable, why = openssl_version(openssl)
        res.say("OpenSSL", version or openssl)
    trusted, untrusted = load_roots(src, res, set(args.trust_root or []))
    heads_ok = imprints_ok = 0
    tokens = []  # anchors whose token passed the built-in checks
    for where, seq, d, idx in anchors:
        hs, hh, tok = d.get("head_seq"), d.get("head_hash"), d.get("token_sha256")
        tsa = d.get("tsa_url", "?")
        if d.get("chain_ok") is False:
            note = d.get("chain_note")
            res.note("%s: when this time-stamp was obtained, the monitoring computer could not verify the TSA certificate "
                     "chain (chain_ok=false%s); the openssl check of this script does not depend on that"
                     % (where, (", chain_note: " + one_line(note)) if isinstance(note, str) and note.strip() else ""))
        head_ok = False
        if not _is_int(hs) or not isinstance(hh, str):
            res.fail("%s: anchor lacks head_seq/head_hash" % where)
            continue
        if hs >= seq:
            res.fail("%s: head_seq %d is not before the anchor record" % (where, hs))
            continue
        if hs in seq_hash:
            if seq_hash[hs] != hh:
                res.fail("%s: head_hash differs from the hash of record %d" % (where, hs))
            else:
                head_ok = True
                heads_ok += 1
        else:
            res.note("%s: anchored head record %d is not in this bundle" % (where, hs))
        if not isinstance(tok, str) or not HEX64.match(tok):
            res.fail("%s: anchor has no valid token_sha256" % where)
            continue
        path = "blobs/" + tok
        if path not in src.nameset:
            res.fail("%s: time-stamp token %s is missing" % (where, path))
            continue
        try:
            token = src.read(path)
        except (OSError, zipfile.BadZipFile) as e:
            res.fail("%s: cannot read token: %s" % (where, e))
            continue
        if sha256_hex(token) != tok:
            res.fail("%s: %s does not match token_sha256 (its sha256 is %s): it is not the token the record names"
                     % (where, path, sha256_hex(token)))
            continue
        try:
            info = parse_token(token)
        except TokenError as e:
            res.fail("%s: time-stamp token cannot be parsed: %s" % (where, e))
            continue
        bad = info["hash_algorithm"] != OID_SHA256
        if bad:
            res.fail("%s: token hash algorithm %s is not SHA-256" % (where, info["hash_algorithm"]))
        if info["imprint"] != hh:
            res.fail("%s: token message imprint %s != head_hash %s" % (where, info["imprint"], hh))
            continue
        imprints_ok += 1
        g1, g2 = _parse_iso(info["gen_time"]), _parse_iso(d.get("gen_time", ""))
        if g1 is None or g2 is None or abs((g1 - g2).total_seconds()) >= 1:
            res.warn("%s: record gen_time %r differs from the token's genTime %r" % (where, d.get("gen_time"), info["gen_time"]))
        signer = token_signer(token)
        label = ("signed by " + one_line(signer, 200)) if signer else ("signer not identified; the record names %s" % one_line(tsa, 200))
        tokens.append({"where": where, "seq": seq, "idx": idx, "tsa": tsa, "path": path, "token": token, "hh": hh, "hs": hs,
                       "gen": info["gen_time"], "bare": info["status"] is None, "head_ok": head_ok, "proof": False,
                       "label": label, "untrusted": False, "bad": bad, "tried": False,
                       "flags_ok": d.get("verified") is True and d.get("chain_ok") is True})

    limit = args.openssl_limit
    ran = 0
    mode = "none"
    if openssl and usable and (trusted or untrusted):
        mode = "verify"
        # The latest token of each TSA covers the most records: verify those first.
        last = {}
        for i, t in enumerate(tokens):
            last[t["tsa"]] = i
        first = sorted(set(last.values()))
        firstset = set(first)
        order = first + [i for i in range(len(tokens)) if i not in firstset]
        tmpdir = tempfile.mkdtemp(prefix="attmon-tsr-")
        try:
            # Only trusted roots make a time-stamp proof of time; the others only tell a token that
            # chains to an untrusted root from an invalid one.
            trusted_file = untrusted_file = None
            if trusted:
                trusted_file = os.path.join(tmpdir, "trusted-roots.pem")
                with open(trusted_file, "wb") as fh:
                    fh.write(der_to_pem(trusted))
            if untrusted:
                untrusted_file = os.path.join(tmpdir, "untrusted-roots.pem")
                with open(untrusted_file, "wb") as fh:
                    fh.write(der_to_pem(untrusted))
            for i in order:
                if 0 <= limit <= ran:
                    break
                t = tokens[i]
                attime = gen_time_unix(t["gen"])
                if attime is None:
                    res.fail("%s: the token's genTime %r cannot be read, so it cannot be verified at its own time; "
                             "this anchor is not proof of time" % (t["where"], t["gen"]))
                    continue
                token_file = os.path.join(tmpdir, "token-%d.tsr" % t["seq"])
                with open(token_file, "wb") as fh:
                    fh.write(t["token"])
                ran += 1
                t["tried"] = True
                ok, problem = False, "no trusted TSA root"
                if trusted_file:
                    ok, problem = openssl_verify(openssl, token_file, t["hh"], attime, trusted_file, t["bare"])
                if ok:
                    t["proof"] = True
                    res.lines.append("    openssl ts -verify: OK  anchor seq %d (%s), genTime %s (-attime %d)"
                                     % (t["seq"], t["label"], t["gen"], attime))
                elif untrusted_file and openssl_verify(openssl, token_file, t["hh"], attime, untrusted_file, t["bare"])[0]:
                    t["untrusted"] = True
                    res.warn("%s: the token (%s) verifies only against a certificate in %s that is not a TSA root known to "
                             "this verifier: this anchor is not proof of time (see the TSA roots above; --trust-root names a "
                             "root you have checked)" % (t["where"], t["label"], ROOTS))
                else:
                    res.fail("%s: openssl ts -verify -attime %d -digest %s -in %s -CAfile <the TSA roots of %s> FAILED (%s): "
                             "this anchor is not proof of time" % (t["where"], attime, t["hh"], t["path"], ROOTS, problem))
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
        if len(tokens) > ran:
            res.warn("%d of %d time-stamp tokens were NOT verified with openssl because of --openssl-limit %d "
                     "(the latest token of each TSA is verified first); re-run with --openssl-limit -1 to verify all"
                     % (len(tokens) - ran, len(tokens), limit))
    else:
        if args.openssl_limit == 0:
            res.warn("openssl verification disabled (--openssl-limit 0): the TSA signatures and certificate chains of the "
                     "time-stamp tokens were NOT verified")
        elif not openssl:
            res.warn("openssl was not found on PATH: the TSA signatures and certificate chains of the time-stamp tokens "
                     "were NOT verified (only their message imprint and genTime were read); install OpenSSL 1.1.1 or "
                     "newer and re-run, or run the openssl commands below")
        elif not usable:
            res.warn("%s: the TSA signatures and certificate chains of the time-stamp tokens were NOT verified" % why)
        elif ROOTS in src.nameset:
            res.warn("%s cannot be used (see the failures): the TSA signatures and certificate chains of the time-stamp "
                     "tokens were NOT verified" % ROOTS)
        else:
            res.warn("%s is not in this bundle: the TSA signatures and certificate chains of the time-stamp tokens were "
                     "NOT verified; obtain the TSAs' root certificates and run the openssl commands below" % ROOTS)
        if openssl and usable:
            mode = "inspect"
            for t in tokens:
                if 0 <= limit <= ran:
                    break
                ran += 1
                gtime, imp, err = openssl_inspect(openssl, t["token"])
                if err:
                    res.warn("%s: openssl could not read the token: %s" % (t["where"], err))
                elif imp != t["hh"]:
                    t["bad"] = True
                    res.fail("%s: openssl reports message imprint %s != head_hash %s" % (t["where"], imp, t["hh"]))
                else:
                    res.lines.append("    openssl: %s  genTime %s  imprint OK (seq %d)" % (t["label"], gtime, t["seq"]))

    if mode == "verify":
        openssl_note = "; openssl verified %d of %d (TSA signature and chain to a trusted root of %s)" % (
            sum(1 for t in tokens if t["proof"]), len(tokens), ROOTS)
        if any(t["untrusted"] for t in tokens):
            openssl_note += "; %d chain only to an untrusted root (not proof of time)" % sum(1 for t in tokens if t["untrusted"])
    elif mode == "inspect":
        openssl_note = "; openssl read %d (imprint only; signatures and chains NOT verified)" % ran
    elif args.openssl_limit == 0:
        openssl_note = "; openssl disabled (built-in DER check only)"
    elif openssl:
        openssl_note = "; openssl unusable (built-in DER check only)"
    else:
        openssl_note = "; openssl not found (built-in DER check only)"
    res.say("Anchors", "%d records; heads OK %d; token imprints OK %d%s" % (len(anchors), heads_ok, imprints_ok, openssl_note))

    proven = [t for t in tokens if t["proof"] and t["head_ok"]]
    if proven:
        best = max(proven, key=lambda t: t["hs"])
        res.say("Latest anchor", "records up to seq %d existed no later than %s (%s; TSA signature and certificate chain "
                "verified by openssl against a trusted TSA root)" % (best["hs"], best["gen"], best["label"]))
    else:
        cands = [t for t in tokens if t["head_ok"]]
        if cands:
            best = max(cands, key=lambda t: t["hs"])
            res.say("Latest anchor", "seq %d, genTime %s (%s) - NOT verified as proof of time (no TSA signature and "
                    "certificate chain verified against a trusted root, see above)" % (best["hs"], best["gen"], best["label"]))
    examples = {}
    for t in tokens:
        examples[t["tsa"]] = t  # the latest token per TSA (as the records name them) covers the most records
    ca = (ROOTS + " (after checking its certificates' fingerprints)") if (trusted or untrusted) else "<TSA root CA certificates .pem>"
    for tsa in sorted(examples):
        t = examples[tsa]
        attime = gen_time_unix(t["gen"])
        res.lines.append("    TSA signature and chain check of anchor seq %d (%s), on the extracted bundle:" % (t["seq"], t["label"]))
        res.lines.append("      openssl ts -verify -attime %s -digest %s -in %s -CAfile %s"
                         % (attime if attime is not None else "<genTime>", t["hh"], t["path"], ca))

    # The time-stamps that bound record times (item 7): with openssl, those it verified against a
    # trusted root; without it, those whose records state they verified and chained when obtained.
    trust["basis"] = "openssl" if mode == "verify" else "flags"
    for t in tokens:
        if not t["head_ok"] or t["bad"]:
            continue
        if mode == "verify":
            if not t["tried"]:
                trust["unverified"] += 1
                continue
            if not t["proof"]:
                continue
        elif not t["flags_ok"]:
            continue
        gen = parse_ts_ns(t["gen"])
        if gen is not None:
            trust["bounds"][t["idx"]] = (t["seq"], t["hs"], t["label"], gen)
    return trust


# ---------------------------------------------------------------------------- 7. record times

# The checks of the att-monitor ledger verifier (internal/ledger timecheck.go): a record's ts
# against the trusted time-stamps the chain holds, and against the records before it.

NS = 10 ** 9
TS_TOLERANCE = 300 * NS  # 5 minutes: how far a ts may lie on the wrong side of a trusted time-stamp
TS_TOLERANCE_TEXT = "5m0s"
CLOCK_BEHIND_PREFIX = "the computer's clock is behind the newest ledger record"
MAX_PENDING_TS = 1 << 17  # records kept exactly until a trusted time-stamp covers them
MAX_BACK_NOTES = 5
# The ts the Go writer formats (time.RFC3339Nano) and the Go verifier accepts: "T" and "Z" in upper case.
TS_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$")
EPOCH_ORDINAL = _dt.date(1970, 1, 1).toordinal()

# Record flags for the time checks.
F_GENESIS, F_CLOCK_JUMP, F_CLOCK_ALERT = 1, 2, 4


def parse_ts_ns(s):
    """An RFC 3339 time in integer nanoseconds since the Unix epoch (UTC), or None."""
    m = TS_RE.match(s) if isinstance(s, str) else None
    if not m:
        return None
    y, mo, d, hh, mm, ss = (int(m.group(i)) for i in range(1, 7))
    if hh > 23 or mm > 59 or ss > 59:
        return None
    try:
        days = _dt.date(y, mo, d).toordinal() - EPOCH_ORDINAL
    except ValueError:
        return None
    frac = (m.group(7) or "")[:9].ljust(9, "0")
    ns = (((days * 24 + hh) * 60 + mm) * 60 + ss) * NS + int(frac)
    tz = m.group(8)
    if tz != "Z":
        oh, om = int(tz[1:3]), int(tz[4:6])
        if oh > 23 or om > 59:
            return None
        ns -= (1 if tz[0] == "+" else -1) * (oh * 3600 + om * 60) * NS
    return ns


def fmt_ts(ns):
    """Nanoseconds since the epoch as RFC 3339 UTC with the fraction trimmed (Go's RFC3339Nano)."""
    sec, frac = divmod(ns, NS)
    try:
        t = _dt.datetime(1970, 1, 1) + _dt.timedelta(seconds=sec)
    except OverflowError:
        return "%d ns since 1970" % ns
    s = "%04d-%02d-%02dT%02d:%02d:%02d" % (t.year, t.month, t.day, t.hour, t.minute, t.second)
    if frac:
        s += "." + ("%09d" % frac).rstrip("0")
    return s + "Z"


def _go_round(d, m):
    """Go's Duration.Round: d rounded to a multiple of m, halves away from zero."""
    a = -d if d < 0 else d
    r = a % m
    a = a - r if 2 * r < m else a + m - r
    return -a if d < 0 else a


def fmt_dur(d):
    """A duration in nanoseconds the way the Go verifier words it: to the second ("4m0s"), or to
    the millisecond below a second ("300ms")."""
    if -NS < d < NS:
        ms = _go_round(d, 10 ** 6) // 10 ** 6
        return "0s" if ms == 0 else "%dms" % ms
    d = _go_round(d, NS)
    sign = "-" if d < 0 else ""
    sec = abs(d) // NS
    h, rest = divmod(sec, 3600)
    m, s = divmod(rest, 60)
    if h:
        return "%s%dh%dm%ds" % (sign, h, m, s)
    if m:
        return "%s%dm%ds" % (sign, m, s)
    return "%s%ds" % (sign, s)


class RecordTimes(object):
    """Every parsed record's seq, ts (ns, or none), segment index, line and flags, in chain order,
    kept compactly (a bundle can hold hundreds of thousands of records)."""

    NO_TS = -(1 << 63)

    def __init__(self):
        self.seq = array("Q")
        self.ts = array("q")
        self.seg = array("i")
        self.line = array("i")
        self.flags = bytearray()
        self.big = {}  # index -> ts outside the signed 64-bit range of nanoseconds (before 1678, after 2262)

    def __len__(self):
        return len(self.flags)

    def add(self, seq, ts, seg, line, flags):
        i = len(self.flags)
        self.seq.append(min(seq, (1 << 64) - 1))
        if ts is None:
            self.ts.append(self.NO_TS)
        elif self.NO_TS < ts < (1 << 63):
            self.ts.append(ts)
        else:
            self.ts.append(0)
            self.big[i] = ts
        self.seg.append(seg)
        self.line.append(min(line, (1 << 31) - 1))
        self.flags.append(flags)
        return i

    def ts_at(self, i):
        b = self.big.get(i)
        if b is not None:
            return b
        v = self.ts[i]
        return None if v == self.NO_TS else v


class _TSRun(object):
    """The records whose ts contradict trusted time-stamps over a contiguous period. It ends when a
    whole anchoring window (the records a time-stamp bounds first) passes without one."""

    __slots__ = ("n", "first", "last", "worst", "by", "bound", "hit", "seen")

    def __init__(self):
        self.reset()

    def reset(self):
        self.n = 0
        self.first = self.last = self.worst = None
        self.by = 0
        self.bound = None
        self.hit = self.seen = False


class TimeCheck(object):
    """Record ts against the trusted time-stamps of the chain and against each other, in chain order.

    A record is (seq, ts, segment index, line); a trusted time-stamp (bound) is (anchor record seq,
    head_seq, TSA label, genTime). anchor() is called for a trusted anchor record before record()
    checks that record's own ts. Port of the att-monitor ledger verifier (timecheck.go)."""

    def __init__(self, now_ns):
        self.now_ns = now_ns
        self.notes = []
        self.low_fails = []
        self.high_fails = []
        self.fail_total = 0
        self.used = 0
        self.window_head = None
        self.floor = None  # the trusted time-stamp with the latest genTime seen so far
        self.low = _TSRun()
        self.low_max = None
        self.pend = []  # records no trusted time-stamp has covered yet, in chain order
        self.pend_head = 0
        self.fold = None
        self.high = _TSRun()
        self.high_max = None
        self.max = None  # the record with the latest ts so far
        self.genesis = None
        self.back = None
        self.back_runs = 0

    # --- trusted time-stamps

    def anchor(self, b):
        self.used += 1
        self.cover(b)
        # Each anchoring event (the TSAs stamp the same head one after the other) starts a new
        # window of records that its genTimes bound from below.
        if self.window_head is None or b[1] != self.window_head:
            self.end_window(self.low, True)
            self.window_head = b[1]
        if self.floor is None or b[3] > self.floor[3]:
            self.floor = b

    def cover(self, b):
        """Checks the records up to b's head that no trusted time-stamp covered yet against its genTime."""
        limit = b[3] + TS_TOLERANCE
        if self.fold is not None:
            f = self.fold
            if b[1] < f["last"][0]:
                return  # covers only part of the folded records: a later time-stamp covers them all
            self.end_run(self.high, False)
            self.fold = None
            by = f["max"][1] - b[3]
            if self.high_max is None or by > self.high_max:
                self.high_max = by
            if f["max"][1] > limit:
                self.add_fail(self.high_fails, f["max"], (
                    "of the %d records seq %d-%d (more than %d records awaited a trusted time-stamp, so they were not examined "
                    "one by one), seq %d is dated %s, %s after the genTime %s of the trusted time-stamp held by anchor record %d "
                    "(%s), which covers the chain up to seq %d: it existed by that time, so its ts is false - forward-dated, or "
                    "the clock was ahead (tolerance %s)")
                    % (f["n"], f["first"][0], f["last"][0], MAX_PENDING_TS, f["max"][0], fmt_ts(f["max"][1]),
                       fmt_dur(f["max"][1] - b[3]), fmt_ts(b[3]), b[0], b[2], b[1], TS_TOLERANCE_TEXT))
        while self.pend_head < len(self.pend) and self.pend[self.pend_head][0] <= b[1]:
            rec = self.pend[self.pend_head]
            self.pend_head += 1
            by = rec[1] - b[3]
            if self.high_max is None or by > self.high_max:
                self.high_max = by
            if rec[1] > limit:
                self.offend(self.high, rec, by, b)
            else:
                self.high.seen = True
        self.compact()
        self.end_window(self.high, False)

    @staticmethod
    def offend(run, rec, by, b):
        if run.n == 0:
            run.first = rec
        run.n += 1
        run.last = rec
        if run.n == 1 or by > run.by:
            run.worst, run.by, run.bound = rec, by, b
        run.hit = run.seen = True

    def end_window(self, run, low):
        """Closes an anchoring window: the run ends if the window held records and none of them
        contradicted its time-stamp."""
        if run.n > 0 and run.seen and not run.hit:
            self.end_run(run, low)
        run.hit = run.seen = False

    def end_run(self, run, low):
        """Reports the run, if any, as one failure located at its first contradicting record."""
        n, first, last, worst, by, b = run.n, run.first, run.last, run.worst, run.by, run.bound
        run.reset()
        if n == 0:
            return
        if n > 1:
            who, them, these = "%d records from seq %d to seq %d are" % (n, first[0], last[0]), "them", "these ts are"
        else:
            who, them, these = "seq %d is" % first[0], "it", "its ts is"
        if low:
            self.add_fail(self.low_fails, first, (
                "%s dated up to %s earlier than trusted time-stamps that precede %s in the chain: seq %d is dated %s, %s before the "
                "genTime %s of the time-stamp held by anchor record %d (%s). Records from an anchor record on were written after its "
                "genTime, so %s false - back-dated, or the clock was behind (tolerance %s)")
                % (who, fmt_dur(by), them, worst[0], fmt_ts(worst[1]), fmt_dur(by), fmt_ts(b[3]), b[0], b[2], these,
                   TS_TOLERANCE_TEXT))
            return
        self.add_fail(self.high_fails, first, (
            "%s dated up to %s later than trusted time-stamps that cover %s: seq %d is dated %s, %s after the genTime %s of the "
            "time-stamp held by anchor record %d (%s), which covers the chain up to seq %d. Covered records existed by that genTime, "
            "so %s false - forward-dated, or the clock was ahead (tolerance %s)")
            % (who, fmt_dur(by), them, worst[0], fmt_ts(worst[1]), fmt_dur(by), fmt_ts(b[3]), b[0], b[2], b[1], these,
               TS_TOLERANCE_TEXT))

    def add_fail(self, lst, at, detail):
        self.fail_total += 1
        lst.append((at, detail))

    def compact(self):
        if self.pend_head == len(self.pend):
            self.pend, self.pend_head = [], 0
        elif self.pend_head >= 4096 and 2 * self.pend_head >= len(self.pend):
            self.pend, self.pend_head = self.pend[self.pend_head:], 0

    def push(self, rec):
        """Adds a record to the pending list, folding the older half when it is full."""
        n = len(self.pend) - self.pend_head
        if n >= MAX_PENDING_TS:
            half = n // 2
            for e in self.pend[self.pend_head:self.pend_head + half]:
                if self.fold is None:
                    self.fold = {"n": 0, "first": e, "last": e, "max": e}
                f = self.fold
                f["n"] += 1
                f["last"] = e
                if e[1] > f["max"][1]:
                    f["max"] = e
            self.pend_head += half
            self.compact()
        self.pend.append(rec)

    # --- records

    def record(self, seq, ts, seg, line, flags):
        """Checks one record, in chain order."""
        if ts is None:
            self.end_back()
            return
        rec = (seq, ts, seg, line)
        if flags & F_GENESIS and self.genesis is None:
            self.genesis = ts
        # Lower bound: written after the latest trusted genTime that precedes it.
        if self.floor is not None:
            by = self.floor[3] - ts
            if self.low_max is None or by > self.low_max:
                self.low_max = by
            if by > TS_TOLERANCE:
                self.offend(self.low, rec, by, self.floor)
            else:
                self.low.seen = True
        # Order: dated well before a record that precedes it.
        if self.max is not None and ts < self.max[1] - TS_TOLERANCE:
            run = self.back
            if run is None:
                run = self.back = {"n": 0, "first": rec, "last": rec, "ref": self.max, "by": 0, "worst": rec, "jump": None,
                                   "alert": None, "before_genesis": False}
            run["n"] += 1
            run["last"] = rec
            by = run["ref"][1] - ts
            if run["n"] == 1 or by > run["by"]:
                run["by"], run["worst"] = by, rec
            if flags & F_CLOCK_JUMP and run["jump"] is None:
                run["jump"] = seq
            if flags & F_CLOCK_ALERT and run["alert"] is None:
                run["alert"] = seq
            if self.genesis is not None and ts < self.genesis - TS_TOLERANCE:
                run["before_genesis"] = True
        else:
            self.end_back()
        if self.max is None or ts > self.max[1]:
            self.max = rec
        self.push(rec)

    def end_back(self):
        run = self.back
        if run is None:
            return
        self.back = None
        self.back_runs += 1
        if self.back_runs > MAX_BACK_NOTES:
            return
        docs = []
        if run["jump"] is not None:
            docs.append("the clock_jump record seq %d documents a step of the wall clock" % run["jump"])
        if run["alert"] is not None:
            docs.append("the writer's integrity_alert seq %d records that the computer's clock was behind the newest ledger "
                        "record when the ledger was opened" % run["alert"])
        how = "; ".join(docs) or "no clock_jump record or clock integrity_alert documents a step of the wall clock here"
        genesis = ", some of them before the genesis record" if run["before_genesis"] else ""
        if run["n"] > 1:
            who, them = "seq %d-%d (%d records) are" % (run["first"][0], run["last"][0], run["n"]), "them"
        else:
            who, them = "seq %d is" % run["first"][0], "it"
        self.notes.append("record ts go backwards: %s dated up to %s before seq %d (ts %s), which precedes %s in the chain%s; %s "
                          "(tolerance %s)" % (who, fmt_dur(run["by"]), run["ref"][0], fmt_ts(run["ref"][1]), them, genesis, how,
                                              TS_TOLERANCE_TEXT))

    def finish(self):
        """Closes the open runs and adds the summary notes. Records no trusted time-stamp covers
        (the unanchored tail) are not judged against an upper bound: nothing bounds them yet."""
        self.end_run(self.low, True)
        self.end_run(self.high, False)
        self.end_back()
        if self.back_runs > MAX_BACK_NOTES:
            self.notes.append("%d further backward step(s) of the record ts are not listed" % (self.back_runs - MAX_BACK_NOTES))
        if self.used > 0 and self.fail_total == 0:
            self.notes.append("record ts agree with the %d trusted time-stamp(s) in the chain within the %s tolerance: no record is "
                              "dated more than %s before a time-stamp that precedes it, nor more than %s after one that covers it"
                              % (self.used, TS_TOLERANCE_TEXT, fmt_dur(max(self.low_max or 0, 0)),
                                 fmt_dur(max(self.high_max or 0, 0))))
        if self.max is not None and self.max[1] - self.now_ns > TS_TOLERANCE:
            self.notes.append("records are dated after the time of this verification (%s): the newest, seq %d, is dated %s, %s "
                              "later - their ts are false, or the verifying computer's clock is behind"
                              % (fmt_ts(self.now_ns), self.max[0], fmt_ts(self.max[1]), fmt_dur(self.max[1] - self.now_ns)))


def check_record_times(res, times, seg_names, trust):
    """Runs the record-time checks with the trusted time-stamps found by check_anchors."""
    bounds = trust["bounds"]
    tc = TimeCheck(time.time_ns())
    for i in range(len(times)):
        b = bounds.get(i)
        if b is not None:
            tc.anchor(b)
        tc.record(times.seq[i], times.ts_at(i), times.seg[i], times.line[i], times.flags[i])
    tc.finish()
    fails = sorted(tc.low_fails + tc.high_fails, key=lambda f: (f[0][2], f[0][3]))
    for rec, detail in fails:
        name = seg_names[rec[2]] if 0 <= rec[2] < len(seg_names) else "?"
        res.fail("%s line %d (seq %d): record time contradicts a trusted time-stamp (ts_contradiction): %s"
                 % (name, rec[3], rec[0], detail))
    for n in tc.notes:
        res.note(n)
    if trust["basis"] == "openssl":
        how = "their TSA signatures and certificate chains verified by openssl against a trusted root"
    else:
        how = ("accepted per their anchor records' issue-time flags verified and chain_ok; their TSA signatures and chains were "
               "NOT verified here")
    if not bounds:
        if len(times):
            res.warn("record times were NOT checked against time-stamps: no time-stamp in this bundle is accepted as proof of "
                     "time here (only their order was checked, see the notes)")
        res.say("Record times", "NOT CHECKED against time-stamps (none accepted as proof of time here); order checked")
    elif fails:
        res.say("Record times", "FAILED (%d contradiction(s) with the %d trusted time-stamp(s), %s; tolerance %s)"
                % (len(fails), tc.used, how, TS_TOLERANCE_TEXT))
    else:
        res.say("Record times", "OK (no record contradicts the %d trusted time-stamp(s) by more than %s; %s)"
                % (tc.used, TS_TOLERANCE_TEXT, how))
    if trust["unverified"]:
        res.lines.append("    %d other time-stamp(s) were not verified with openssl (--openssl-limit) and were not used here; "
                         "re-run with --openssl-limit -1 to use all of them" % trust["unverified"])


# ---------------------------------------------------------------------------- 9. syslog chunks

# The checks of the att-monitor verifier (internal/export syslog.go): the same records are usable
# and the same chunks count as chunks of the period; chunk files are read as strictly (one or more
# gzip members and nothing after them), so every file a gzip writer produces, and every damaged or
# altered one, gets the same verdict.

SYSLOG_DIR = "syslog/"
MAX_CHUNK_CONTENT = 1 << 30  # largest uncompressed chunk content that is verified
GZ_STEP = 1 << 16
CHUNK_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
DEVICE_NAMES = ("CON", "PRN", "AUX", "NUL")
MAX_LISTED_CHUNKS = 10
# The fields of syslog_chunk and syslog_prune records, by type: a record with a field of another
# type cannot be used (as the Go verifier cannot decode it).
CHUNK_FIELDS = (("name", "from", "to", "sha256", "reason"), ("messages", "dropped", "rejected", "bytes", "gz_bytes"))
PRUNE_FIELDS = (("reason",), ("keep_mb", "keep_days", "kept_bytes", "kept_chunks"))
PRUNED_CHUNK_FIELDS = (("name", "sha256", "from", "to"), ("messages", "gz_bytes"))


class ChunkTooLarge(Exception):
    """The uncompressed content of a chunk file is larger than the limit it is read with."""


def chunk_name_ok(name):
    """True for a chunk name the exporter puts into a bundle (syslog/<name>): one plain path
    element of letters, digits, '.', '_' and '-' starting with a letter or digit, at most 200
    bytes, without '..', not ending with '.' and not a Windows device name."""
    if not isinstance(name, str) or len(name) > 200 or not CHUNK_NAME.fullmatch(name):
        return False
    if ".." in name or name.endswith("."):
        return False
    base = name.split(".", 1)[0].upper()
    if base in DEVICE_NAMES:
        return False
    return not (len(base) == 4 and base[:3] in ("COM", "LPT") and base[3] in "0123456789")


def _go_int(v):
    """An integer a Go int/int64 field accepts."""
    return _is_int(v) and -(1 << 63) <= v < (1 << 63)


def _field_problem(d, fields):
    """Why the JSON object d does not have fields = (string fields, integer fields) of those types
    (absent or null is fine), or ""."""
    strs, ints = fields
    for k in strs:
        if d.get(k) is not None and not isinstance(d.get(k), str):
            return "%s is not a string" % k
    for k in ints:
        if d.get(k) is not None and not _go_int(d.get(k)):
            return "%s is not an integer" % k
    return ""


def chunk_record(data):
    """The chunk a syslog_chunk record states: (dict, None), or (None, why the record cannot be
    used). The record must state a plain chunk name, a SHA-256, and a size and message count of
    at least 0; from/to (receive times of its first and last message) only place it in time."""
    if data is None:
        data = {}
    if not isinstance(data, dict):
        return None, "its data is not a JSON object"
    problem = _field_problem(data, CHUNK_FIELDS)
    if problem:
        return None, problem
    name = data.get("name") or ""
    sha = (data.get("sha256") or "").lower()
    nbytes, msgs = data.get("bytes") or 0, data.get("messages") or 0
    if not chunk_name_ok(name):
        return None, "its chunk name %r is not a plain file name" % one_line(name, 80)
    if not HEX64.fullmatch(sha):
        return None, "its sha256 %r is not a SHA-256" % one_line(data.get("sha256") or "", 80)
    if nbytes < 0 or msgs < 0:
        return None, "it states a negative size or message count"
    return {"name": name, "sha256": sha, "bytes": nbytes, "messages": msgs,
            "from": parse_ts_ns(data.get("from")), "to": parse_ts_ns(data.get("to"))}, None


def pruned_refs(data):
    """The chunks a syslog_prune record names, [(name, sha256 or "")], or None when the record
    cannot be used."""
    if data is None:
        return []
    if not isinstance(data, dict) or _field_problem(data, PRUNE_FIELDS):
        return None
    deleted = data.get("deleted")
    if deleted is None:
        return []
    if not isinstance(deleted, list):
        return None
    out = []
    for e in deleted:
        if e is None:
            e = {}
        if not isinstance(e, dict) or _field_problem(e, PRUNED_CHUNK_FIELDS):
            return None
        out.append((e.get("name") or "", (e.get("sha256") or "").lower()))
    return out


def gunzip_digest(f, limit):
    """(SHA-256 hex, bytes, lines) of the uncompressed content of a chunk file read from f: gzip,
    one or more members and nothing after them. Raises ValueError when it is not valid gzip and
    ChunkTooLarge when its content is larger than limit bytes."""
    h = hashlib.sha256()
    size = lines = 0
    d = None  # the decompressor of the current gzip member
    data = b""
    started = False
    while True:
        if not data:
            data = f.read(GZ_STEP)
            if not data:
                break
            started = True
        if d is None:
            d = zlib.decompressobj(31)  # gzip: header, and the trailer's CRC-32 and size, are checked
        try:
            out = d.decompress(data, GZ_STEP)
            while True:
                size += len(out)
                if size > limit:
                    raise ChunkTooLarge()
                h.update(out)
                lines += out.count(b"\n")
                if d.eof or d.unconsumed_tail or len(out) < GZ_STEP:
                    break
                out = d.decompress(b"", GZ_STEP)  # output the decompressor still holds
        except zlib.error as e:
            raise ValueError("it is not a valid gzip file: %s" % e)
        if d.eof:
            data, d = d.unused_data, None
        else:
            data = d.unconsumed_tail
    if not started:
        raise ValueError("it is not a valid gzip file: it is empty")
    if d is not None:
        raise ValueError("it is not a valid gzip file: it ends inside a gzip member (truncated)")
    return h.hexdigest(), size, lines


def chunk_diff(digest, rec):
    """How a chunk's content (SHA-256, bytes, lines) differs from a record ("" = it matches)."""
    sha, size, lines = digest
    out = []
    if sha != rec["sha256"]:
        out.append("its SHA-256 is %s, the record states %s" % (sha, rec["sha256"]))
    if size != rec["bytes"]:
        out.append("it holds %d bytes, the record states %d" % (size, rec["bytes"]))
    if lines != rec["messages"]:
        out.append("it holds %d messages (lines), the record states %d" % (lines, rec["messages"]))
    return "; ".join(out)


def match_chunk(src, path, cands):
    """What is wrong with the chunk file at path, or "" when it is gzip whose content has the
    SHA-256, size and line count one of the syslog_chunk records that name it (cands) states."""
    largest = max(cands, key=lambda r: r["bytes"])
    limit = min(largest["bytes"], MAX_CHUNK_CONTENT)
    try:
        with src._open(path) as f:
            digest = gunzip_digest(f, limit)
    except ChunkTooLarge:
        if limit < MAX_CHUNK_CONTENT:
            return "uncompressed it is larger than the %d bytes its syslog_chunk record (seq %d) states" % (
                largest["bytes"], largest["seq"])
        return "uncompressed it is larger than %d bytes, more than a chunk can hold" % limit
    except ValueError as e:
        return str(e)
    except (OSError, EOFError, zipfile.BadZipFile, zlib.error) as e:
        return "it cannot be read: %s" % e
    for rec in cands:
        if not chunk_diff(digest, rec):
            return ""
    last = cands[-1]
    return "it is not what its syslog_chunk record (seq %d) states: %s" % (last["seq"], chunk_diff(digest, last))


def report_period(src):
    """The period [from, to) report.json states, in nanoseconds, or None."""
    if "report.json" not in src.nameset:
        return None
    try:
        doc = json.loads(src.read("report.json").decode("utf-8", "replace"))
    except (ValueError, OSError, EOFError, zipfile.BadZipFile, zlib.error):
        return None
    p = doc.get("period") if isinstance(doc, dict) else None
    if not isinstance(p, dict):
        return None
    start, end = parse_ts_ns(p.get("from")), parse_ts_ns(p.get("to"))
    if start is None or end is None or start >= end:
        return None
    return start, end


def listing(names):
    shown = ", ".join(names[:MAX_LISTED_CHUNKS])
    if len(names) > MAX_LISTED_CHUNKS:
        shown += " and %d more" % (len(names) - MAX_LISTED_CHUNKS)
    return shown


def check_syslog(src, res, facts):
    """Checks the syslog chunks (item 9): every syslog/<name> against the syslog_chunk records
    that name it; the chunks of the period that are not in the bundle are listed."""
    files = sorted(n[len(SYSLOG_DIR):] for n in src.names if n.startswith(SYSLOG_DIR))
    recs, pruned = [], []
    for seq, typ, data, where in facts["syslog"]:
        if typ == "syslog_chunk":
            rec, why = chunk_record(data)
            if rec is None:
                res.note("%s: the syslog_chunk record cannot be used: %s" % (where, why))
                continue
            rec["seq"] = seq
            recs.append(rec)
        else:
            refs = pruned_refs(data)
            if refs is None:
                res.note("%s: the syslog_prune record cannot be used: its data cannot be read" % where)
                continue
            pruned.extend(refs)
    if not recs and not files:
        res.say("Syslog chunks", "none in this bundle")
        return
    by_name = {}
    for rec in recs:
        by_name.setdefault(rec["name"], []).append(rec)
    bad = 0
    for name in files:
        path = SYSLOG_DIR + name
        cands = by_name.get(name)
        problem = match_chunk(src, path, cands) if cands else "no syslog_chunk record in this bundle names it"
        if problem:
            res.fail("%s: %s" % (path, problem))
            bad += 1

    period = report_period(src)
    if period is None and recs:
        res.note("report.json states no usable period: every syslog_chunk record of this bundle counts as one of the period")
    of_period = 0
    deleted, absent, listed = [], [], set()
    for rec in recs:
        if period is not None and not (rec["from"] is not None and rec["to"] is not None and
                                       rec["from"] < period[1] and rec["to"] >= period[0]):
            continue
        of_period += 1
        name = rec["name"]
        if SYSLOG_DIR + name in src.nameset or name in listed:
            continue
        listed.add(name)
        label = "%s (syslog_chunk seq %d)" % (name, rec["seq"])
        if any(n == name and (not sha or sha == rec["sha256"]) for n, sha in pruned):
            deleted.append(label)
        else:
            absent.append(label)
    if deleted:
        res.note("%d syslog chunk(s) of the period are not in this bundle because the syslog store's retention limit deleted "
                 "them (a syslog_prune record names them; their SHA-256 stays in their syslog_chunk records): %s"
                 % (len(deleted), listing(deleted)))
    if absent:
        res.note("%d syslog chunk(s) of the period are not in this bundle and no syslog_prune record in it names them (deleted "
                 "after the records of this bundle, or not readable at export; their SHA-256 stays in their syslog_chunk "
                 "records): %s" % (len(absent), listing(absent)))

    if bad:
        text = "FAILED (%d of %d chunk file(s) are not what a syslog_chunk record states)" % (bad, len(files))
    elif files:
        text = "OK (%d chunk file(s), each matching its syslog_chunk record: SHA-256, size and message count)" % len(files)
    else:
        text = "OK (no chunk files in this bundle)"
    if deleted or absent:
        text += ("; of the %d chunk(s) of the period, %d deleted by the retention limit and %d not in the bundle (see the notes)"
                 % (of_period, len(deleted), len(absent)))
    res.say("Syslog chunks", text)


# ---------------------------------------------------------------------------- main


def inspect_token(path):
    with open(path, "rb") as fh:
        data = fh.read()
    try:
        info = parse_token(data)
    except TokenError as e:
        print(terminal_text("cannot parse token: %s" % e))
        return 1
    info["file_sha256"] = sha256_hex(data)
    print(json.dumps(info, indent=2, sort_keys=True))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Verify an att-monitor evidence bundle (zip or extracted folder).")
    ap.add_argument("bundle", nargs="?", help="bundle .zip file or extracted folder")
    ap.add_argument("--pure-python-ed25519", action="store_true",
                    help="check Ed25519 signatures with the built-in pure-Python implementation (slow)")
    ap.add_argument("--openssl-limit", type=int, default=25,
                    help="verify at most N time-stamp tokens with openssl (0 = never, -1 = all; default 25); "
                         "the latest token of each TSA is verified first")
    ap.add_argument("--max-failures", type=int, default=100, help="print at most N failures (default 100)")
    ap.add_argument("--trust-root", metavar="SHA256", action="append", type=parse_fingerprint,
                    help="also trust the certificate of keys/tsa-roots.pem with this SHA-256 fingerprint as a TSA root "
                         "(only after checking it against the fingerprint the TSA publishes); may be repeated")
    ap.add_argument("--inspect-token", metavar="FILE", help="print the content of an RFC 3161 token and exit")
    args = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(errors="replace")
        except (ValueError, OSError):
            pass
    if args.inspect_token:
        return inspect_token(args.inspect_token)
    if not args.bundle:
        ap.print_usage()
        return 2
    try:
        src = Source(args.bundle)
    except (OSError, zipfile.BadZipFile) as e:
        print(terminal_text("cannot open bundle %s: %s" % (args.bundle, e)))
        return 2
    res = Results()
    try:
        check_manifest(src, res)
        facts = check_ledger(src, res, args)
        check_report(src, res, facts)
        check_syslog(src, res, facts)
    finally:
        src.close()

    def out(line):
        print(terminal_text(line))

    out("att-monitor evidence bundle verification (verify_bundle.py %s, Python %s)" % (VERSION, sys.version.split()[0]))
    out("Bundle: %s" % args.bundle)
    for line in res.lines:
        out(line)
    if res.notes:
        out("Notes:")
        for n in res.notes:
            out("  - " + n)
    if res.warnings:
        out("Warnings (not checked):")
        for w in res.warnings:
            out("  - " + w)
    out("REPORT.html and report.json were NOT verified by this script: it checks the ledger records, which are the evidence. "
        "Use 'att-monitor verify-bundle' to verify the report's figures.")
    if res.failures:
        out("FAILURES (%d):" % len(res.failures))
        for f in res.failures[:args.max_failures]:
            out("  - " + f)
        if len(res.failures) > args.max_failures:
            out("  ... %d more" % (len(res.failures) - args.max_failures))
        out("RESULT: FAIL")
        return 1
    out("RESULT: PASS" + (" (with warnings)" if res.warnings else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
