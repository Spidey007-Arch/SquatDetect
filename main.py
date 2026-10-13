"""
Domain Impersonation Detector — Backend API
Clone of haveibeensquatted.com
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import asyncio
import json
import dns.resolver
import dns.exception
import itertools
import string
import socket
import datetime
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Generator

app = FastAPI(title="Domain Squatter Detector API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──────────────────────────────────────────────
# QWERTY keyboard adjacency map for typosquatting
# ──────────────────────────────────────────────
QWERTY = {
    'a': 'qwsz', 'b': 'vghn', 'c': 'xdfv', 'd': 'ersfxc', 'e': 'rdsw34',
    'f': 'rtgdcv', 'g': 'tyhfvb', 'h': 'yugjbn', 'i': 'ujko89', 'j': 'uikhbn',
    'k': 'iolj', 'l': 'opk', 'm': 'njk', 'n': 'bhjm', 'o': 'iklp90',
    'p': 'ol0', 'q': 'wa12', 'r': 'etdf45', 's': 'wedaxz', 't': 'ryfg56',
    'u': 'yhji78', 'v': 'cfgb', 'w': 'qesa23', 'x': 'zsdc', 'y': 'tghu67',
    'z': 'asx',
}

# Homoglyph replacements (Latin → lookalike Unicode)
HOMOGLYPHS = {
    'a': ['а', 'ɑ'],  # Cyrillic а
    'e': ['е', 'ё'],  # Cyrillic е
    'o': ['о', '0'],  # Cyrillic о
    'p': ['р'],       # Cyrillic р
    'c': ['с'],       # Cyrillic с
    'i': ['і', '1'],  # Cyrillic і
    'x': ['х'],       # Cyrillic х
}

COMBO_PREFIXES = ['login-', 'secure-', 'verify-', 'account-', 'auth-', 'my-', 'signin-', 'support-']
COMBO_SUFFIXES = ['-login', '-secure', '-verify', '-account', '-auth', '-signin', '-support', '-online', '-official']

COMMON_TLDS = ['.com', '.net', '.org', '.co', '.io', '.info', '.biz']

# ──────────────────────────────────────────────
# Permutation Engine
# ──────────────────────────────────────────────
def generate_permutations(domain: str) -> list[dict]:
    """Generate all lookalike domain variants with labelled attack types."""
    domain = domain.lower().strip()
    # Strip protocol/www
    domain = re.sub(r'^https?://', '', domain)
    domain = re.sub(r'^www\.', '', domain)

    # Split name and TLD
    parts = domain.rsplit('.', 1)
    if len(parts) != 2:
        raise ValueError("Invalid domain format")
    name, tld = parts[0], '.' + parts[1]

    variants: list[dict] = []
    seen = set()

    def add(variant_name: str, attack_type: str, original_tld: str = None):
        full = variant_name + (original_tld or tld)
        if full != domain and full not in seen:
            seen.add(full)
            variants.append({"domain": full, "attack_type": attack_type})

    # 1. Typosquatting – adjacent key substitution
    for i, ch in enumerate(name):
        for sub in QWERTY.get(ch, ''):
            add(name[:i] + sub + name[i+1:], "Typosquatting")

    # 2. Missing letter
    for i in range(len(name)):
        add(name[:i] + name[i+1:], "Missing Letter")

    # 3. Repeated letter
    for i, ch in enumerate(name):
        add(name[:i] + ch + name[i:], "Repeated Letter")

    # 4. Transposition
    for i in range(len(name) - 1):
        swapped = list(name)
        swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
        add(''.join(swapped), "Transposition")

    # 5. Homoglyph / IDN spoofing
    for i, ch in enumerate(name):
        for glyph in HOMOGLYPHS.get(ch, []):
            add(name[:i] + glyph + name[i+1:], "Homoglyph")

    # 6. Combosquatting
    for prefix in COMBO_PREFIXES:
        add(prefix + name, "Combosquatting")
    for suffix in COMBO_SUFFIXES:
        add(name + suffix, "Combosquatting")

    # 7. TLD swap
    for alt_tld in COMMON_TLDS:
        if alt_tld != tld:
            add(name, "TLD Swap", alt_tld)

    # 8. Hyphenation (inserting hyphens)
    for i in range(1, len(name)):
        add(name[:i] + '-' + name[i:], "Hyphenation")

    # 9. Bitsquatting – flip one bit per char
    for i, ch in enumerate(name):
        if ch in string.ascii_lowercase:
            for bit in range(8):
                flipped = ord(ch) ^ (1 << bit)
                if 32 <= flipped <= 126 and chr(flipped) != ch:
                    candidate = name[:i] + chr(flipped) + name[i+1:]
                    if all(c in string.ascii_lowercase + string.digits + '-' for c in candidate):
                        add(candidate, "Bitsquatting")

    return variants

# ──────────────────────────────────────────────
# Detection Engine (DNS / MX)
# ──────────────────────────────────────────────
resolver = dns.resolver.Resolver()
resolver.lifetime = 3
resolver.timeout = 3

def check_domain(entry: dict) -> dict:
    """Synchronously check DNS A, AAAA, MX records for a domain."""
    d = entry["domain"]
    result = {**entry, "dns": False, "ip": None, "mx": False, "risk_score": 0}

    try:
        # Try to resolve A record
        answers = resolver.resolve(d, 'A')
        result["dns"] = True
        result["ip"] = str(answers[0])
    except Exception:
        pass

    if not result["dns"]:
        try:
            answers = resolver.resolve(d, 'AAAA')
            result["dns"] = True
            result["ip"] = str(answers[0])
        except Exception:
            pass

    if result["dns"]:
        try:
            resolver.resolve(d, 'MX')
            result["mx"] = True
        except Exception:
            pass

    result["risk_score"] = compute_risk(result)
    return result

def compute_risk(entry: dict) -> int:
    """Simple risk score 0-100."""
    score = 0
    if entry["dns"]:
        score += 50
    if entry["mx"]:
        score += 30  # Has mail → likely phishing
    # Attack type weights
    weights = {
        "Homoglyph": 15, "Combosquatting": 10, "Typosquatting": 5,
        "Bitsquatting": 5, "TLD Swap": 5, "Transposition": 3,
        "Missing Letter": 3, "Repeated Letter": 2, "Hyphenation": 3,
    }
    score += weights.get(entry["attack_type"], 0)
    return min(score, 100)

# ──────────────────────────────────────────────
# Streaming SSE scan endpoint
# ──────────────────────────────────────────────
class ScanRequest(BaseModel):
    domain: str

@app.post("/scan")
def scan(req: ScanRequest):
    """Stream scan results as newline-delimited JSON (NDJSON)."""
    try:
        variants = generate_permutations(req.domain)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    total = len(variants)

    def stream() -> Generator[str, None, None]:
        # Send metadata first
        yield json.dumps({"type": "meta", "total": total, "domain": req.domain}) + "\n"

        with ThreadPoolExecutor(max_workers=30) as pool:
            futures = [pool.submit(check_domain, v) for v in variants]
            for i, future in enumerate(futures):
                result = future.result()
                result["type"] = "result"
                result["index"] = i + 1
                yield json.dumps(result, ensure_ascii=False) + "\n"

        yield json.dumps({"type": "done", "total": total}) + "\n"

    return StreamingResponse(stream(), media_type="application/x-ndjson")

@app.get("/health")
def health():
    return {"status": "ok"}
