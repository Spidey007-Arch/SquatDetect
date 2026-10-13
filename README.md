# SquatWatch — Domain Impersonation Detector
> SE Computer Engineering · Cybersecurity Project  
> Clone of haveibeensquatted.com

---

## Architecture

```
squatdetector/
├── backend/
│   ├── main.py            ← FastAPI app (Permutation + Detection + Scoring engines)
│   └── requirements.txt
└── frontend/
    └── index.html         ← Single-file dashboard (no build step needed)
```

---

## Quick Start

### 1. Install & run the backend

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### 2. Open the frontend

Open `frontend/index.html` directly in your browser (double-click or `open frontend/index.html`).

> No build step, no npm, no framework — pure HTML/CSS/JS.

---

## How It Works

### Phase 1 — Permutation Engine (`generate_permutations`)
For a given domain (e.g. `paypal.com`) the engine generates lookalike variants using:

| Attack Type       | Example                    | Description                            |
|-------------------|----------------------------|----------------------------------------|
| Typosquatting     | `paupal.com`               | Adjacent QWERTY key substitution       |
| Missing Letter    | `paypl.com`                | One character removed                  |
| Repeated Letter   | `payppal.com`              | One character doubled                  |
| Transposition     | `papyal.com`               | Two adjacent chars swapped             |
| Homoglyph / IDN   | `pаypаl.com` (Cyrillic а)  | Visually identical Unicode substitution|
| Combosquatting    | `paypal-login.com`         | Appended/prepended keywords            |
| TLD Swap          | `paypal.net`               | Different top-level domain             |
| Hyphenation       | `pay-pal.com`              | Hyphen inserted                        |
| Bitsquatting      | `qaypal.com`               | Single bit flipped in ASCII code       |

### Phase 2 — Detection Engine (`check_domain`)
Each variant is checked in parallel (30 threads) for:
- **A / AAAA DNS record** → Is the domain live?
- **MX record** → Is it receiving email? (high phishing signal)

### Phase 3 — Risk Scoring (`compute_risk`)
Score 0–100 based on:
- DNS live: +50
- MX present: +30
- Attack type severity weight: +2 to +15

### Phase 4 — Streaming Dashboard
Results stream in real-time via NDJSON over HTTP.  
Frontend shows:
- Live progress bar
- Stats cards (live / MX / unregistered)
- Filterable, searchable table with risk badges

---

## Milestone Roadmap (extend this project)

| Milestone | Feature |
|-----------|---------|
| ✅ M1 | Permutation engine + DNS scanning |
| ✅ M2 | FastAPI backend with streaming |
| ✅ M3 | Live dashboard frontend |
| 🔲 M4 | VirusTotal / PhishTank API integration |
| 🔲 M5 | WHOIS registration date lookup |
| 🔲 M6 | Screenshot similarity (Playwright + SSIM) |
| 🔲 M7 | PostgreSQL result caching |
| 🔲 M8 | Export CSV / PDF report |

---

## API Reference

### `POST /scan`
```json
{ "domain": "paypal.com" }
```
Returns: NDJSON stream of:
```
{"type":"meta","total":843,"domain":"paypal.com"}
{"type":"result","domain":"paupal.com","attack_type":"Typosquatting","dns":false,"ip":null,"mx":false,"risk_score":5,"index":1}
...
{"type":"done","total":843}
```

### `GET /health`
```json
{ "status": "ok" }
```
