"""
Generates the weekly maritime Threat Radar CSV using the Gemini API free tier.

MVP design notes:
- Single model, single call, no merge/fallback across providers.
- MODEL is a config value at the top of this file -- swap it here if you
  later want a different free-tier model (e.g. a different Flash version,
  or a different provider's script entirely). Check current free-tier
  models/limits at https://ai.google.dev/gemini-api/docs/pricing before
  changing this, since free-tier model availability shifts over time.
- Uses Gemini's Google Search grounding tool so the model can actually
  look things up, rather than answering from static training data alone.
- No merge/dedupe, no multi-model loop -- this is intentionally the
  simplest version that produces one CSV per run.
"""

import csv
import datetime
import io
import os

import requests

# ---- config -----------------------------------------------------------
MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.5-flash")
API_URL = (
    f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent"
)
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "data")
PROMPT_PATH = os.path.join(os.path.dirname(__file__), "prompt_template.txt")
EXPECTED_HEADER = ["name", "ring", "quadrant", "isNew", "description"]

# ---- prompt building ---------------------------------------------------

def build_prompt() -> str:
    with open(PROMPT_PATH, "r", encoding="utf-8") as f:
        template = f.read()
    today = datetime.date.today()
    window_start = today - datetime.timedelta(days=7)
    return (
        template.replace("[INSTRUCTION_DATE]", today.isoformat())
        .replace("[WINDOW_START]", window_start.isoformat())
    )


# ---- API call -----------------------------------------------------------

def call_gemini(prompt: str) -> str:
    api_key = os.environ["GEMINI_API_KEY"]
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "tools": [{"googleSearch": {}}],
    }
    resp = requests.post(
        API_URL, params={"key": api_key}, json=payload, timeout=120
    )
    resp.raise_for_status()
    data = resp.json()
    try:
        candidate = data["candidates"][0]
        parts = candidate["content"]["parts"]
        return "".join(p.get("text", "") for p in parts)
    except (KeyError, IndexError) as exc:
        raise RuntimeError(f"Unexpected Gemini response shape: {data}") from exc


# ---- cleanup + validation ------------------------------------------------

def clean_csv_text(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines)
    return text.strip()


def validate_csv(text: str):
    rows = list(csv.reader(io.StringIO(text)))
    if not rows:
        raise ValueError("Model returned no CSV content at all.")
    if rows[0] != EXPECTED_HEADER:
        raise ValueError(f"Header mismatch. Got {rows[0]!r}, expected {EXPECTED_HEADER!r}")
    for i, row in enumerate(rows[1:], start=2):
        if len(row) != len(EXPECTED_HEADER):
            raise ValueError(f"Row {i} has {len(row)} fields, expected {len(EXPECTED_HEADER)}: {row}")
    return rows


# ---- main ----------------------------------------------------------------

def main():
    prompt = build_prompt()
    raw = call_gemini(prompt)
    csv_text = clean_csv_text(raw)
    rows = validate_csv(csv_text)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    filename = f"maritime_{datetime.date.today().isoformat()}.csv"
    filepath = os.path.join(OUTPUT_DIR, filename)
    with open(filepath, "w", encoding="utf-8", newline="") as f:
        f.write(csv_text)
        if not csv_text.endswith("\n"):
            f.write("\n")

    print(f"Wrote {len(rows) - 1} threat row(s) to {filepath} using model={MODEL}")


if __name__ == "__main__":
    main()
