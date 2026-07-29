#!/usr/bin/env python3
"""
Maritime Cyber Threat Intelligence CSV Generator
Automated weekly threat radar update using Brave Search + Jina Reader + Gemini API
"""

import os
import csv
import json
import time
import requests
from datetime import datetime, timedelta
from typing import List, Dict

# Import new Google GenAI SDK (or fall back to legacy google.generativeai if needed)
try:
    from google import genai
    from google.genai import types
    USE_NEW_SDK = True
except ImportError:
    import google.generativeai as legacy_genai
    USE_NEW_SDK = False

# ============================================================================
# CONFIGURATION
# ============================================================================

BRAVE_SEARCH_API_KEY = os.environ.get("BRAVE_SEARCH_API_KEY")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

# Preferred models in order of priority
PREFERRED_MODELS = [
    os.environ.get("GEMINI_MODEL", "gemini-2.5-flash"),
    "gemini-2.5-flash",
    "gemini-1.5-flash",
    "gemini-flash-latest"
]

CSV_PATH = "data/maritime_latest.csv"
CSV_HEADERS = ["name", "ring", "quadrant", "isNew", "description"]

SEARCH_QUERIES = [
    'site:cisa.gov OR site:dragos.com OR site:recordedfuture.com "maritime" OR "shipping" OR "port" cyber threat',
    'site:singcert.gov.sg OR site:maritimeisac.com "cyber attack" OR "threat actor"',
    '"maritime cyber" OR "port cyber" OR "shipping cyber" ransomware OR APT OR breach'
]
MAX_SEARCH_RESULTS_PER_QUERY = 5
MAX_JINA_TEXT_LENGTH = 6000  # Token cap per article
BATCH_SIZE = 3               # Process articles in small batches to prevent timeouts

# ============================================================================
# EXISTING THREATS DEDUPLICATION
# ============================================================================

def load_existing_threats() -> List[str]:
    """Read existing CSV and extract threat names for deduplication."""
    existing_threats = []
    if not os.path.exists(CSV_PATH):
        print(f"CSV file not found at {CSV_PATH}, starting fresh.")
        return existing_threats
    
    try:
        with open(CSV_PATH, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if 'name' in row and row['name']:
                    existing_threats.append(row['name'])
        print(f"Loaded {len(existing_threats)} existing threats for deduplication.")
    except Exception as e:
        print(f"Warning: Could not read existing CSV: {e}")
    
    return existing_threats

# ============================================================================
# BRAVE SEARCH API
# ============================================================================

def search_brave(query: str, max_results: int = 5) -> List[str]:
    if not BRAVE_SEARCH_API_KEY:
        print("ERROR: BRAVE_SEARCH_API_KEY not set")
        return []
    
    url = "https://api.search.brave.com/res/v1/web/search"
    headers = {
        "Accept": "application/json",
        "Accept-Encoding": "gzip",
        "X-Subscription-Token": BRAVE_SEARCH_API_KEY
    }
    params = {
        "q": query,
        "count": max_results,
        "freshness": "pw"  # Past week
    }
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        urls = []
        if "web" in data and "results" in data["web"]:
            for result in data["web"]["results"]:
                if "url" in result:
                    urls.append(result["url"])
        
        print(f"Brave search found {len(urls)} URLs for query: {query[:40]}...")
        return urls
    except Exception as e:
        print(f"Brave search failed: {e}")
        return []

def get_all_urls() -> List[str]:
    all_urls = []
    for query in SEARCH_QUERIES:
        urls = search_brave(query, MAX_SEARCH_RESULTS_PER_QUERY)
        all_urls.extend(urls)
    unique_urls = list(dict.fromkeys(all_urls))
    print(f"Total unique URLs to process: {len(unique_urls)}")
    return unique_urls

# ============================================================================
# JINA READER
# ============================================================================

def fetch_article_text(url: str) -> str:
    jina_url = f"https://r.jina.ai/{url}"
    try:
        response = requests.get(jina_url, timeout=15)
        if response.status_code == 200:
            text = response.text
            if len(text) > MAX_JINA_TEXT_LENGTH:
                text = text[:MAX_JINA_TEXT_LENGTH] + "\n\n[TRUNCATED]"
            return text
        return ""
    except Exception as e:
        print(f"Jina Reader error for {url}: {e}")
        return ""

def fetch_articles_in_batches(urls: List[str], batch_size: int = 3) -> List[str]:
    """Fetch articles and group into text blocks by batch."""
    fetched_articles = []
    for i, url in enumerate(urls, 1):
        print(f"Fetching article {i}/{len(urls)}: {url}")
        text = fetch_article_text(url)
        if text:
            fetched_articles.append(f"--- SOURCE {i}: {url} ---\n{text}")
    
    batches = []
    for i in range(0, len(fetched_articles), batch_size):
        batch_text = "\n\n".join(fetched_articles[i:i + batch_size])
        batches.append(batch_text)
    
    print(f"Grouped {len(fetched_articles)} articles into {len(batches)} batches for Gemini.")
    return batches

# ============================================================================
# GEMINI API PROMPT (SOLVES DATE ISSUE)
# ============================================================================

def generate_prompt(instruction_date: str, start_date: str, 
                   existing_threats: List[str], jina_text: str) -> str:
    """Generate prompt with flexible date matching rules."""
    
    existing_threats_str = ", ".join(existing_threats) if existing_threats else "None"
    
    prompt = f"""ROLE: You are a maritime cyber-threat-intelligence analyst producing structured
input data for a "Threat Radar" tracking cyber threats to Singapore's maritime sector.

TASK: Analyze the provided recent threat intelligence reports and extract threat-actor activity, campaigns, or advisories. Output strictly as a JSON array.

REPORT DATE CONTEXT: {instruction_date} (Target window: recent week ending {instruction_date}).

DATE EXTRACTION & FLEXIBILITY RULES:
1. The provided reports were retrieved from past-week searches.
2. In the description header (<b>YYYY-MM-DD | Title</b>):
   - If an explicit incident/advisory date is mentioned in the text (e.g., "2026-07-24"), use that date.
   - If no explicit YYYY-MM-DD date is stated in the article, use the report date ({instruction_date}).
3. DO NOT discard threat intelligence simply because an article describes an ongoing campaign or lacks an explicit YYYY-MM-DD timestamp in the body text. Extract all relevant active threats reported.

TA SCOPE: Include threat actors in: Hacktivists, Cyber criminal gangs, State-sponsored actors, APTs, Cyber terrorists, Cyber mercenaries, or named/unnamed ransomware groups. Exclude generic spam.

TARGET RELEVANCE: Activity relevant to Singapore or the global maritime/shipping supply chain (ports, shipping lines, maritime IT/OT vendors, logistics).

EXISTING THREATS IN DATABASE (DO NOT DUPLICATE):
{existing_threats_str}

OUTPUT SCHEMA (JSON array of objects):
name, ring, quadrant, isNew, description

FIELD RULES:
- name: Threat actor/group name (include aliases if available, e.g. "Volt Typhoon (BRONZE SILHOUETTE)").
- ring: "Asia" (Singapore/APAC targeting) or "ROTW" (Rest of World / global maritime).
- quadrant: "CIIs" (critical infrastructure/ports), "My-Suppliers" (maritime vendors/software/OT), or "All Others" (broader sector relevance).
- isNew: true
- description: HTML block formatted as:
  <b>YYYY-MM-DD | Short Campaign Title</b><br>Target: ...<br>Vector: ...<br>Impact: ...

JSON FORMATTING:
- Output ONLY a valid JSON array of objects `[...]`.
- Do not include markdown formatting (no ```json), no commentary.
- Use <br> for line breaks inside strings.

ANTI-HALLUCINATION: Do not invent fake group names or imaginary CVEs not present in the text. However, DO extract legitimate threat reports present in the provided text.

RAW THREAT INTELLIGENCE REPORTS TO ANALYZE:
{jina_text}
"""
    return prompt

# ============================================================================
# GEMINI API CALL WITH RETRIES & MODEL FALLBACK
# ============================================================================

def call_gemini(prompt: str) -> str:
    if not GEMINI_API_KEY:
        print("ERROR: GEMINI_API_KEY not set")
        return "[]"
    
    max_retries = 3
    base_delay = 5
    
    for model_name in PREFERRED_MODELS:
        for attempt in range(max_retries):
            try:
                print(f"Calling Gemini API ({model_name}) - Attempt {attempt + 1}/{max_retries}...")
                
                if USE_NEW_SDK:
                    client = genai.Client(api_key=GEMINI_API_KEY)
                    config = types.GenerateContentConfig(
                        response_mime_type="application/json",
                        temperature=0.1,
                        max_output_tokens=2500
                    )
                    response = client.models.generate_content(
                        model=model_name,
                        contents=prompt,
                        config=config
                    )
                else:
                    legacy_genai.configure(api_key=GEMINI_API_KEY)
                    generation_config = {
                        "response_mime_type": "application/json",
                        "temperature": 0.1,
                        "max_output_tokens": 2500
                    }
                    model = legacy_genai.GenerativeModel(
                        model_name=model_name,
                        generation_config=generation_config
                    )
                    response = model.generate_content(
                        prompt,
                        request_options={"timeout": 120}
                    )
                
                if response.text:
                    print(f"Gemini response length: {len(response.text)} characters")
                    return response.text
                else:
                    print("Gemini returned empty response text.")
                    return "[]"
                    
            except Exception as e:
                err_msg = str(e)
                if "404" in err_msg or "not found" in err_msg.lower():
                    print(f"Model {model_name} not available (404). Trying fallback model...")
                    break  # Try next model in PREFERRED_MODELS
                
                if any(code in err_msg for code in ["504", "503", "502", "deadline", "timeout"]):
                    delay = base_delay * (2 ** attempt)
                    print(f"Transient error ({err_msg[:60]}...). Retrying in {delay}s...")
                    time.sleep(delay)
                else:
                    print(f"Gemini API error: {e}")
                    return "[]"
                    
    print("ERROR: All Gemini models/retries failed")
    return "[]"

# ============================================================================
# CSV GENERATION & MERGING
# ============================================================================

def parse_json_response(json_text: str) -> List[Dict]:
    json_text = json_text.strip()
    if json_text.startswith("```json"):
        json_text = json_text[7:]
    if json_text.startswith("```"):
        json_text = json_text[3:]
    if json_text.endswith("```"):
        json_text = json_text[:-3]
    json_text = json_text.strip()
    
    try:
        data = json.loads(json_text)
        if isinstance(data, list):
            return data
    except Exception as e:
        print(f"Failed to parse JSON response: {e}")
    return []

def write_csv(all_entries: List[Dict]):
    os.makedirs(os.path.dirname(CSV_PATH), exist_ok=True)
    with open(CSV_PATH, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
        writer.writeheader()
        
        for entry in all_entries:
            row = {
                "name": entry.get("name", "Unknown"),
                "ring": entry.get("ring", "ROTW"),
                "quadrant": entry.get("quadrant", "All Others"),
                "isNew": entry.get("isNew", True),
                "description": entry.get("description", "")
            }
            writer.writerow(row)
    print(f"Successfully wrote {len(all_entries)} threat rows to {CSV_PATH}")

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    print("=" * 60)
    print("Maritime Cyber Threat Intelligence CSV Generator")
    print("=" * 60)
    
    instruction_date = datetime.now()
    start_date = instruction_date - timedelta(days=7)
    instruction_date_str = instruction_date.strftime("%Y-%m-%d")
    start_date_str = start_date.strftime("%Y-%m-%d")
    
    print(f"Time window context: {start_date_str} to {instruction_date_str}\n")
    
    existing_threats = load_existing_threats()
    urls = get_all_urls()
    
    if not urls:
        print("No URLs found. Writing empty CSV.")
        write_csv([])
        return
        
    batches = fetch_articles_in_batches(urls, batch_size=BATCH_SIZE)
    if not batches:
        print("No article text retrieved. Writing empty CSV.")
        write_csv([])
        return
    
    all_threat_entries = []
    
    print("\nStep 4: Calling Gemini API for each batch...")
    for idx, batch_text in enumerate(batches, 1):
        print(f"\n--- Processing Batch {idx}/{len(batches)} ---")
        prompt = generate_prompt(instruction_date_str, start_date_str, 
                                existing_threats, batch_text)
        json_response = call_gemini(prompt)
        entries = parse_json_response(json_response)
        print(f"Batch {idx} extracted {len(entries)} entries.")
        all_threat_entries.extend(entries)
    
    print("\nStep 5: Writing results to CSV...")
    write_csv(all_threat_entries)
    print("=" * 60)
    print("CSV generation complete!")
    print("=" * 60)

if __name__ == "__main__":
    main()
