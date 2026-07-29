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
from typing import List, Dict, Any
import google.generativeai as genai

# ============================================================================
# CONFIGURATION
# ============================================================================

# API Keys (injected via Environment Variables / GitHub Secrets)
BRAVE_SEARCH_API_KEY = os.environ.get("BRAVE_SEARCH_API_KEY")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")

# File paths
CSV_PATH = "data/maritime_latest.csv"
CSV_HEADERS = ["name", "ring", "quadrant", "isNew", "description"]

# Search configuration
SEARCH_QUERIES = [
    'site:cisa.gov OR site:dragos.com OR site:recordedfuture.com "maritime" OR "shipping" OR "port" cyber threat',
    'site:singcert.gov.sg OR site:maritimeisac.com "cyber attack" OR "threat actor"',
    '"maritime cyber" OR "port cyber" OR "shipping cyber" ransomware OR APT OR breach'
]
MAX_SEARCH_RESULTS_PER_QUERY = 5
MAX_JINA_TEXT_LENGTH = 6000  # Limit per article to prevent prompt bloat
ARTICLES_PER_BATCH = 3       # Group articles into batches to avoid 504 timeouts

# ============================================================================
# MODEL RESOLVER
# ============================================================================

_CACHED_MODEL_NAME = None

def get_working_model_name(requested_model: str) -> str:
    """Dynamically discover a supported Gemini model to avoid 404 errors."""
    global _CACHED_MODEL_NAME
    if _CACHED_MODEL_NAME:
        return _CACHED_MODEL_NAME

    # Priority candidate list
    candidates = [
        requested_model,
        "gemini-2.5-flash",
        "gemini-2.0-flash",
        "gemini-1.5-flash",
        "gemini-flash-latest"
    ]
    
    # Filter out empty or duplicate entries
    seen = set()
    unique_candidates = [m for m in candidates if m and not (m in seen or seen.add(m))]

    try:
        genai.configure(api_key=GEMINI_API_KEY)
        available_models = [m.name for m in genai.list_models() if "generateContent" in m.supported_generation_methods]
        clean_available = {m.replace("models/", ""): m for m in available_models}

        for cand in unique_candidates:
            clean_cand = cand.replace("models/", "")
            if clean_cand in clean_available:
                _CACHED_MODEL_NAME = clean_available[clean_cand]
                print(f"Verified available Gemini model: {_CACHED_MODEL_NAME}")
                return _CACHED_MODEL_NAME
    except Exception as e:
        print(f"Warning: Could not list models ({e}). Falling back to requested: {requested_model}")

    _CACHED_MODEL_NAME = requested_model
    return requested_model

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
    """Search Brave Search API and return list of URLs."""
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
        "offset": 0,
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
        
        print(f"Brave search found {len(urls)} URLs for query: {query[:50]}...")
        return urls
    
    except requests.exceptions.RequestException as e:
        print(f"Brave search failed: {e}")
        return []

def get_all_urls() -> List[str]:
    """Run all search queries and return unique URLs."""
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
    """Fetch full article text using Jina Reader."""
    jina_url = f"https://r.jina.ai/{url}"
    
    try:
        response = requests.get(jina_url, timeout=15)
        
        if response.status_code == 200:
            text = response.text
            if len(text) > MAX_JINA_TEXT_LENGTH:
                text = text[:MAX_JINA_TEXT_LENGTH] + "\n\n[TRUNCATED]"
            return text
        else:
            print(f"Jina Reader failed for {url}: HTTP {response.status_code}")
            return ""
    
    except requests.exceptions.RequestException as e:
        print(f"Jina Reader error for {url}: {e}")
        return ""

def fetch_all_articles(urls: List[str], current_date_str: str) -> List[Dict[str, str]]:
    """Fetch articles and return list of objects with metadata."""
    articles = []
    
    for i, url in enumerate(urls, 1):
        print(f"Fetching article {i}/{len(urls)}: {url}")
        text = fetch_article_text(url)
        
        if text and len(text.strip()) > 100:
            articles.append({
                "url": url,
                "fetched_date": current_date_str,
                "text": text
            })
    
    print(f"Successfully fetched {len(articles)} articles.")
    return articles

# ============================================================================
# GEMINI API
# ============================================================================

def generate_prompt(instruction_date: str, day_of_week: str, start_date: str, 
                   existing_threats: List[str], jina_text: str) -> str:
    """Generate the optimized prompt for Gemini with flexible date context."""
    
    existing_threats_str = ", ".join(existing_threats) if existing_threats else "None"
    
    prompt = f"""ROLE: You are a maritime cyber-threat-intelligence analyst producing structured
input data for a "Threat Radar" tracking cyber threats to Singapore's maritime sector.

TASK: Analyze the provided threat intelligence reports and extract threat-actor activity
reported in the recent 7-day window ({start_date} through {instruction_date}).
Output the result strictly as a JSON array of objects.

CURRENT DATE CONTEXT:
- Today is: {instruction_date} ({day_of_week})
- Time Window: {start_date} through {instruction_date} inclusive.

DATE REASONING RULES:
- Articles may use relative dates like "yesterday", "this week", "last Tuesday", "recently", "July 25", or give no exact day.
- Treat any threat or incident reported in these articles as occurring within the 7-day window UNLESS the text explicitly states it occurred in a prior year or earlier month (e.g. 2024 or 2025).
- For the incident date in the description field, use the date explicitly mentioned in the text (e.g. YYYY-MM-DD). If no exact date is present, estimate it based on the report context or default to {instruction_date}.

TARGET RELEVANCE:
Include activity plausibly relevant to Singapore's maritime & port ecosystem — direct attacks on Singapore-linked maritime infrastructure, attacks on maritime supply chain vendors (ERP, satcom, logistics, ECDIS), or global shipping sector campaigns.

TA SCOPE:
Hacktivists, Cyber criminal gangs, State-sponsored actors, APTs, Cyber terrorists, Ransomware groups. Exclude generic unattributed noise.

EXISTING THREATS IN DATABASE (DO NOT DUPLICATE EXISTING NAMES UNLESS NEW INCIDENT):
{existing_threats_str}

OUTPUT SCHEMA (JSON array of objects):
[
  {{
    "name": "Threat actor group name (aliases)",
    "ring": "Asia" or "ROTW",
    "quadrant": "CIIs" or "My-Suppliers" or "All Others",
    "isNew": true,
    "description": "<b>YYYY-MM-DD | Short Title</b><br>Target: ...<br>Vector: ...<br>Impact: ..."
  }}
]

FIELD RULES:
- ring: "Asia" = targets Singapore/APAC maritime infrastructure. "ROTW" = Rest of World/Global relevance.
- quadrant: "CIIs" (Port authority, terminal operating systems), "My-Suppliers" (vendors, ERP, satcom, freight tech), "All Others" (general maritime).
- isNew: true
- description: Single line HTML string. Use <br> for line breaks — NEVER literal newlines inside strings.

FORMATTING MANDATE:
- Output ONLY a valid JSON array.
- Do not wrap in ```json markdown block.
- If no relevant incidents are found, return empty array: []

RAW THREAT INTELLIGENCE REPORTS TO ANALYZE:
{jina_text}
"""
    return prompt

def call_gemini(prompt: str) -> str:
    """Call Gemini API with dynamic model selection, retry backoff, and timeouts."""
    if not GEMINI_API_KEY:
        print("ERROR: GEMINI_API_KEY not set")
        return "[]"
    
    model_name = get_working_model_name(GEMINI_MODEL)
    
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        
        generation_config = {
            "response_mime_type": "application/json",
            "temperature": 0.1,
            "max_output_tokens": 3000
        }
        
        model = genai.GenerativeModel(
            model_name=model_name,
            generation_config=generation_config
        )
        
        max_retries = 3
        base_delay = 4
        
        for attempt in range(max_retries):
            try:
                print(f"Calling Gemini API ({model_name}) - Attempt {attempt + 1}/{max_retries}...")
                
                response = model.generate_content(
                    prompt,
                    request_options={"timeout": 120}
                )
                
                if response and response.text:
                    res_text = response.text.strip()
                    print(f"Gemini response length: {len(res_text)} characters")
                    return res_text
                else:
                    print("ERROR: Gemini returned empty response text")
                    return "[]"
                    
            except Exception as e:
                error_str = str(e).lower()
                if "504" in error_str or "deadline" in error_str or "503" in error_str or "502" in error_str:
                    delay = base_delay * (2 ** attempt)
                    print(f"Transient error ({e}). Retrying in {delay} seconds...")
                    time.sleep(delay)
                else:
                    print(f"Gemini API Fatal Error: {e}")
                    return "[]"
        
        print("ERROR: Max retries exceeded for Gemini API")
        return "[]"
        
    except Exception as e:
        print(f"Gemini API configuration error: {e}")
        return "[]"

# ============================================================================
# CSV MERGE & GENERATION
# ============================================================================

def clean_json_response(json_text: str) -> List[Dict[str, Any]]:
    """Clean markdown artifacts and parse JSON safely."""
    text = json_text.strip()
    if text.startswith("```json"):
        text = text[7:]
    if text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()
    
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return data
        return []
    except json.JSONDecodeError as e:
        print(f"Failed to parse batch JSON response: {e}")
        return []

def parse_and_write_csv(entries: List[Dict[str, Any]]):
    """Write parsed threat entries to CSV."""
    os.makedirs(os.path.dirname(CSV_PATH), exist_ok=True)
    
    try:
        with open(CSV_PATH, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
            writer.writeheader()
            
            written_count = 0
            for entry in entries:
                row = {
                    "name": entry.get("name", "Unknown Threat"),
                    "ring": entry.get("ring", "ROTW"),
                    "quadrant": entry.get("quadrant", "All Others"),
                    "isNew": entry.get("isNew", True),
                    "description": entry.get("description", "")
                }
                writer.writerow(row)
                written_count += 1
                
        print(f"Successfully wrote {written_count} threat rows to {CSV_PATH}")
        
    except Exception as e:
        print(f"ERROR writing CSV file: {e}")

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    print("=" * 60)
    print("Maritime Cyber Threat Intelligence CSV Generator")
    print("=" * 60)
    
    # Calculate dates
    now = datetime.now()
    start_date = now - timedelta(days=7)
    instruction_date_str = now.strftime("%Y-%m-%d")
    day_of_week = now.strftime("%A")
    start_date_str = start_date.strftime("%Y-%m-%d")
    
    print(f"Time window: {start_date_str} to {instruction_date_str} ({day_of_week})")
    print()
    
    # Step 1: Load existing threats
    print("Step 1: Loading existing threats...")
    existing_threats = load_existing_threats()
    print()
    
    # Step 2: Search Brave for URLs
    print("Step 2: Searching for threat intelligence URLs...")
    urls = get_all_urls()
    
    if not urls:
        print("No URLs found. Writing empty CSV.")
        parse_and_write_csv([])
        return
    print()
    
    # Step 3: Fetch article texts
    print("Step 3: Fetching article texts...")
    articles = fetch_all_articles(urls, instruction_date_str)
    
    if not articles:
        print("No article content retrieved. Writing empty CSV.")
        parse_and_write_csv([])
        return
    print()
    
    # Step 4: Batch articles and Call Gemini
    print("Step 4: Grouping articles into batches and calling Gemini API...")
    
    # Group articles into batches of ARTICLES_PER_BATCH (e.g. 3)
    batches = [articles[i:i + ARTICLES_PER_BATCH] for i in range(0, len(articles), ARTICLES_PER_BATCH)]
    print(f"Grouped {len(articles)} articles into {len(batches)} batches for Gemini.")
    print()
    
    all_extracted_threats: List[Dict[str, Any]] = []
    
    for idx, batch in enumerate(batches, 1):
        print(f"--- Processing Batch {idx}/{len(batches)} ({len(batch)} articles) ---")
        
        # Build batch text block with article publication/fetch context
        batch_text_blocks = []
        for a_idx, item in enumerate(batch, 1):
            batch_text_blocks.append(
                f"--- SOURCE {a_idx} [URL: {item['url']} | Report Context Date: {item['fetched_date']}] ---\n{item['text']}"
            )
        
        combined_batch_text = "\n\n".join(batch_text_blocks)
        
        prompt = generate_prompt(
            instruction_date_str, 
            day_of_week, 
            start_date_str, 
            existing_threats, 
            combined_batch_text
        )
        
        json_resp = call_gemini(prompt)
        extracted = clean_json_response(json_resp)
        
        print(f"Batch {idx} extracted {len(extracted)} entries.")
        all_extracted_threats.extend(extracted)
        print()
    
    # Step 5: Deduplicate and Write CSV
    print("Step 5: Merging results and writing CSV...")
    
    # Deduplicate extracted results by threat name
    unique_entries = []
    seen_names = set()
    for entry in all_extracted_threats:
        name = entry.get("name", "").strip()
        if name and name.lower() not in seen_names:
            seen_names.add(name.lower())
            unique_entries.append(entry)
            
    parse_and_write_csv(unique_entries)
    print()
    
    print("=" * 60)
    print("CSV generation complete!")
    print("=" * 60)

if __name__ == "__main__":
    main()
