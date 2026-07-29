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

# API Keys (injected via Environment / GitHub Secrets)
BRAVE_SEARCH_API_KEY = os.environ.get("BRAVE_SEARCH_API_KEY")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

# Supported active models (gemini-1.5-flash is deprecated and returns 404)
DEFAULT_GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
FALLBACK_MODELS = ["gemini-2.5-flash", "gemini-flash-latest", "gemini-3.6-flash"]

# File paths
CSV_PATH = "data/maritime_latest.csv"
CSV_HEADERS = ["name", "ring", "quadrant", "isNew", "description"]

# Search & Text configuration
SEARCH_QUERIES = [
    'site:cisa.gov OR site:dragos.com OR site:recordedfuture.com "maritime" OR "shipping" OR "port" cyber threat',
    'site:singcert.gov.sg OR site:maritimeisac.com "cyber attack" OR "threat actor"',
    '"maritime cyber" OR "port cyber" OR "shipping cyber" ransomware OR APT OR breach'
]
MAX_SEARCH_RESULTS_PER_QUERY = 5
MAX_JINA_TEXT_LENGTH = 3500       # Truncate boilerplate per article
ARTICLES_PER_GEMINI_BATCH = 3     # Batch articles to avoid 504 timeouts

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
    
    # Remove duplicates while preserving order
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

def fetch_all_articles_batched(urls: List[str], batch_size: int = 3) -> List[str]:
    """Fetch all articles and return them grouped in small batch text blocks."""
    fetched_articles = []
    
    for i, url in enumerate(urls, 1):
        print(f"Fetching article {i}/{len(urls)}: {url}")
        text = fetch_article_text(url)
        if text:
            fetched_articles.append(f"--- SOURCE {i}: {url} ---\n{text}")
    
    # Chunk into smaller batches
    batches = []
    for i in range(0, len(fetched_articles), batch_size):
        chunk = fetched_articles[i:i + batch_size]
        batches.append("\n\n".join(chunk))
    
    print(f"Grouped {len(fetched_articles)} articles into {len(batches)} batches for Gemini.")
    return batches

# ============================================================================
# GEMINI API
# ============================================================================

def generate_prompt(instruction_date: str, start_date: str, 
                   existing_threats: List[str], jina_text: str) -> str:
    """Generate the complete prompt for Gemini."""
    
    existing_threats_str = ", ".join(existing_threats) if existing_threats else "None"
    
    prompt = f"""ROLE: You are a maritime cyber-threat-intelligence analyst producing structured
input data for a "Threat Radar" (a ThoughtWorks Tech-Radar-style visualization)
tracking cyber threats to Singapore's maritime sector.

TASK: Analyze the provided threat intelligence reports and extract threat-actor activity
from the past 7 days. Output it strictly as a JSON array.

INSTRUCTION DATE: {instruction_date}
TIME WINDOW: {start_date} through {instruction_date} inclusive. Only include incidents
with a confirmed/reported date inside this 7-day window.

SOURCES: Raw text pre-fetched from CISA, CERTs, threat-intel vendors, and news.

TA SCOPE: Hacktivists, Cyber criminal gangs, State-sponsored actors, APTs, Cyber terrorists, Cyber mercenaries. Exclude insider threats and unattributed script-kiddie noise.

TARGET RELEVANCE: Only include activity plausibly relevant to Singapore's maritime/port ecosystem or global maritime supply chain with credible spillover.

EXISTING THREATS IN DATABASE (DO NOT DUPLICATE):
{existing_threats_str}

OUTPUT SCHEMA (JSON array of objects with these 5 fields):
name, ring, quadrant, isNew, description

FIELD RULES:
- name: Threat actor/group name (e.g. "Volt Typhoon (BRONZE SILHOUETTE)").
- ring: "Asia" or "ROTW" (Rest of World).
- quadrant: "CIIs", "My-Suppliers", or "All Others".
- isNew: true
- description: One HTML block per incident:
  <b>YYYY-MM-DD | Short Campaign Title</b><br>Target: ...<br>Vector: ...<br>Impact: ...
  If one actor has multiple incidents, separate each with <br><br><hr><br>.

JSON FORMATTING RULES:
- Output ONLY a valid JSON array of objects.
- Do not include markdown formatting (no ```json).
- Use <br> for line breaks inside description.
- Boolean values must be true/false (lowercase).

ANTI-HALLUCINATION RULE: Do not invent details. If no verifiable incidents exist in this batch for the window, return an empty array: []

RAW THREAT INTELLIGENCE REPORTS TO ANALYZE:
{jina_text}
"""
    return prompt

def call_gemini_single_batch(prompt: str) -> str:
    """Call Gemini API with timeouts, retry logic, and model fallback."""
    if not GEMINI_API_KEY:
        print("ERROR: GEMINI_API_KEY not set")
        return "[]"
    
    genai.configure(api_key=GEMINI_API_KEY)
    
    generation_config = {
        "response_mime_type": "application/json",
        "temperature": 0.1,
        "max_output_tokens": 2000
    }
    
    # Try preferred model first, then fallbacks
    models_to_try = [DEFAULT_GEMINI_MODEL] + [m for m in FALLBACK_MODELS if m != DEFAULT_GEMINI_MODEL]
    
    for current_model_name in models_to_try:
        try:
            model = genai.GenerativeModel(
                model_name=current_model_name,
                generation_config=generation_config
            )
            
            max_retries = 3
            base_delay = 5
            
            for attempt in range(max_retries):
                try:
                    print(f"Calling Gemini API ({current_model_name}) - Attempt {attempt + 1}/{max_retries}...")
                    
                    response = model.generate_content(
                        prompt,
                        request_options={"timeout": 120}  # 2-minute timeout
                    )
                    
                    if response.text:
                        print(f"Gemini response length: {len(response.text)} characters")
                        return response.text
                    else:
                        print("Warning: Gemini returned empty response")
                        return "[]"
                        
                except Exception as e:
                    error_str = str(e).lower()
                    
                    # If 404 Model Not Found, break inner loop to try fallback model
                    if "404" in error_str or "not found" in error_str:
                        print(f"Model {current_model_name} not available (404). Trying fallback model...")
                        break
                    
                    # Handle transient timeouts and gateway errors
                    if any(code in error_str for code in ["504", "deadline", "503", "502"]):
                        delay = base_delay * (2 ** attempt)
                        print(f"Transient error detected ({e}). Retrying in {delay} seconds...")
                        time.sleep(delay)
                    else:
                        print(f"Gemini API error on {current_model_name}: {e}")
                        return "[]"
                        
        except Exception as e:
            print(f"Configuration error for {current_model_name}: {e}")
            
    print("ERROR: All Gemini models failed or were unavailable.")
    return "[]"

# ============================================================================
# CSV GENERATION & MERGING
# ============================================================================

def parse_json_response(json_text: str) -> List[Dict[str, Any]]:
    """Clean and parse JSON output string from Gemini."""
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
    except json.JSONDecodeError as e:
        print(f"JSON Parse Error: {e}")
    
    return []

def write_csv(data: List[Dict[str, Any]]):
    """Write sanitized records to CSV."""
    os.makedirs(os.path.dirname(CSV_PATH), exist_ok=True)
    
    # Deduplicate entries across batches by (name, ring, quadrant)
    deduped = {}
    for entry in data:
        key = (entry.get("name", "").strip(), entry.get("ring", "").strip(), entry.get("quadrant", "").strip())
        if not key[0]:
            continue
        if key not in deduped:
            deduped[key] = {
                "name": entry.get("name", "Unknown"),
                "ring": entry.get("ring", "ROTW"),
                "quadrant": entry.get("quadrant", "All Others"),
                "isNew": True,
                "description": entry.get("description", "")
            }
        else:
            # Append new incident description if duplicate key
            existing_desc = deduped[key]["description"]
            new_desc = entry.get("description", "")
            if new_desc and new_desc not in existing_desc:
                deduped[key]["description"] = f"{existing_desc}<br><br><hr><br>{new_desc}"

    final_rows = list(deduped.values())
    
    with open(CSV_PATH, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
        writer.writeheader()
        for row in final_rows:
            writer.writerow(row)
            
    print(f"Successfully wrote {len(final_rows)} threat rows to {CSV_PATH}")

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
    
    print(f"Time window: {start_date_str} to {instruction_date_str}\n")
    
    # Step 1: Load existing threats
    print("Step 1: Loading existing threats...")
    existing_threats = load_existing_threats()
    print()
    
    # Step 2: Search URLs
    print("Step 2: Searching for threat intelligence URLs...")
    urls = get_all_urls()
    
    if not urls:
        print("No URLs found. Writing empty CSV.")
        write_csv([])
        return
    print()
    
    # Step 3: Fetch articles in batches
    print("Step 3: Fetching article text in batches...")
    batches = fetch_all_articles_batched(urls, batch_size=ARTICLES_PER_GEMINI_BATCH)
    
    if not batches:
        print("No article text retrieved. Writing empty CSV.")
        write_csv([])
        return
    print()
    
    # Step 4: Process batches through Gemini
    print("Step 4: Calling Gemini API for each batch...")
    all_extracted_entries = []
    
    for batch_idx, jina_text_batch in enumerate(batches, 1):
        print(f"\n--- Processing Batch {batch_idx}/{len(batches)} ---")
        prompt = generate_prompt(instruction_date_str, start_date_str, existing_threats, jina_text_batch)
        json_response = call_gemini_single_batch(prompt)
        
        entries = parse_json_response(json_response)
        print(f"Batch {batch_idx} extracted {len(entries)} entries.")
        all_extracted_entries.extend(entries)
    
    print()
    
    # Step 5: Merge and write CSV
    print("Step 5: Merging results and writing CSV...")
    write_csv(all_extracted_entries)
    print()
    
    print("=" * 60)
    print("CSV generation complete!")
    print("=" * 60)

if __name__ == "__main__":
    main()
