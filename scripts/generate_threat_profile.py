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

# API Keys (injected via GitHub Secrets)
BRAVE_SEARCH_API_KEY = os.environ.get("BRAVE_SEARCH_API_KEY")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-1.5-flash")

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
MAX_JINA_TEXT_LENGTH = 8000  # Character limit per article

# Batching limits for Gemini API calls to prevent 504 timeouts
MAX_BATCH_CHARS = 12000
MAX_BATCH_COUNT = 3

# ============================================================================
# DEDUPLICATION & CSV HELPERS
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

def fetch_article(url: str) -> Dict[str, str]:
    """Fetch article text using Jina Reader."""
    jina_url = f"https://r.jina.ai/{url}"
    
    try:
        response = requests.get(jina_url, timeout=15)
        
        if response.status_code == 200:
            text = response.text
            if len(text) > MAX_JINA_TEXT_LENGTH:
                text = text[:MAX_JINA_TEXT_LENGTH] + "\n\n[TRUNCATED]"
            return {"url": url, "text": text}
        else:
            print(f"Jina Reader failed for {url}: HTTP {response.status_code}")
            return {"url": url, "text": ""}
    
    except requests.exceptions.RequestException as e:
        print(f"Jina Reader error for {url}: {e}")
        return {"url": url, "text": ""}

def fetch_all_articles(urls: List[str]) -> List[Dict[str, str]]:
    """Fetch all articles and return list of article objects."""
    articles = []
    for i, url in enumerate(urls, 1):
        print(f"Fetching article {i}/{len(urls)}: {url}")
        art = fetch_article(url)
        if art["text"]:
            articles.append(art)
    
    print(f"Successfully retrieved {len(articles)} articles.")
    return articles

# ============================================================================
# GEMINI API & DYNAMIC MODEL SELECTION
# ============================================================================

def discover_available_models() -> List[str]:
    """Dynamically query Gemini API for models supporting generateContent."""
    try:
        supported = []
        for m in genai.list_models():
            if 'generateContent' in m.supported_generation_methods:
                name = m.name.replace("models/", "")
                supported.append(name)
        return supported
    except Exception as e:
        print(f"Warning: Could not dynamically list models from Gemini API: {e}")
        return []

def get_model_candidates() -> List[str]:
    """Build prioritized list of candidate models for fallback."""
    candidates = []
    
    # 1. User specified GEMINI_MODEL env var
    if GEMINI_MODEL:
        clean_user_model = GEMINI_MODEL.replace("models/", "").strip()
        candidates.append(clean_user_model)
    
    # 2. Standard stable default aliases
    defaults = [
        "gemini-1.5-flash",
        "gemini-2.0-flash",
        "gemini-flash-latest",
        "gemini-1.5-pro"
    ]
    for d in defaults:
        if d not in candidates:
            candidates.append(d)
            
    # 3. Add dynamically discovered models from API
    api_discovered = discover_available_models()
    for m in api_discovered:
        if m not in candidates:
            candidates.append(m)
            
    return candidates

def generate_prompt(instruction_date: str, start_date: str, 
                   existing_threats: List[str], jina_text: str) -> str:
    """Generate the complete prompt for Gemini."""
    
    existing_threats_str = ", ".join(existing_threats) if existing_threats else "None"
    
    prompt = f"""ROLE: You are a maritime cyber-threat-intelligence analyst producing structured
input data for a "Threat Radar" (a ThoughtWorks Tech-Radar-style visualization)
tracking cyber threats to Singapore's maritime sector.

TASK: Analyze the provided threat intelligence reports and extract threat-actor activity
from the past 7 days. Output it strictly as a JSON array (which will be converted to CSV).

INSTRUCTION DATE: {instruction_date}
TIME WINDOW: {start_date} through {instruction_date} inclusive. Only include incidents
with a confirmed/reported date inside this 7-day window.

SOURCES: The raw text below has been pre-fetched from real, verifiable reporting sources.

TA SCOPE: Only include actors falling into one of these categories:
Hacktivists, Cyber criminal gangs, State-sponsored actors, APTs, Cyber
terrorists, Cyber mercenaries. Exclude insider threats and generic unattributed noise.

TARGET RELEVANCE: Only include activity plausibly relevant to Singapore's
maritime and port ecosystem.

EXISTING THREATS IN DATABASE (DO NOT DUPLICATE):
{existing_threats_str}

OUTPUT SCHEMA (JSON array of objects with 5 fields):
name, ring, quadrant, isNew, description

FIELD RULES:
- name: Threat actor/group name. Include known aliases in parentheses, e.g. "Volt Typhoon (BRONZE SILHOUETTE)".
- ring: "Asia" or "ROTW" (Rest of World).
- quadrant: "CIIs", "My-Suppliers", or "All Others".
- isNew: true
- description: HTML block: <b>YYYY-MM-DD | Title</b><br>Target: ...<br>Vector: ...<br>Impact: ...

JSON FORMATTING RULES:
- Output ONLY a valid JSON array of objects.
- Do not include markdown formatting (no ```json).
- Use <br> for line breaks inside description string.

RAW THREAT INTELLIGENCE REPORTS TO ANALYZE:
{jina_text}
"""
    return prompt

def call_gemini_with_fallback(prompt: str) -> str:
    """Call Gemini API with dynamic model discovery, 404 auto-failover, and exponential retries."""
    if not GEMINI_API_KEY:
        print("ERROR: GEMINI_API_KEY not set")
        return "[]"
    
    genai.configure(api_key=GEMINI_API_KEY)
    
    generation_config = {
        "response_mime_type": "application/json",
        "temperature": 0.1,
        "max_output_tokens": 2500
    }
    
    candidates = get_model_candidates()
    print(f"Model priority chain: {', '.join(candidates)}")
    
    for model_name in candidates:
        print(f"\n---> Trying model candidate: {model_name}")
        
        try:
            model = genai.GenerativeModel(
                model_name=model_name,
                generation_config=generation_config
            )
        except Exception as e:
            print(f"Failed to initialize model '{model_name}': {e}. Skipping...")
            continue
        
        max_retries = 3
        base_delay = 5  # seconds
        model_failed = False
        
        for attempt in range(max_retries):
            try:
                print(f"Calling Gemini ({model_name}) - Attempt {attempt + 1}/{max_retries}...")
                
                response = model.generate_content(
                    prompt,
                    request_options={"timeout": 120}  # 2-minute timeout
                )
                
                if response.text and len(response.text.strip()) > 2:
                    print(f"Success! Response received ({len(response.text)} chars).")
                    return response.text
                else:
                    print("Warning: Gemini returned an empty response or '[]'.")
                    # Break to try next candidate or retry
                    break
                    
            except Exception as e:
                error_str = str(e).lower()
                
                # Check for 404 / Model Not Found errors -> Fail fast to next model candidate
                if "404" in error_str or "not found" in error_str or "invalidargument" in error_str:
                    print(f"Model '{model_name}' not available (404/Not Found). Switching to fallback model...")
                    model_failed = True
                    break  # Exit attempt loop immediately to try next candidate
                
                # Check for transient network/timeout errors (504, 503, 502) -> Retry current model
                elif "504" in error_str or "deadline" in error_str or "503" in error_str or "502" in error_str:
                    delay = base_delay * (2 ** attempt)
                    print(f"Transient timeout error ({e}). Retrying in {delay} seconds...")
                    time.sleep(delay)
                else:
                    print(f"Gemini API error for model '{model_name}': {e}")
                    model_failed = True
                    break
                    
        if model_failed:
            continue
            
    print("ERROR: All Gemini model candidates failed or returned empty results.")
    return "[]"

# ============================================================================
# PROCESSING & CSV WRITING
# ============================================================================

def parse_json_response(json_text: str) -> List[Dict[str, Any]]:
    """Clean markdown artifacts and parse JSON string into list of dicts."""
    json_text = json_text.strip()
    if json_text.startswith("```json"):
        json_text = json_text[7:]
    if json_text.startswith("```"):
        json_text = json_text[3:]
    if json_text.endswith("```"):
        json_text = json_text[:-3]
    json_text = json_text.strip()
    
    if not json_text or json_text == "[]":
        return []
    
    try:
        data = json.loads(json_text)
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            return [data]
        return []
    except json.JSONDecodeError as e:
        print(f"Warning: Failed to parse JSON response: {e}")
        return []

def process_articles_in_batches(articles: List[Dict[str, str]], instruction_date_str: str, 
                                start_date_str: str, existing_threats: List[str]) -> List[Dict[str, Any]]:
    """Group articles into smaller batches to keep prompt size under limits."""
    if not articles:
        return []
    
    batches = []
    current_batch = []
    current_length = 0
    
    for art in articles:
        art_len = len(art["text"])
        if current_batch and (current_length + art_len > MAX_BATCH_CHARS or len(current_batch) >= MAX_BATCH_COUNT):
            batches.append(current_batch)
            current_batch = [art]
            current_length = art_len
        else:
            current_batch.append(art)
            current_length += art_len
            
    if current_batch:
        batches.append(current_batch)
        
    print(f"\nGrouped {len(articles)} articles into {len(batches)} batch(es) for Gemini API calls.")
    
    all_threats = []
    for idx, batch in enumerate(batches, 1):
        print(f"\n==================================================")
        print(f"Processing Batch {idx}/{len(batches)} ({len(batch)} source articles)")
        print(f"==================================================")
        
        batch_text = "\n\n".join([f"--- SOURCE {i+1}: {a['url']} ---\n{a['text']}" for i, a in enumerate(batch)])
        
        prompt = generate_prompt(instruction_date_str, start_date_str, existing_threats, batch_text)
        json_response = call_gemini_with_fallback(prompt)
        
        extracted = parse_json_response(json_response)
        print(f"Batch {idx} extracted {len(extracted)} threat entries.")
        all_threats.extend(extracted)
        
    return all_threats

def write_csv(threat_entries: List[Dict[str, Any]]):
    """Write extracted threat entries to CSV."""
    os.makedirs(os.path.dirname(CSV_PATH), exist_ok=True)
    
    try:
        with open(CSV_PATH, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
            writer.writeheader()
            
            for entry in threat_entries:
                row = {
                    "name": entry.get("name", "Unknown Threat Actor"),
                    "ring": entry.get("ring", "ROTW"),
                    "quadrant": entry.get("quadrant", "All Others"),
                    "isNew": entry.get("isNew", True),
                    "description": entry.get("description", "")
                }
                writer.writerow(row)
                
        print(f"\nSuccessfully wrote {len(threat_entries)} threat rows to {CSV_PATH}")
    except Exception as e:
        print(f"ERROR: Failed to write CSV file: {e}")

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    print("=" * 60)
    print("Maritime Cyber Threat Intelligence CSV Generator")
    print("=" * 60)
    
    # Calculate date window
    instruction_date = datetime.now()
    start_date = instruction_date - timedelta(days=7)
    instruction_date_str = instruction_date.strftime("%Y-%m-%d")
    start_date_str = start_date.strftime("%Y-%m-%d")
    
    print(f"Time window: {start_date_str} to {instruction_date_str}\n")
    
    # Step 1: Load existing threats
    print("Step 1: Loading existing threats for deduplication...")
    existing_threats = load_existing_threats()
    print()
    
    # Step 2: Search Brave for URLs
    print("Step 2: Searching for threat intelligence URLs...")
    urls = get_all_urls()
    if not urls:
        print("No URLs found. Writing empty CSV.")
        write_csv([])
        return
    print()
    
    # Step 3: Fetch full article text
    print("Step 3: Fetching full article text via Jina Reader...")
    articles = fetch_all_articles(urls)
    if not articles:
        print("No article content retrieved. Writing empty CSV.")
        write_csv([])
        return
    print()
    
    # Step 4: Call Gemini in batches with fallback logic
    print("Step 4: Calling Gemini API with dynamic model fallback and batching...")
    threat_entries = process_articles_in_batches(articles, instruction_date_str, start_date_str, existing_threats)
    print()
    
    # Step 5: Save results to CSV
    print("Step 5: Writing results to CSV...")
    write_csv(threat_entries)
    
    print("\n" + "=" * 60)
    print("CSV generation pipeline complete!")
    print("=" * 60)

if __name__ == "__main__":
    main()
