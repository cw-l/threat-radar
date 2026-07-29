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
import google.generativeai as genai

# ============================================================================
# CONFIGURATION
# ============================================================================

# API Keys (injected via GitHub Secrets)
BRAVE_SEARCH_API_KEY = os.environ.get("BRAVE_SEARCH_API_KEY")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-flash-latest")

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
MAX_JINA_TEXT_LENGTH = 6000      # Limit per individual article
MAX_TOTAL_JINA_LENGTH = 30000    # Global cap on combined text to prevent API timeouts (504s)

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
            # Limit individual article length
            if len(text) > MAX_JINA_TEXT_LENGTH:
                text = text[:MAX_JINA_TEXT_LENGTH] + "\n\n[TRUNCATED]"
            return text
        else:
            print(f"Jina Reader failed for {url}: HTTP {response.status_code}")
            return ""
    
    except requests.exceptions.RequestException as e:
        print(f"Jina Reader error for {url}: {e}")
        return ""

def fetch_all_articles(urls: List[str]) -> str:
    """Fetch all articles and combine into single text block with global length capping."""
    articles = []
    total_length = 0
    
    for i, url in enumerate(urls, 1):
        if total_length >= MAX_TOTAL_JINA_LENGTH:
            print(f"Reached global article text cap ({MAX_TOTAL_JINA_LENGTH} chars). Skipping remaining URLs.")
            break
            
        print(f"Fetching article {i}/{len(urls)}: {url}")
        text = fetch_article_text(url)
        
        if text:
            # Enforce global combined length cap to prevent oversized prompts
            if total_length + len(text) > MAX_TOTAL_JINA_LENGTH:
                remaining_budget = MAX_TOTAL_JINA_LENGTH - total_length
                text = text[:remaining_budget] + "\n\n[TRUNCATED DUE TO GLOBAL SIZE CAP]"
            
            articles.append(f"--- SOURCE {i}: {url} ---\n{text}")
            total_length += len(text)
    
    combined = "\n\n".join(articles)
    print(f"Combined article text length: {len(combined)} characters")
    return combined

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
from the past 7 days. Output it strictly as a JSON array (which will be converted to CSV).

INSTRUCTION DATE: {instruction_date}
TIME WINDOW: {start_date} through {instruction_date} inclusive. Only include incidents
with a confirmed/reported date inside this 7-day window.

SOURCES: The raw text below has been pre-fetched from real, verifiable reporting sources
including CISA advisories, FBI/IC3 alerts, ISACs (Maritime-ISAC, IT-ISAC, etc.), national
CERTs (e.g. SingCERT), reputable threat-intel vendors, mainstream/trade cybersecurity news,
and credibly reported dark web/forum/Reddit chatter.

TA SCOPE: Only include actors falling into one of these categories:
Hacktivists, Cyber criminal gangs, State-sponsored actors, APTs, Cyber
terrorists, Cyber mercenaries. Exclude insider threats and generic
unattributed script-kiddie noise.

TARGET RELEVANCE: Only include activity plausibly relevant to Singapore's
maritime and port ecosystem — direct attacks on Singapore-linked maritime/port
critical infrastructure, attacks on the maritime supply chain / vendors /
logistics-tech providers serving Singapore, or broader global maritime/
shipping-sector campaigns with credible spillover relevance.

EXISTING THREATS IN DATABASE (DO NOT DUPLICATE):
{existing_threats_str}

OUTPUT SCHEMA (JSON array of objects, which will be converted to CSV with these 5 columns):
name, ring, quadrant, isNew, description

FIELD RULES:
- name: Threat actor/group name. Include known aliases in parentheses,
  e.g. "Volt Typhoon (BRONZE SILHOUETTE)".
- ring: "Asia" or "ROTW" (Rest of World). Asia = campaign directly targets
  Singapore/APAC maritime infrastructure. ROTW = campaign is global/elsewhere
  but relevant to Singapore's maritime supply chain or interests.
- quadrant: "CIIs" (own critical infrastructure — port authority, terminal
  operating systems, telecom backbone), "My-Suppliers" (third-party vendors —
  ERP, logistics software, satcom, ECDIS, freight/bunkering providers), or
  "All Others" (broader/global relevance, not directly own-CII or own-supplier).
- isNew: Set to true for every row (fixed default for now).
- description: One HTML block per incident:
  <b>YYYY-MM-DD | Short Campaign Title</b><br>Target: ...<br>Vector: ...<br>Impact: ...
  If one actor has multiple incidents in this window, list each as its own
  dated block, newest first, separated by <br><br><hr><br>.

ROW GRANULARITY: One row per threat actor per unique (ring, quadrant)
combination. If an actor's incidents span more than one ring or quadrant,
create a separate row per combination, with only that combination's
incidents in its description.

JSON FORMATTING RULES:
- Output ONLY a valid JSON array of objects.
- Do not include markdown formatting (no ```json), no commentary, no explanation.
- Use <br> for line breaks inside description — never literal newlines.
- Escape internal double quotes in strings by doubling them ("").
- Boolean values must be true/false (lowercase, no quotes).

REFERENCE FORMAT EXAMPLE (for structure only — this is a PRIOR period's data,
do not reuse, extend, re-date, or treat any of it as current. It exists only
to show you the exact schema, HTML formatting style, and multi-incident
<hr> pattern to follow):

[
  {{
    "name": "Volt Typhoon (BRONZE SILHOUETTE)",
    "ring": "Asia",
    "quadrant": "CIIs",
    "isNew": true,
    "description": "<b>2026-05-18 | Active Pre-Positioning & LotL Activity</b><br>Target: Critical infrastructure Operational Technology (OT) networks in Singapore, focused heavily on port automation control systems supporting PSA and Jurong Port layouts.<br>Vector: Stealth-first Living-off-the-land (LotL) execution exploiting unpatched edge networking components to harvest internal domain credentials.<br>Impact: Silent establishment of persistent access footprints inside Terminal Operating Systems (TOS)."
  }},
  {{
    "name": "Akira Ransomware Group",
    "ring": "ROTW",
    "quadrant": "My-Suppliers",
    "isNew": true,
    "description": "<b>2026-05-12 | Vendor Supply Chain Extortion</b><br>Target: Third-party cloud-native Maritime Enterprise Resource Planning (ERP) and fleet logistics software providers serving Singapore hub networks.<br>Vector: Helpdesk social engineering and high-frequency MFA fatigue attacks to compromise administrator portals.<br>Impact: Quiet data-theft campaign exfiltrating over 1TB of cargo manifests and custom clearance pipelines."
  }}
]

ANTI-HALLUCINATION RULE (critical): Do not invent CVEs, dates, victim names,
or incident details. If you're not confident an incident is real and falls
within the stated window, leave it out. Returning 2 accurate rows is far
better than 10 rows padded with fabricated detail. If you find no verifiable
incidents for this window, return an empty array: []

Now analyze the following pre-fetched threat intelligence reports and generate the JSON array for the window: {start_date} to {instruction_date}.

RAW THREAT INTELLIGENCE REPORTS TO ANALYZE:
{jina_text}
"""
    
    return prompt

def call_gemini(prompt: str) -> str:
    """Call Gemini API with JSON mode, token capping, extended timeout, and exponential backoff retry logic."""
    if not GEMINI_API_KEY:
        print("ERROR: GEMINI_API_KEY not set")
        return "[]"
    
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        
        # 1. Enforce JSON mode and token cap for fast, bounded generation
        generation_config = {
            "response_mime_type": "application/json",
            "temperature": 0.1,         # Low temperature for deterministic output
            "max_output_tokens": 2500   # Prevents runaway output generation and 504 timeouts
        }
        
        model = genai.GenerativeModel(
            model_name=GEMINI_MODEL,
            generation_config=generation_config
        )
        
        # 2. Configure retries with exponential backoff
        max_retries = 3
        base_delay = 5  # Initial backoff delay in seconds (5s, 10s, 20s)
        
        for attempt in range(max_retries):
            try:
                print(f"Calling Gemini API (Attempt {attempt + 1}/{max_retries})...")
                
                # 3. Increase client-side timeout to 120s
                response = model.generate_content(
                    prompt,
                    request_options={"timeout": 120}
                )
                
                if response.text:
                    print(f"Gemini response length: {len(response.text)} characters")
                    return response.text
                else:
                    print("ERROR: Gemini returned empty response")
                    return "[]"
                    
            except Exception as e:
                error_str = str(e).lower()
                # Detect transient network/gateway/timeout error codes
                transient_keywords = ["504", "deadline", "503", "502", "429", "resourceexhausted", "unavailable", "timeout"]
                is_transient = any(kw in error_str for kw in transient_keywords)
                
                if is_transient and attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)  # 5s, 10s, 20s
                    print(f"Transient error detected ({e}). Retrying in {delay} seconds...")
                    time.sleep(delay)
                else:
                    # Non-transient error or retries exhausted
                    print(f"Gemini API error on attempt {attempt + 1}: {e}")
                    if not is_transient:
                        # Fail fast for client configuration or auth errors
                        return "[]"
        
        print("ERROR: Max retries exceeded for Gemini API")
        return "[]"
        
    except Exception as e:
        print(f"Gemini API configuration error: {e}")
        return "[]"

# ============================================================================
# CSV GENERATION
# ============================================================================

def parse_and_write_csv(json_text: str):
    """Parse JSON response and write to CSV with robust cleaning."""
    
    # Clean up accidental markdown code fences
    json_text = json_text.strip()
    if json_text.startswith("```"):
        first_newline = json_text.find("\n")
        if first_newline != -1:
            json_text = json_text[first_newline + 1:]
    if json_text.endswith("```"):
        json_text = json_text[:-3]
    json_text = json_text.strip()
    
    try:
        data = json.loads(json_text)
        
        if not isinstance(data, list):
            print("ERROR: Gemini did not return a JSON array")
            data = []
        
        print(f"Parsed {len(data)} threat entries from JSON")
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(CSV_PATH), exist_ok=True)
        
        # Write CSV
        with open(CSV_PATH, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
            writer.writeheader()
            
            for entry in data:
                # Validate and clean entry fields
                row = {
                    "name": entry.get("name", "Unknown"),
                    "ring": entry.get("ring", "ROTW"),
                    "quadrant": entry.get("quadrant", "All Others"),
                    "isNew": entry.get("isNew", True),
                    "description": entry.get("description", "")
                }
                writer.writerow(row)
        
        print(f"Successfully wrote {len(data)} rows to {CSV_PATH}")
        
    except json.JSONDecodeError as e:
        print(f"ERROR: Failed to parse JSON: {e}")
        print(f"Raw response snippet: {json_text[:300]}...")
        
        # Fallback: Write empty CSV with headers
        os.makedirs(os.path.dirname(CSV_PATH), exist_ok=True)
        with open(CSV_PATH, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
            writer.writeheader()
        print("Wrote empty CSV with headers as fallback")

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
    
    print(f"Time window: {start_date_str} to {instruction_date_str}")
    print()
    
    # Step 1: Load existing threats for deduplication
    print("Step 1: Loading existing threats...")
    existing_threats = load_existing_threats()
    print()
    
    # Step 2: Search for URLs via Brave
    print("Step 2: Searching for threat intelligence URLs...")
    urls = get_all_urls()
    
    if not urls:
        print("No URLs found. Writing empty CSV.")
        os.makedirs(os.path.dirname(CSV_PATH), exist_ok=True)
        with open(CSV_PATH, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
            writer.writeheader()
        return
    print()
    
    # Step 3: Fetch full article text via Jina Reader
    print("Step 3: Fetching full article text...")
    jina_text = fetch_all_articles(urls)
    
    if not jina_text or len(jina_text) < 100:
        print("No article text retrieved. Writing empty CSV.")
        os.makedirs(os.path.dirname(CSV_PATH), exist_ok=True)
        with open(CSV_PATH, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
            writer.writeheader()
        return
    print()
    
    # Step 4: Generate prompt and call Gemini
    print("Step 4: Generating prompt and calling Gemini...")
    prompt = generate_prompt(instruction_date_str, start_date_str, 
                            existing_threats, jina_text)
    json_response = call_gemini(prompt)
    print()
    
    # Step 5: Parse JSON and write CSV
    print("Step 5: Parsing JSON and writing CSV...")
    parse_and_write_csv(json_response)
    print()
    
    print("=" * 60)
    print("CSV generation complete!")
    print("=" * 60)

if __name__ == "__main__":
    main()
