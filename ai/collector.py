"""
collector.py — Phase 1a
Fetches all findings from DefectDojo, enriches with EPSS scores, saves to JSON.

Usage:
    python collector.py
"""

import os
import json
import time
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

DEFECTDOJO_URL  = os.getenv("DEFECTDOJO_URL", "http://localhost:8080")
API_TOKEN       = os.getenv("DEFECTDOJO_API_TOKEN", "")
USE_EPSS        = os.getenv("USE_EPSS", "true").lower() == "true"
OUTPUT_PATH     = "data/raw_findings.json"
PAGE_SIZE       = 100

if not API_TOKEN:
    raise SystemExit("ERROR: DEFECTDOJO_API_TOKEN is not set.")

headers = {
    "Authorization": f"Token {API_TOKEN}",
    "Content-Type": "application/json",
}

# ---------------------------------------------------------------------------
# 1. Fetch all findings from DefectDojo (paginated)
# ---------------------------------------------------------------------------
print("Fetching findings from DefectDojo...")

findings = []
url = f"{DEFECTDOJO_URL}/api/v2/findings/?limit={PAGE_SIZE}&offset=0"

while url:
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    findings.extend(data.get("results", []))
    url = data.get("next")
    print(f"  Fetched {len(findings)} / {data.get('count', '?')} findings...")
    time.sleep(0.1)

print(f"Done. {len(findings)} findings collected.")

# ---------------------------------------------------------------------------
# 2. Enrich with EPSS scores (FIRST.org public API, no auth needed)
#
# We prioritize EPSS data already present in DefectDojo (epss_score / epss_percentile).
# We only query FIRST.org for CVEs missing these scores.
# ---------------------------------------------------------------------------
if USE_EPSS:
    print("Checking for existing EPSS scores and fetching missing ones...")

    cve_ids_to_fetch = set()
    for f in findings:
        # Check if finding already has EPSS (from defectdojo-epss-patch.py)
        # Note: We check if epss_score exists and is > 0.
        if f.get("epss_score") is not None and float(f.get("epss_score", 0.0)) > 0:
            f["_epss_score"]      = float(f["epss_score"])
            f["_epss_percentile"] = float(f.get("epss_percentile", 0.0))
            continue

        # If not, collect the CVE to fetch it
        cve = str(f.get("cve_id") or "").strip().upper()
        if cve.startswith("CVE-"):
            cve_ids_to_fetch.add(cve)
        else:
            for vuln in f.get("vulnerability_ids") or []:
                url_val = str(vuln.get("url") or vuln.get("vulnerability_id") or "")
                cve_from_url = url_val.strip().split("/")[-1].upper()
                if cve_from_url.startswith("CVE-"):
                    cve_ids_to_fetch.add(cve_from_url)

    cve_ids_to_fetch = list(cve_ids_to_fetch)
    print(f"  {len(cve_ids_to_fetch)} unique CVE IDs need EPSS fetching.")

    epss_map = {}
    if cve_ids_to_fetch:
        for i in range(0, len(cve_ids_to_fetch), 30):
            batch = ",".join(cve_ids_to_fetch[i:i + 30])
            try:
                r = requests.get("https://api.first.org/data/v1/epss",
                                 params={"cve": batch}, timeout=10)
                r.raise_for_status()
                for entry in r.json().get("data", []):
                    epss_map[entry["cve"].upper()] = {
                        "epss":       float(entry.get("epss", 0.0)),
                        "percentile": float(entry.get("percentile", 0.0)),
                    }
                time.sleep(0.2)
            except Exception as e:
                print(f"  EPSS batch {i // 30 + 1} failed: {e}")

    # Attach newly fetched EPSS to findings that were missing it
    for f in findings:
        if "_epss_score" in f:
            continue

        cve = str(f.get("cve_id") or "").strip().upper()
        if not cve.startswith("CVE-"):
            for vuln in f.get("vulnerability_ids") or []:
                url_val = str(vuln.get("url") or vuln.get("vulnerability_id") or "")
                cve = url_val.strip().split("/")[-1].upper()
                if cve.startswith("CVE-"):
                    break
        
        scores = epss_map.get(cve, {"epss": 0.0, "percentile": 0.0})
        f["_epss_score"]      = scores["epss"]
        f["_epss_percentile"] = scores["percentile"]

    print(f"  EPSS enrichment complete ({len(epss_map)} new scores fetched).")
else:
    for f in findings:
        f["_epss_score"]      = 0.0
        f["_epss_percentile"] = 0.0

# ---------------------------------------------------------------------------
# 3. Save to disk
# ---------------------------------------------------------------------------
os.makedirs("data", exist_ok=True)

output = {
    "collected_at":   datetime.utcnow().isoformat() + "Z",
    "source_url":     DEFECTDOJO_URL,
    "total_findings": len(findings),
    "epss_enriched":  USE_EPSS,
    "findings":       findings,
}

with open(OUTPUT_PATH, "w") as f:
    json.dump(output, f, indent=2, default=str)

print(f"\nSaved {len(findings)} findings → {OUTPUT_PATH}")