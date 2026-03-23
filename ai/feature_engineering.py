"""
feature_engineering.py — Phase 1b  (patched)
Loads raw findings, builds a feature matrix, computes AI risk scores, saves to CSV.

Fixes applied vs original:
  1. scanner  — extract scanner name from test string "filename (Scanner Name)"
               rather than inspecting test.type nested dict that DefectDojo
               doesn't always populate.
  2. age_days — handle both datetime.date objects and ISO-string dates coming
               from the collector; fromisoformat() only accepts strings.
  3. has_cve  — DefectDojo returns CVEs in "vulnerability_ids" (string or list),
               not a "cve_id" key that the original code expected.
  4. duplicates — skip findings flagged duplicate=True at collection time so the
               feature count matches what DefectDojo shows in the UI.

Usage:
    python feature_engineering.py
"""

import os
import re
import json
import pandas as pd
from datetime import datetime, date, timezone

INPUT_PATH  = "data/raw_findings.json"
OUTPUT_PATH = "data/features.csv"

# ---------------------------------------------------------------------------
# Mappings
# ---------------------------------------------------------------------------

SEVERITY_SCORE = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "informational": 0
}

SEVERITY_TO_CVSS = {
    "critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5, "informational": 0.5
}

# FIX 1 — match against the human-readable scanner name in parentheses,
# e.g. "trivy-image-results.json (Trivy Scan)" → "trivy scan" → SCA
# The original code matched against test.type which DefectDojo does not always
# populate, so every row fell through to "OTHER".
SCANNER_MAP = {
    # SAST
    "semgrep":          "SAST",
    "bandit":           "SAST",
    "sonarqube":        "SAST",
    # DAST
    "zap scan":         "DAST",
    "zap":              "DAST",
    # SCA
    "trivy scan":       "SCA",
    "trivy":            "SCA",
    "dependency check": "SCA",
    "snyk":             "SCA",
    "npm audit":        "SCA",
}

CWE_CATEGORY_MAP = {
    **{c: "injection"      for c in [89, 77, 78, 79, 80, 611, 918]},
    **{c: "auth"           for c in [287, 306, 307, 384, 521, 522, 640]},
    **{c: "crypto"         for c in [310, 311, 312, 319, 326, 327, 328, 338]},
    **{c: "access_control" for c in [22, 269, 276, 284, 732, 862, 863]},
    **{c: "data_exposure"  for c in [200, 201, 209, 359, 540]},
    **{c: "memory"         for c in [119, 120, 121, 122, 125, 401, 416, 476]},
    **{c: "config"         for c in [16, 358, 547, 614, 1004]},
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def extract_scanner(test_field) -> str:
    """
    FIX 1 — resolve scanner category from the test string.

    DefectDojo returns test as either:
      • a plain string: "trivy-image-results.json (Trivy Scan)"
      • a dict:         {"id": 45, "title": "trivy-image-results.json",
                         "test_type": {"name": "Trivy Scan"}, ...}

    We prefer the parenthesised name in the string representation because it is
    always present.  If test is a dict we fall back to test_type.name.
    """
    if isinstance(test_field, str):
        # Extract text inside the last pair of parentheses: "Trivy Scan"
        m = re.search(r"\(([^)]+)\)\s*$", test_field)
        label = m.group(1).lower() if m else test_field.lower()
    elif isinstance(test_field, dict):
        tt = test_field.get("test_type") or {}
        label = (
            tt.get("name") or test_field.get("title") or ""
        ).lower()
    else:
        label = ""

    for key, cat in SCANNER_MAP.items():
        if key in label:
            return cat
    return "OTHER"


def extract_cve(f: dict) -> bool:
    """
    FIX 3 — detect presence of a CVE from any of the locations DefectDojo
    might store it:
      • f["vulnerability_ids"]  — string "CVE-2023-1234" or list of dicts
      • f["cve"]                — legacy top-level field
      • title regex             — embedded in the finding title
    """
    # 1. vulnerability_ids — string (xlsx export) or list of dicts (API JSON)
    vids = f.get("vulnerability_ids")
    if isinstance(vids, str) and _CVE_RE.search(vids):
        return True
    if isinstance(vids, list):
        for item in vids:
            vid = item.get("vulnerability_id", "") if isinstance(item, dict) else str(item)
            if _CVE_RE.search(vid):
                return True

    # 2. Top-level cve field (some parsers)
    cve = f.get("cve") or ""
    if isinstance(cve, str) and cve.upper().startswith("CVE-"):
        return True

    # 3. Regex in title
    if _CVE_RE.search(f.get("title") or ""):
        return True

    return False


def parse_age(date_val) -> int:
    """
    FIX 2 — handle both datetime.date objects and ISO-string dates.

    The collector may store dates as:
      • datetime.date / datetime.datetime  (openpyxl or already-parsed)
      • str "2026-03-11" or "2026-03-11T06:46:37Z"

    Returns age in days (≥0) or -1 if unparseable.
    """
    if date_val is None:
        return -1

    # Already a date/datetime object
    if isinstance(date_val, datetime):
        dt = date_val.replace(tzinfo=timezone.utc) if date_val.tzinfo is None else date_val
        return max((datetime.now(timezone.utc) - dt).days, 0)
    if isinstance(date_val, date):
        dt = datetime(date_val.year, date_val.month, date_val.day, tzinfo=timezone.utc)
        return max((datetime.now(timezone.utc) - dt).days, 0)

    # String — strip Z suffix that fromisoformat() rejects on Python < 3.11
    try:
        dt = datetime.fromisoformat(str(date_val).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return max((datetime.now(timezone.utc) - dt).days, 0)
    except (ValueError, TypeError):
        return -1

# ---------------------------------------------------------------------------
# 1. Load raw findings
# ---------------------------------------------------------------------------
print(f"Loading {INPUT_PATH}...")

with open(INPUT_PATH) as fh:
    raw = json.load(fh)

findings = raw.get("findings", raw) if isinstance(raw, dict) else raw
print(f"  {len(findings)} findings loaded.")

# FIX 4 — skip duplicates so the feature count matches the DefectDojo UI.
# The collector fetches all findings from the API; DefectDojo marks duplicates
# with duplicate=True but does not exclude them from paginated results.
before = len(findings)
findings = [f for f in findings if not f.get("duplicate", False)]
skipped = before - len(findings)
if skipped:
    print(f"  Skipped {skipped} duplicate findings ({len(findings)} remaining).")

# ---------------------------------------------------------------------------
# 2. Build feature rows
# ---------------------------------------------------------------------------
print("Building feature matrix...")

rows = []
for f in findings:

    # Severity
    severity = (f.get("severity") or "info").lower().strip()
    if severity not in SEVERITY_SCORE:
        severity = "info"

    # CVSS score
    cvss = None
    for field in ("cvssv3_score", "cvssv2_score", "cvss_score"):
        val = f.get(field)
        if val is not None:
            try:
                cvss = float(val)
                break
            except (ValueError, TypeError):
                pass
    if cvss is None or not (0.0 <= cvss <= 10.0):
        cvss = SEVERITY_TO_CVSS.get(severity, 0.5)

    # FIX 1 — scanner category
    scanner = extract_scanner(f.get("test"))

    # CWE category
    try:
        cwe_id  = int(str(f.get("cwe", "0")).replace("CWE-", "").strip())
        cwe_cat = CWE_CATEGORY_MAP.get(cwe_id, "other")
    except (ValueError, TypeError):
        cwe_cat = "unknown"

    # EPSS
    epss     = float(f.get("_epss_score", 0.0))
    epss_pct = float(f.get("_epss_percentile", 0.0))

    # FIX 3 — has_cve
    has_cve = 1 if extract_cve(f) else 0

    # FIX 2 — age_days
    age = parse_age(f.get("date") or f.get("created"))

    rows.append({
        "finding_id":      f.get("id", -1),
        "title":           f.get("title", ""),
        "severity":        severity,
        "scanner":         scanner,
        "cwe_category":    cwe_cat,
        "cvss_score":      cvss,
        "epss_score":      epss,
        "epss_percentile": epss_pct,
        "severity_score":  SEVERITY_SCORE.get(severity, 0),
        "age_days":        age,
        "is_verified":     int(bool(f.get("verified", False))),
        "is_active":       int(bool(f.get("active", True))),
        "has_cve":         has_cve,
    })

df = pd.DataFrame(rows)

# ---------------------------------------------------------------------------
# 3. Compute AI risk score
# ---------------------------------------------------------------------------
cvss_norm = df["cvss_score"] / 10.0
epss_norm = df["epss_score"]
sev_norm  = df["severity_score"] / 4.0
freshness = df["age_days"].apply(
    lambda d: 0.5 if d < 0 else max(0.0, 1.0 - d / 365.0)
)

df["ai_risk_score"] = (
    1.0 + (
        0.40 * cvss_norm
        + 0.30 * epss_norm
        + 0.20 * sev_norm
        + 0.10 * freshness
    ) * 9.0
).round(2)

df["ai_severity"] = pd.cut(
    df["ai_risk_score"],
    bins=[0, 2, 4, 6.5, 8.5, 10],
    labels=["Info", "Low", "Medium", "High", "Critical"],
    right=True,
)

# One-hot encode
df = pd.get_dummies(df, columns=["scanner", "cwe_category"], prefix=["scanner", "cwe"], dtype=int)

# ---------------------------------------------------------------------------
# 4. Save
# ---------------------------------------------------------------------------
os.makedirs("data", exist_ok=True)
df.to_csv(OUTPUT_PATH, index=False)

print(f"  Feature matrix: {df.shape[0]} rows × {df.shape[1]} columns")
print(f"\nAI Risk Score summary:\n{df['ai_risk_score'].describe().round(2).to_string()}")
print(f"\nAI Severity distribution:\n{df['ai_severity'].value_counts().to_string()}")

# Sanity-check the fixes
scanner_cols = [c for c in df.columns if c.startswith("scanner_")]
print(f"\nScanner columns: {scanner_cols}")
for col in scanner_cols:
    print(f"  {col}: {df[col].sum()} findings")

has_cve_count = df["has_cve"].sum() if "has_cve" in df.columns else 0
print(f"\nhas_cve=1: {has_cve_count} findings")

age_valid = (df["age_days"] >= 0).sum()
print(f"age_days >= 0: {age_valid} findings")

print(f"\nSaved → {OUTPUT_PATH}")