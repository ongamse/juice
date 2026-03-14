#!/usr/bin/env python3
"""
Query all findings for a DefectDojo engagement, fetch EPSS scores from
FIRST.org, and PATCH each finding with epss_score / epss_percentile.

This is the definitive EPSS enrichment step: it writes directly to
DefectDojo's database via the API rather than relying on parsers or
background tasks to read EPSS data from scan files.

Usage: defectdojo-epss-patch.py <defectdojo_url> <api_token> <engagement_id>
"""

import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

FIRST_EPSS_ENDPOINT = "https://api.first.org/data/v1/epss"
USER_AGENT = "defectdojo-upload/1.0"
EPSS_BATCH_SIZE = 100   # FIRST.org supports up to 100 CVEs per request
FINDINGS_PAGE_SIZE = 100
BATCH_SLEEP_SECONDS = 0.2


def dd_get(base_url: str, token: str, path: str) -> dict:
    url = f"{base_url}/api/v2/{path}"
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Token {token}", "User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def dd_patch(base_url: str, token: str, finding_id: int, payload: dict) -> None:
    url = f"{base_url}/api/v2/findings/{finding_id}/"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="PATCH",
        headers={
            "Authorization": f"Token {token}",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        resp.read()


def get_all_findings(base_url: str, token: str, engagement_id: str) -> list[dict]:
    findings: list[dict] = []
    offset = 0
    while True:
        params = urllib.parse.urlencode(
            {"engagement": engagement_id, "limit": FINDINGS_PAGE_SIZE, "offset": offset}
        )
        page = dd_get(base_url, token, f"findings/?{params}")
        findings.extend(page.get("results") or [])
        if not page.get("next"):
            break
        offset += FINDINGS_PAGE_SIZE
    return findings


def extract_cve_id(finding: dict) -> str | None:
    # 1. Top-level cve field (Trivy, some other parsers)
    cve = finding.get("cve")
    if isinstance(cve, str) and cve.upper().startswith("CVE-"):
        return cve.upper()

    # 2. vulnerability_ids list (DefectDojo 2.x schema)
    for vid_obj in finding.get("vulnerability_ids") or []:
        if not isinstance(vid_obj, dict):
            continue
        vid = vid_obj.get("vulnerability_id", "")
        if isinstance(vid, str) and vid.upper().startswith("CVE-"):
            return vid.upper()

    # 3. Regex scan on title — catches Dependency Check XML findings where the
    #    parser embeds the CVE in the title (e.g. "CVE-2021-44228 | log4j-core")
    #    and leaves finding.cve blank.
    title = finding.get("title") or ""
    match = _CVE_RE.search(title)
    if match:
        return match.group(0).upper()

    return None


def fetch_epss_scores(cve_ids: list[str]) -> dict[str, dict[str, float]]:
    epss_by_cve: dict[str, dict[str, float]] = {}

    for start in range(0, len(cve_ids), EPSS_BATCH_SIZE):
        batch = cve_ids[start : start + EPSS_BATCH_SIZE]
        query = urllib.parse.urlencode({"cve": ",".join(batch)})
        req = urllib.request.Request(
            f"{FIRST_EPSS_ENDPOINT}?{query}",
            headers={"User-Agent": USER_AGENT},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            print(
                f"  Warning: EPSS fetch failed for batch starting {batch[0]}: {exc}",
                file=sys.stderr,
            )
            if start + EPSS_BATCH_SIZE < len(cve_ids):
                time.sleep(BATCH_SLEEP_SECONDS)
            continue

        for item in payload.get("data") or []:
            cid = item.get("cve")
            if not isinstance(cid, str):
                continue
            try:
                epss_by_cve[cid] = {
                    "epss": float(item.get("epss", 0)),
                    "percentile": float(item.get("percentile", 0)),
                }
            except (TypeError, ValueError):
                pass

        if start + EPSS_BATCH_SIZE < len(cve_ids):
            time.sleep(BATCH_SLEEP_SECONDS)

    return epss_by_cve


def main() -> int:
    if len(sys.argv) != 4:
        print(
            "Usage: defectdojo-epss-patch.py <dd_url> <api_token> <engagement_id>",
            file=sys.stderr,
        )
        return 2

    base_url = sys.argv[1].rstrip("/")
    token = sys.argv[2]
    engagement_id = sys.argv[3]

    print(f"  Fetching findings for engagement {engagement_id}...")
    try:
        findings = get_all_findings(base_url, token, engagement_id)
    except (urllib.error.URLError, OSError) as exc:
        print(f"  Error fetching findings: {exc}", file=sys.stderr)
        return 1

    print(f"  Found {len(findings)} findings")

    # Map finding ID → CVE ID, skipping findings with no CVE
    finding_cve: dict[int, str] = {}
    for finding in findings:
        fid = finding.get("id")
        cve_id = extract_cve_id(finding)
        if isinstance(fid, int) and cve_id:
            finding_cve[fid] = cve_id

    if not finding_cve:
        print("  No CVE IDs in findings — skipping EPSS patching")
        return 0

    unique_cves = list(set(finding_cve.values()))
    print(f"  Fetching EPSS scores for {len(unique_cves)} unique CVEs...")
    epss_by_cve = fetch_epss_scores(unique_cves)
    print(f"  EPSS data retrieved for {len(epss_by_cve)}/{len(unique_cves)} CVEs")

    patched = skipped = errors = 0
    for finding_id, cve_id in finding_cve.items():
        info = epss_by_cve.get(cve_id)
        if not info:
            skipped += 1
            continue
        try:
            dd_patch(
                base_url,
                token,
                finding_id,
                {"epss_score": info["epss"], "epss_percentile": info["percentile"]},
            )
            patched += 1
        except (urllib.error.URLError, OSError) as exc:
            print(
                f"  Warning: failed to patch finding {finding_id} ({cve_id}): {exc}",
                file=sys.stderr,
            )
            errors += 1

    print(
        f"  EPSS patching complete: {patched} patched, "
        f"{skipped} skipped (no EPSS data), {errors} errors"
    )
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
