#!/usr/bin/env python3

import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

FIRST_EPSS_ENDPOINT = "https://api.first.org/data/v1/epss"
USER_AGENT = "defectdojo-upload/1.0"
BATCH_SIZE = 10
BATCH_SLEEP_SECONDS = 0.2


def normalize_vulnerabilities_and_collect_cves(data: dict) -> list[str]:
    cve_ids: list[str] = []
    seen: set[str] = set()

    for result in data.get("Results") or []:
        for vulnerability in result.get("Vulnerabilities") or []:
            vulnerability_id = vulnerability.get("VulnerabilityID", "")

            if isinstance(vulnerability_id, str) and vulnerability_id.startswith("GHSA-"):
                aliases = vulnerability.get("Aliases") or []
                cve_alias = next(
                    (
                        alias
                        for alias in aliases
                        if isinstance(alias, str) and alias.startswith("CVE-")
                    ),
                    None,
                )
                if cve_alias:
                    vulnerability["VulnerabilityID"] = cve_alias
                    vulnerability_id = cve_alias

            if (
                isinstance(vulnerability_id, str)
                and vulnerability_id.startswith("CVE-")
                and vulnerability_id not in seen
            ):
                seen.add(vulnerability_id)
                cve_ids.append(vulnerability_id)

    return cve_ids


def fetch_epss_scores(cve_ids: list[str]) -> dict[str, dict[str, float]]:
    epss_by_cve: dict[str, dict[str, float]] = {}

    for start in range(0, len(cve_ids), BATCH_SIZE):
        batch = cve_ids[start:start + BATCH_SIZE]
        query = urllib.parse.urlencode({"cve": ",".join(batch)})
        url = f"{FIRST_EPSS_ENDPOINT}?{query}"
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})

        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError) as exc:
            print(f"  Warning: EPSS fetch failed for batch {batch[0]}: {exc}", file=sys.stderr)
            if start + BATCH_SIZE < len(cve_ids):
                time.sleep(BATCH_SLEEP_SECONDS)
            continue

        for item in payload.get("data", []):
            cve_id = item.get("cve")
            if not isinstance(cve_id, str):
                continue

            try:
                epss = float(item.get("epss", 0))
            except (TypeError, ValueError):
                epss = 0.0

            try:
                percentile = float(item.get("percentile", 0))
            except (TypeError, ValueError):
                percentile = 0.0

            epss_by_cve[cve_id] = {
                "epss": epss,
                "percentile": percentile,
            }

        if start + BATCH_SIZE < len(cve_ids):
            time.sleep(BATCH_SLEEP_SECONDS)

    return epss_by_cve


def inject_epss_data(data: dict, epss_by_cve: dict[str, dict[str, float]]) -> int:
    enriched_count = 0

    for result in data.get("Results") or []:
        for vulnerability in result.get("Vulnerabilities") or []:
            vulnerability_id = vulnerability.get("VulnerabilityID", "")
            if not isinstance(vulnerability_id, str):
                continue

            epss_info = epss_by_cve.get(vulnerability_id)
            if not epss_info:
                continue

            vulnerability["EPSS"] = [
                {
                    "cve": vulnerability_id,
                    "epss": epss_info["epss"],
                    "percentile": epss_info["percentile"],
                }
            ]
            enriched_count += 1

    return enriched_count


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: trivy-epss-enricher.py <trivy-json-file>", file=sys.stderr)
        return 2

    input_path = Path(sys.argv[1])
    if not input_path.is_file():
        print(f"  File not found: {input_path}", file=sys.stderr)
        return 0

    try:
        with input_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"  Error: could not read JSON from {input_path}: {exc}", file=sys.stderr)
        return 1

    cve_ids = normalize_vulnerabilities_and_collect_cves(data)
    if not cve_ids:
        print(f"  EPSS enrichment skipped: no CVE IDs found in {input_path}")
        return 0

    epss_by_cve = fetch_epss_scores(cve_ids)
    enriched_count = inject_epss_data(data, epss_by_cve)

    try:
        with input_path.open("w", encoding="utf-8") as handle:
            json.dump(data, handle)
    except OSError as exc:
        print(f"  Error: could not write JSON to {input_path}: {exc}", file=sys.stderr)
        return 1

    print(
        f"  EPSS enrichment done: {enriched_count}/{len(cve_ids)} CVEs enriched in {input_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
