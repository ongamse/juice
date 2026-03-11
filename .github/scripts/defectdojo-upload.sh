#!/bin/bash

DEFECTDOJO_URL="${DEFECTDOJO_URL}"
DEFECTDOJO_API_TOKEN="${DEFECTDOJO_API_TOKEN}"
PRODUCT_NAME="${PRODUCT_NAME:-OWASP Juice Shop}"
ENGAGEMENT_NAME="${ENGAGEMENT_NAME:-CI/CD Security Scans}"
BUILD_ID="${BUILD_ID}"
COMMIT_HASH="${COMMIT_HASH}"
BRANCH_TAG="${BRANCH_TAG}"
SOURCE_CODE_MANAGEMENT_URI="${SOURCE_CODE_MANAGEMENT_URI}"

UPLOAD_FAILURES=0

# ---------------------------------------------------------------------------
# api_request: JSON-based API helper (GET/POST/PATCH).
# NOTE: This helper is intentionally JSON-only. upload_scan uses raw curl
# directly because multipart/form-data (required by the import endpoints)
# cannot be expressed through a generic JSON wrapper.
# ---------------------------------------------------------------------------
api_request() {
    local method=$1 endpoint=$2 data=$3
    local response http_code body

    response=$(curl -s -w "\n%{http_code}" -X "${method}" \
        "${DEFECTDOJO_URL}/api/v2/${endpoint}" \
        -H "Authorization: Token ${DEFECTDOJO_API_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "${data}")
    http_code=$(echo "${response}" | tail -1)
    body=$(echo "${response}" | sed '$d')

    if [ "${http_code}" -ge 200 ] && [ "${http_code}" -lt 300 ] 2>/dev/null; then
        echo "${body}"
        return 0
    else
        echo "API ${method} ${endpoint} failed (HTTP ${http_code}): ${body}" >&2
        return 1
    fi
}

find_or_create_product() {
    local encoded
    # jq -sRr @uri is used here for percent-encoding the product name so it is
    # safe to embed in a query string. It reads stdin as a raw string (-R),
    # slurps it into one value (-s), and applies the @uri format filter.
    encoded=$(echo "${PRODUCT_NAME}" | jq -sRr @uri)
    local response count

    response=$(api_request "GET" "products/?name=${encoded}" "") || {
        echo "Failed to query products" >&2
        exit 1
    }
    count=$(echo "${response}" | jq -r '.count // 0')

    if [ "$count" -gt 0 ]; then
        echo "${response}" | jq -r '.results[0].id'
    else
        local data id
        data=$(jq -n --arg name "${PRODUCT_NAME}" \
            '{name: $name, description: $name, prod_type: 1}')
        response=$(api_request "POST" "products/" "${data}") || {
            echo "Failed to create product" >&2
            exit 1
        }
        id=$(echo "${response}" | jq -r '.id')
        [ -n "$id" ] && [ "$id" != "null" ] || {
            echo "Failed to create product (no id in response)" >&2
            exit 1
        }
        echo "${id}"
    fi
}

find_or_create_engagement() {
    local product_id=$1
    local today
    today=$(date +%Y-%m-%d)

    local encoded_name
    encoded_name=$(echo "${ENGAGEMENT_NAME}" | jq -sRr @uri)
    local response count

    response=$(api_request "GET" "engagements/?product=${product_id}&name=${encoded_name}" "") || {
        echo "Failed to query engagements" >&2
        exit 1
    }
    count=$(echo "${response}" | jq -r '.count // 0')

    if [ "$count" -gt 0 ]; then
        local id patch_data
        id=$(echo "${response}" | jq -r '.results[0].id')
        echo "Reusing existing engagement ${id}" >&2

        patch_data=$(jq -n \
            --arg date "${today}" --arg build "${BUILD_ID}" \
            --arg commit "${COMMIT_HASH}" --arg branch "${BRANCH_TAG}" \
            --arg uri "${SOURCE_CODE_MANAGEMENT_URI}" \
            '{target_end:$date, status:"In Progress",
              build_id:$build, commit_hash:$commit, branch_tag:$branch,
              source_code_management_uri:$uri}')
        api_request "PATCH" "engagements/${id}/" "${patch_data}" > /dev/null 2>&1 || true

        echo "${id}"
    else
        local data id
        data=$(jq -n \
            --arg name "${ENGAGEMENT_NAME}" --arg product "${product_id}" \
            --arg date "${today}" --arg build "${BUILD_ID}" \
            --arg commit "${COMMIT_HASH}" --arg branch "${BRANCH_TAG}" \
            --arg uri "${SOURCE_CODE_MANAGEMENT_URI}" \
            '{name:$name, product:($product|tonumber), engagement_type:"CI/CD",
              target_start:$date, target_end:$date, status:"In Progress",
              build_id:$build, commit_hash:$commit, branch_tag:$branch,
              source_code_management_uri:$uri,
              deduplication_on_engagement:true}')

        response=$(api_request "POST" "engagements/" "${data}") || {
            echo "Failed to create engagement" >&2
            exit 1
        }
        id=$(echo "${response}" | jq -r '.id')
        [ -n "$id" ] && [ "$id" != "null" ] || {
            echo "Failed to create engagement (no id in response)" >&2
            exit 1
        }
        echo "Created new engagement ${id}" >&2
        echo "${id}"
    fi
}

# ---------------------------------------------------------------------------
# upload_scan: uploads a scan file via multipart/form-data.
# Uses raw curl (not api_request) because the import endpoints require
# multipart form fields rather than a JSON body.
# Tries reimport first (updates an existing test) and falls back to import
# (creates a new test). Both failures increment UPLOAD_FAILURES so the
# caller can decide whether to fail the pipeline.
# ---------------------------------------------------------------------------
upload_scan() {
    local engagement_id=$1 scan_file=$2 scan_type=$3

    if [ ! -f "${scan_file}" ]; then
        echo "  Skipping ${scan_type}: file '${scan_file}' not found"
        return 0
    fi

    local file_size
    file_size=$(wc -c < "${scan_file}" | tr -d ' ')
    echo "Uploading ${scan_type}: ${scan_file} (${file_size} bytes)"

    if [ "${file_size}" -eq 0 ]; then
        echo "  Skipping ${scan_type}: file is empty"
        return 0
    fi

    local scan_date response http_code body
    scan_date=$(date +%Y-%m-%d)

    # Try reimport first (updates existing test, avoids duplicate test entries).
    # test_type lets DefectDojo locate the existing test within the engagement.
    # auto_create_context=true means on first run it creates the test itself,
    # so we should never need to fall back to the import endpoint at all.
    response=$(curl -s -w "\n%{http_code}" -X POST \
        "${DEFECTDOJO_URL}/api/v2/reimport-scan/" \
        -H "Authorization: Token ${DEFECTDOJO_API_TOKEN}" \
        -F "scan_type=${scan_type}" \
        -F "test_type=${scan_type}" \
        -F "file=@${scan_file}" \
        -F "engagement=${engagement_id}" \
        -F "minimum_severity=Info" \
        -F "active=true" \
        -F "verified=false" \
        -F "scan_date=${scan_date}" \
        -F "close_old_findings=true" \
        -F "close_old_findings_product_scope=false" \
        -F "do_not_reactivate=false" \
        -F "auto_create_context=true")
    http_code=$(echo "${response}" | tail -1)
    body=$(echo "${response}" | sed '$d')

    if [ "${http_code}" -ge 200 ] && [ "${http_code}" -lt 300 ] 2>/dev/null; then
        echo "  Reimport successful (HTTP ${http_code})"
        return 0
    fi

    echo "  Reimport failed (HTTP ${http_code}), trying import..." >&2
    [ -n "${body}" ] && echo "  Reimport response: ${body}" >&2

    # Fall back to import (creates a new test for this scan type)
    response=$(curl -s -w "\n%{http_code}" -X POST \
        "${DEFECTDOJO_URL}/api/v2/import-scan/" \
        -H "Authorization: Token ${DEFECTDOJO_API_TOKEN}" \
        -F "scan_type=${scan_type}" \
        -F "file=@${scan_file}" \
        -F "engagement=${engagement_id}" \
        -F "minimum_severity=Info" \
        -F "active=true" \
        -F "verified=false" \
        -F "scan_date=${scan_date}" \
        -F "close_old_findings=true" \
        -F "close_old_findings_product_scope=false")
    http_code=$(echo "${response}" | tail -1)
    body=$(echo "${response}" | sed '$d')

    if [ "${http_code}" -ge 200 ] && [ "${http_code}" -lt 300 ] 2>/dev/null; then
        echo "  Import successful (HTTP ${http_code})"
        return 0
    fi

    echo "  ERROR: Import also failed (HTTP ${http_code})" >&2
    echo "  Response: ${body}" >&2
    UPLOAD_FAILURES=$((UPLOAD_FAILURES + 1))
    return 1
}

main() {
    # ---------------------------------------------------------------------------
    # Guard: missing credentials are treated as a hard misconfiguration error
    # (exit 1) rather than a silent skip (exit 0), so CI pipelines catch it.
    # If you intentionally want to skip DefectDojo in some environments, set
    # DEFECTDOJO_SKIP=true before running this script.
    # ---------------------------------------------------------------------------
    if [ -z "$DEFECTDOJO_URL" ] || [ -z "$DEFECTDOJO_API_TOKEN" ]; then
        if [ "${DEFECTDOJO_SKIP:-false}" = "true" ]; then
            echo "DEFECTDOJO_SKIP=true — skipping DefectDojo upload."
            exit 0
        fi
        echo "ERROR: DEFECTDOJO_URL and DEFECTDOJO_API_TOKEN must be set." >&2
        echo "       To intentionally skip upload, set DEFECTDOJO_SKIP=true." >&2
        exit 1
    fi

    # Mask the token in any debug output. If set -x is active in a parent
    # shell, the token would be visible in expanded curl commands. Unsetting
    # here won't help in that case, but at least our own echo statements are
    # safe and serve as a reminder to avoid logging full curl invocations.
    : "DEFECTDOJO_API_TOKEN is set but intentionally not echoed to avoid leaking secrets"

    echo "DefectDojo URL: ${DEFECTDOJO_URL}"
    echo "Product:        ${PRODUCT_NAME}"
    echo "Engagement:     ${ENGAGEMENT_NAME}"
    echo ""

    echo "Available scan files:"
    for f in semgrep-results.json trivy-fs-results.json trivy-image-results.json report_xml.xml dependency-check-report.xml; do
        if [ -f "$f" ]; then
            echo "  [found]   $f ($(wc -c < "$f" | tr -d ' ') bytes)"
        else
            echo "  [missing] $f"
        fi
    done
    echo ""

    local PRODUCT_ID ENGAGEMENT_ID
    PRODUCT_ID=$(find_or_create_product) || exit 1
    echo "Product ID:    ${PRODUCT_ID}"
    ENGAGEMENT_ID=$(find_or_create_engagement "$PRODUCT_ID") || exit 1
    echo "Engagement ID: ${ENGAGEMENT_ID}"
    echo ""

    # Each upload_scan call tracks its own failure via UPLOAD_FAILURES.
    # We do NOT use `|| true` here so that a non-zero return propagates
    # the failure count correctly while still allowing subsequent scans
    # to be attempted. The final exit code is based on UPLOAD_FAILURES.
    upload_scan "$ENGAGEMENT_ID" "semgrep-results.json"        "Semgrep JSON Report"
    upload_scan "$ENGAGEMENT_ID" "trivy-fs-results.json"       "Trivy Scan"
    upload_scan "$ENGAGEMENT_ID" "trivy-image-results.json"    "Trivy Scan"
    upload_scan "$ENGAGEMENT_ID" "report_xml.xml"              "ZAP Scan"
    upload_scan "$ENGAGEMENT_ID" "dependency-check-report.xml" "Dependency Check Scan"

    echo ""
    api_request "PATCH" "engagements/${ENGAGEMENT_ID}/" '{"status":"Completed"}' > /dev/null 2>&1 || true

    if [ "${UPLOAD_FAILURES}" -gt 0 ]; then
        echo "Done with ${UPLOAD_FAILURES} upload failure(s)." >&2
        echo "View results at: ${DEFECTDOJO_URL}/engagement/${ENGAGEMENT_ID}"
        exit 1
    fi

    echo "Done. View results at: ${DEFECTDOJO_URL}/engagement/${ENGAGEMENT_ID}"
}

main