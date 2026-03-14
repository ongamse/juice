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
    # jq -sRr @uri: percent-encode for safe use in query strings.
    # -R reads stdin as raw string, -s slurps into one value, @uri applies percent-encoding.
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
# enrich_trivy_with_epss: Normalises GHSA→CVE IDs and injects EPSS scores
# (fetched from the FIRST.org API) into a Trivy JSON file in-place before
# upload.  Without CVE IDs, DefectDojo cannot resolve EPSS scores at all;
# without the pre-injected EPSS payload, scores only appear if DefectDojo's
# own background-enrichment task happens to run after import.
#
# Trivy often reports GHSA identifiers as the primary VulnerabilityID for
# npm/Go advisories.  The advisory's Aliases array typically carries the
# canonical CVE ID — we promote that to VulnerabilityID so DefectDojo
# stores the finding under a CVE it can actually look up.
#
# EPSS data is injected as:
#   "EPSS": [{"cve": "CVE-…", "epss": <float>, "percentile": <float>}]
# which matches the Trivy v0.50+ JSON schema that DefectDojo's Trivy parser
# already reads natively.
# ---------------------------------------------------------------------------
enrich_trivy_with_epss() {
    local input_file=$1

    if [ ! -f "${input_file}" ]; then
        return 0
    fi

    if ! command -v python3 &>/dev/null; then
        echo "  python3 not found — skipping EPSS enrichment for ${input_file}" >&2
        return 0
    fi

    local script_dir script_path
    script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
    script_path="${script_dir}/trivy-epss-enricher.py"

    if [ ! -f "${script_path}" ]; then
        echo "  EPSS helper script not found at ${script_path} — skipping ${input_file}" >&2
        return 0
    fi

    echo "  Enriching ${input_file} with EPSS scores..."

    python3 "${script_path}" "${input_file}" || {
        echo "  EPSS enrichment failed for ${input_file}" >&2
        return 0
    }
}

# ---------------------------------------------------------------------------
# upload_scan: uploads a scan file using ONLY the reimport-scan endpoint.
#
# The reimport endpoint handles everything:
#   - If a test matching engagement + scan_type + test_title already exists,
#     it updates that test in-place (true reimport, Reimports counter goes up).
#   - If no matching test exists, it creates one automatically.
#   - auto_create_context=true means it will also create the engagement or
#     product on the fly if needed (safety net).
#
# test_title is set to the scan filename. This is the critical field that
# separates tests with the same scan_type — e.g. "trivy-fs-results.json"
# and "trivy-image-results.json" are both "Trivy Scan" but have different
# titles, so DefectDojo keeps them as two distinct, stable test objects.
#
# We pass product_name and engagement_name (not IDs) so DefectDojo performs
# the test lookup by name context, which is what enables the title-based
# matching to work correctly.
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

    local scan_date test_title response http_code body
    scan_date=$(date +%Y-%m-%d)
    # Use the filename as a stable, unique title so DefectDojo can
    # distinguish tests that share the same scan_type (e.g. two Trivy scans).
    test_title=$(basename "${scan_file}")

    response=$(curl -s -w "\n%{http_code}" -X POST \
        "${DEFECTDOJO_URL}/api/v2/reimport-scan/" \
        -H "Authorization: Token ${DEFECTDOJO_API_TOKEN}" \
        -F "scan_type=${scan_type}" \
        -F "test_title=${test_title}" \
        -F "file=@${scan_file}" \
        -F "product_name=${PRODUCT_NAME}" \
        -F "engagement_name=${ENGAGEMENT_NAME}" \
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
        echo "  Upload successful (HTTP ${http_code})"
        return 0
    fi

    echo "  ERROR: Upload failed (HTTP ${http_code})" >&2
    echo "  Response: ${body}" >&2
    UPLOAD_FAILURES=$((UPLOAD_FAILURES + 1))
    return 1
}

main() {
    # ---------------------------------------------------------------------------
    # Guard: missing credentials are a hard error (exit 1) not a silent skip,
    # so CI pipelines catch misconfiguration immediately.
    # Set DEFECTDOJO_SKIP=true to intentionally bypass upload in some envs.
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

    # DEFECTDOJO_API_TOKEN is intentionally never echoed. If set -x is active
    # in a parent shell, the token will still appear in expanded curl commands —
    # ensure your CI runner masks the variable in its log output.
    : "token present, not logged"

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

    # Normalize GHSA IDs → CVE IDs and inject EPSS scores from FIRST.org into
    # Trivy JSON files before upload so DefectDojo can display EPSS data for
    # every finding without relying on its background-enrichment task.
    enrich_trivy_with_epss "trivy-fs-results.json"
    enrich_trivy_with_epss "trivy-image-results.json"

    # Each upload_scan call increments UPLOAD_FAILURES on error but does not
    # abort, so all scans are always attempted regardless of individual failures.
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