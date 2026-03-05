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

api_request() {
    local method=$1 endpoint=$2 data=$3
    local response http_code
    response=$(curl -s -w "\n%{http_code}" -X "${method}" \
        "${DEFECTDOJO_URL}/api/v2/${endpoint}" \
        -H "Authorization: Token ${DEFECTDOJO_API_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "${data}")
    http_code=$(echo "${response}" | tail -1)
    local body
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
    encoded=$(echo "${PRODUCT_NAME}" | jq -sRr @uri)
    local response
    response=$(api_request "GET" "products/?name=${encoded}" "") || { echo "Failed to query products" >&2; exit 1; }
    local count
    count=$(echo "${response}" | jq -r '.count // 0')

    if [ "$count" -gt 0 ]; then
        echo "${response}" | jq -r '.results[0].id'
    else
        local data
        data=$(jq -n --arg name "${PRODUCT_NAME}" '{name: $name, description: $name, prod_type: 1}')
        response=$(api_request "POST" "products/" "${data}") || { echo "Failed to create product" >&2; exit 1; }
        local id
        id=$(echo "${response}" | jq -r '.id')
        [ -n "$id" ] && [ "$id" != "null" ] || { echo "Failed to create product" >&2; exit 1; }
        echo "${id}"
    fi
}

find_or_create_engagement() {
    local product_id=$1
    local today
    today=$(date +%Y-%m-%d)

    local encoded_name
    encoded_name=$(echo "${ENGAGEMENT_NAME}" | jq -sRr @uri)
    local response
    response=$(api_request "GET" "engagements/?product=${product_id}&name=${encoded_name}" "") || { echo "Failed to query engagements" >&2; exit 1; }
    local count
    count=$(echo "${response}" | jq -r '.count // 0')

    if [ "$count" -gt 0 ]; then
        local id
        id=$(echo "${response}" | jq -r '.results[0].id')
        echo "Reusing existing engagement ${id}" >&2

        local patch_data
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
        local data
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

        response=$(api_request "POST" "engagements/" "${data}") || { echo "Failed to create engagement" >&2; exit 1; }
        local id
        id=$(echo "${response}" | jq -r '.id')
        [ -n "$id" ] && [ "$id" != "null" ] || { echo "Failed to create engagement" >&2; exit 1; }
        echo "Created new engagement ${id}" >&2
        echo "${id}"
    fi
}

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

    # Try reimport first (updates existing test)
    response=$(curl -s -w "\n%{http_code}" -X POST \
        "${DEFECTDOJO_URL}/api/v2/reimport-scan/" \
        -H "Authorization: Token ${DEFECTDOJO_API_TOKEN}" \
        -F "scan_type=${scan_type}" \
        -F "file=@${scan_file}" \
        -F "engagement=${engagement_id}" \
        -F "minimum_severity=Info" \
        -F "active=true" \
        -F "verified=false" \
        -F "scan_date=${scan_date}" \
        -F "close_old_findings=true" \
        -F "close_old_findings_product_scope=false" \
        -F "do_not_reactivate=false")
    http_code=$(echo "${response}" | tail -1)
    body=$(echo "${response}" | sed '$d')

    if [ "${http_code}" -ge 200 ] && [ "${http_code}" -lt 300 ] 2>/dev/null; then
        echo "  Reimport successful (HTTP ${http_code})"
        return 0
    fi

    echo "  Reimport failed (HTTP ${http_code}), trying import..."
    [ -n "${body}" ] && echo "  Reimport response: ${body}" >&2

    # Fall back to import (creates new test)
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
    if [ -z "$DEFECTDOJO_URL" ] || [ -z "$DEFECTDOJO_API_TOKEN" ]; then
        echo "DefectDojo credentials not configured, skipping upload."
        exit 0
    fi

    echo "DefectDojo URL: ${DEFECTDOJO_URL}"
    echo "Product: ${PRODUCT_NAME}"
    echo "Engagement: ${ENGAGEMENT_NAME}"
    echo ""

    # List available scan files
    echo "Available scan files:"
    for f in semgrep-results.json trivy-fs-results.json trivy-image-results.json report_xml.xml dependency-check-report.xml; do
        if [ -f "$f" ]; then
            echo "  [found] $f ($(wc -c < "$f" | tr -d ' ') bytes)"
        else
            echo "  [missing] $f"
        fi
    done
    echo ""

    PRODUCT_ID=$(find_or_create_product) || exit 1
    echo "Product ID: ${PRODUCT_ID}"
    ENGAGEMENT_ID=$(find_or_create_engagement "$PRODUCT_ID") || exit 1
    echo "Engagement ID: ${ENGAGEMENT_ID}"
    echo ""

    upload_scan "$ENGAGEMENT_ID" "semgrep-results.json"          "Semgrep JSON Report" || true
    upload_scan "$ENGAGEMENT_ID" "trivy-fs-results.json"         "Trivy Scan" || true
    upload_scan "$ENGAGEMENT_ID" "trivy-image-results.json"      "Trivy Scan" || true
    upload_scan "$ENGAGEMENT_ID" "report_xml.xml"                "ZAP Scan" || true
    upload_scan "$ENGAGEMENT_ID" "dependency-check-report.xml"   "Dependency Check Scan" || true

    echo ""
    api_request "PATCH" "engagements/${ENGAGEMENT_ID}/" '{"status":"Completed"}' > /dev/null 2>&1 || true

    if [ "${UPLOAD_FAILURES}" -gt 0 ]; then
        echo "Done with ${UPLOAD_FAILURES} upload failure(s). View results at: ${DEFECTDOJO_URL}/engagement/${ENGAGEMENT_ID}"
        exit 1
    fi

    echo "Done. View results at: ${DEFECTDOJO_URL}/engagement/${ENGAGEMENT_ID}"
}

main
