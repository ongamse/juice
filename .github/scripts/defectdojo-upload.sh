#!/bin/bash
set -e

DEFECTDOJO_URL="${DEFECTDOJO_URL}"
DEFECTDOJO_API_TOKEN="${DEFECTDOJO_API_TOKEN}"
PRODUCT_NAME="${PRODUCT_NAME:-OWASP Juice Shop}"
ENGAGEMENT_NAME="${ENGAGEMENT_NAME:- Security Scans}"
BUILD_ID="${BUILD_ID}"
COMMIT_HASH="${COMMIT_HASH}"
BRANCH_TAG="${BRANCH_TAG}"
SOURCE_CODE_MANAGEMENT_URI="${SOURCE_CODE_MANAGEMENT_URI}"

api_request() {
    local method=$1 endpoint=$2 data=$3
    curl -sf -X "${method}" "${DEFECTDOJO_URL}/api/v2/${endpoint}" \
        -H "Authorization: Token ${DEFECTDOJO_API_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "${data}"
}

find_or_create_product() {
    local encoded=$(echo "${PRODUCT_NAME}" | jq -sRr @uri)
    local response=$(api_request "GET" "products/?name=${encoded}" "")
    local count=$(echo "${response}" | jq -r '.count // 0')

    if [ "$count" -gt 0 ]; then
        echo "${response}" | jq -r '.results[0].id'
    else
        local data=$(jq -n --arg name "${PRODUCT_NAME}" '{name: $name, description: $name, prod_type: 1}')
        local response=$(api_request "POST" "products/" "${data}")
        local id=$(echo "${response}" | jq -r '.id')
        [ -n "$id" ] && [ "$id" != "null" ] || { echo "Failed to create product" >&2; exit 1; }
        echo "${id}"
    fi
}

find_or_create_engagement() {
    local product_id=$1
    local today=$(date +%Y-%m-%d)

    # Search for an existing engagement with the same name in this product
    local encoded_name=$(echo "${ENGAGEMENT_NAME}" | jq -sRr @uri)
    local response=$(api_request "GET" "engagements/?product=${product_id}&name=${encoded_name}" "")
    local count=$(echo "${response}" | jq -r '.count // 0')

    if [ "$count" -gt 0 ]; then
        local id=$(echo "${response}" | jq -r '.results[0].id')
        echo "Reusing existing engagement ${id}" >&2

        # Update the engagement with latest metadata
        local patch_data=$(jq -n \
            --arg date "${today}" --arg build "${BUILD_ID}" \
            --arg commit "${COMMIT_HASH}" --arg branch "${BRANCH_TAG}" \
            --arg uri "${SOURCE_CODE_MANAGEMENT_URI}" \
            '{target_end:$date, status:"In Progress",
              build_id:$build, commit_hash:$commit, branch_tag:$branch,
              source_code_management_uri:$uri}')
        api_request "PATCH" "engagements/${id}/" "${patch_data}" > /dev/null || true

        echo "${id}"
    else
        local data=$(jq -n \
            --arg name "${ENGAGEMENT_NAME}" --arg product "${product_id}" \
            --arg date "${today}" --arg build "${BUILD_ID}" \
            --arg commit "${COMMIT_HASH}" --arg branch "${BRANCH_TAG}" \
            --arg uri "${SOURCE_CODE_MANAGEMENT_URI}" \
            '{name:$name, product:($product|tonumber), engagement_type:"CI/CD",
              target_start:$date, target_end:$date, status:"In Progress",
              build_id:$build, commit_hash:$commit, branch_tag:$branch,
              source_code_management_uri:$uri,
              deduplication_on_engagement:true}')

        local response=$(api_request "POST" "engagements/" "${data}")
        local id=$(echo "${response}" | jq -r '.id')
        [ -n "$id" ] && [ "$id" != "null" ] || { echo "Failed to create engagement" >&2; exit 1; }
        echo "Created new engagement ${id}" >&2
        echo "${id}"
    fi
}

upload_scan() {
    local engagement_id=$1 scan_file=$2 scan_type=$3
    [ -f "${scan_file}" ] || return 0

    local scan_date
    scan_date=$(date +%Y-%m-%d)

    # Try reimport first (updates existing test), fall back to import (creates new test)
    echo "Reimporting ${scan_type}: ${scan_file}"
    if ! curl -sf -X POST "${DEFECTDOJO_URL}/api/v2/reimport-scan/" \
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
        -F "do_not_reactivate=false" > /dev/null 2>&1; then

        echo "  Reimport failed, importing as new scan..."
        curl -sf -X POST "${DEFECTDOJO_URL}/api/v2/import-scan/" \
            -H "Authorization: Token ${DEFECTDOJO_API_TOKEN}" \
            -F "scan_type=${scan_type}" \
            -F "file=@${scan_file}" \
            -F "engagement=${engagement_id}" \
            -F "minimum_severity=Info" \
            -F "active=true" \
            -F "verified=false" \
            -F "scan_date=${scan_date}" \
            -F "close_old_findings=true" \
            -F "close_old_findings_product_scope=false" > /dev/null || echo "  Warning: failed to import ${scan_type}"
    fi
}

main() {
    if [ -z "$DEFECTDOJO_URL" ] || [ -z "$DEFECTDOJO_API_TOKEN" ]; then
        echo "DefectDojo credentials not configured, skipping upload."
        exit 0
    fi

    PRODUCT_ID=$(find_or_create_product)
    ENGAGEMENT_ID=$(find_or_create_engagement "$PRODUCT_ID")

    upload_scan "$ENGAGEMENT_ID" "semgrep-results.json"          "Semgrep JSON Report"
    upload_scan "$ENGAGEMENT_ID" "trivy-fs-results.json"         "Trivy Scan"
    upload_scan "$ENGAGEMENT_ID" "trivy-image-results.json"      "Trivy Scan"
    upload_scan "$ENGAGEMENT_ID" "report_xml.xml"                "ZAP Scan"
    upload_scan "$ENGAGEMENT_ID" "dependency-check-report.xml"   "Dependency Check Scan"

    api_request "PATCH" "engagements/${ENGAGEMENT_ID}/" '{"status":"Completed"}' > /dev/null || true

    echo "Done. View results at: ${DEFECTDOJO_URL}/engagement/${ENGAGEMENT_ID}"
}

main
