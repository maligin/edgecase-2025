#!/bin/bash

# Script to demonstrate vulnerability scanner dependence on package metadata
# Removes libc6 and libc-bin from dpkg status while leaving binaries intact

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ORIGINAL_IMAGE="python:3.12"
CLEANED_IMAGE="python:3.12-cleaned"

echo -e "${BLUE}=== DPKG Metadata Manipulation Demo ===${NC}"
echo -e "${YELLOW}Demonstrates how removing package metadata fools vulnerability scanners${NC}"
echo -e "${YELLOW}Target: ImageMagick (CRITICAL CVE-2025-57807), Python, Curl, Expat packages${NC}"
echo

# Function to print section headers
print_section() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

# Step 1: Scan original image
print_section "Step 1: Scanning Original Image"
echo "Scanning $ORIGINAL_IMAGE with Grype..."
GRYPE_ORIGINAL=$(grype "$ORIGINAL_IMAGE" --output json 2>/dev/null)

echo "Scanning $ORIGINAL_IMAGE with Trivy..."
TRIVY_ORIGINAL=$(trivy image "$ORIGINAL_IMAGE" --format json --quiet --scanners vuln --ignore-unfixed=false --exit-code 0 2>/dev/null)

# Parse Grype original results
GRYPE_ORIG_CRITICAL=$(echo "$GRYPE_ORIGINAL" | jq '.matches | map(select(.vulnerability.severity == "Critical")) | length' 2>/dev/null || echo "0")
GRYPE_ORIG_HIGH=$(echo "$GRYPE_ORIGINAL" | jq '.matches | map(select(.vulnerability.severity == "High")) | length' 2>/dev/null || echo "0") 
GRYPE_ORIG_MEDIUM=$(echo "$GRYPE_ORIGINAL" | jq '.matches | map(select(.vulnerability.severity == "Medium")) | length' 2>/dev/null || echo "0")
GRYPE_ORIG_LOW=$(echo "$GRYPE_ORIGINAL" | jq '.matches | map(select(.vulnerability.severity == "Low")) | length' 2>/dev/null || echo "0")
GRYPE_ORIG_TOTAL=$(echo "$GRYPE_ORIGINAL" | jq '.matches | length' 2>/dev/null || echo "0")

# Parse Trivy original results
TRIVY_ORIG_CRITICAL=$(echo "$TRIVY_ORIGINAL" | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' 2>/dev/null || echo "0")
TRIVY_ORIG_HIGH=$(echo "$TRIVY_ORIGINAL" | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' 2>/dev/null || echo "0")
TRIVY_ORIG_MEDIUM=$(echo "$TRIVY_ORIGINAL" | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM")] | length' 2>/dev/null || echo "0")
TRIVY_ORIG_LOW=$(echo "$TRIVY_ORIGINAL" | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "LOW")] | length' 2>/dev/null || echo "0")
TRIVY_ORIG_TOTAL=$(echo "$TRIVY_ORIGINAL" | jq '[.Results[]?.Vulnerabilities[]?] | length' 2>/dev/null || echo "0")

# Step 2: Manipulate metadata
print_section "Step 2: Manipulating Package Metadata"
echo "Starting container to modify dpkg status file..."

CONTAINER_ID=$(docker run -d "$ORIGINAL_IMAGE" sleep 60)
echo "Container: $CONTAINER_ID"

echo "Modifying /var/lib/dpkg/status file..."
docker exec "$CONTAINER_ID" sh -c '
# Remove packages with CRITICAL and HIGH severity CVEs
# Primary targets: ImageMagick packages (CRITICAL CVE-2025-57807)

# Remove all ImageMagick related packages (CRITICAL severity)
sed -i "/^Package: imagemagick$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: imagemagick-7-common$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: imagemagick-7\.q16$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: libmagickcore-7-arch-config$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: libmagickcore-7-headers$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: libmagickcore-7\.q16-10$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: libmagickcore-7\.q16-10-extra$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: libmagickcore-7\.q16-dev$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: libmagickcore-dev$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: libmagickwand-7-headers$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: libmagickwand-7\.q16-10$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: libmagickwand-7\.q16-dev$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: libmagickwand-dev$/,/^$/d" /var/lib/dpkg/status

# Remove Python 3.13 packages (HIGH severity CVE-2025-8194)
sed -i "/^Package: libpython3\.13-minimal$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: libpython3\.13-stdlib$/,/^$/d" /var/lib/dpkg/status  
sed -i "/^Package: python3\.13$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: python3\.13-minimal$/,/^$/d" /var/lib/dpkg/status

# Remove Curl packages (HIGH severity CVE-2025-9086)
sed -i "/^Package: curl$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: libcurl3t64-gnutls$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: libcurl4-openssl-dev$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: libcurl4t64$/,/^$/d" /var/lib/dpkg/status

# Remove Expat packages (HIGH severity CVE-2025-59375)
sed -i "/^Package: libexpat1$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: libexpat1-dev$/,/^$/d" /var/lib/dpkg/status

echo "Removed CRITICAL and HIGH severity CVE packages from dpkg metadata"
'

echo "Verifying removal..."
docker exec "$CONTAINER_ID" sh -c 'echo "ImageMagick packages found:"; grep -c "^Package: imagemagick\|^Package: libmagick" /var/lib/dpkg/status || echo "0"'
docker exec "$CONTAINER_ID" sh -c 'echo "Python 3.13 packages found:"; grep -c "^Package: python3\.13\|^Package: libpython3\.13" /var/lib/dpkg/status || echo "0"'
docker exec "$CONTAINER_ID" sh -c 'echo "Curl packages found:"; grep -c "^Package: curl\|^Package: libcurl" /var/lib/dpkg/status || echo "0"'
docker exec "$CONTAINER_ID" sh -c 'echo "Expat packages found:"; grep -c "^Package: libexpat1" /var/lib/dpkg/status || echo "0"'

echo "Committing cleaned image..."
docker commit "$CONTAINER_ID" "$CLEANED_IMAGE" >/dev/null
docker stop "$CONTAINER_ID" >/dev/null
docker rm "$CONTAINER_ID" >/dev/null

echo -e "${GREEN}✓ Metadata-cleaned image created${NC}"

# Step 3: Scan cleaned image
print_section "Step 3: Scanning Cleaned Image"
echo "Scanning $CLEANED_IMAGE with Grype..."
GRYPE_CLEANED=$(grype "$CLEANED_IMAGE" --output json 2>/dev/null)

echo "Scanning $CLEANED_IMAGE with Trivy..."
TRIVY_CLEANED=$(trivy image "$CLEANED_IMAGE" --format json --quiet --scanners vuln --ignore-unfixed=false --exit-code 0 2>/dev/null)

# Parse Grype cleaned results
GRYPE_CLEAN_CRITICAL=$(echo "$GRYPE_CLEANED" | jq '.matches | map(select(.vulnerability.severity == "Critical")) | length' 2>/dev/null || echo "0")
GRYPE_CLEAN_HIGH=$(echo "$GRYPE_CLEANED" | jq '.matches | map(select(.vulnerability.severity == "High")) | length' 2>/dev/null || echo "0")
GRYPE_CLEAN_MEDIUM=$(echo "$GRYPE_CLEANED" | jq '.matches | map(select(.vulnerability.severity == "Medium")) | length' 2>/dev/null || echo "0") 
GRYPE_CLEAN_LOW=$(echo "$GRYPE_CLEANED" | jq '.matches | map(select(.vulnerability.severity == "Low")) | length' 2>/dev/null || echo "0")
GRYPE_CLEAN_TOTAL=$(echo "$GRYPE_CLEANED" | jq '.matches | length' 2>/dev/null || echo "0")

# Parse Trivy cleaned results
TRIVY_CLEAN_CRITICAL=$(echo "$TRIVY_CLEANED" | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' 2>/dev/null || echo "0")
TRIVY_CLEAN_HIGH=$(echo "$TRIVY_CLEANED" | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' 2>/dev/null || echo "0")
TRIVY_CLEAN_MEDIUM=$(echo "$TRIVY_CLEANED" | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM")] | length' 2>/dev/null || echo "0")
TRIVY_CLEAN_LOW=$(echo "$TRIVY_CLEANED" | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "LOW")] | length' 2>/dev/null || echo "0")
TRIVY_CLEAN_TOTAL=$(echo "$TRIVY_CLEANED" | jq '[.Results[]?.Vulnerabilities[]?] | length' 2>/dev/null || echo "0")

# Step 4: Display results and analysis
print_section "Step 4: Results Comparison"

# Display results table
echo
echo -e "${BLUE}=== Vulnerability Scan Results ===${NC}"
echo "┌─────────────────────────────────┬─────────────┬──────┬────────┬─────┬───────┐"
echo "│ Image                           │ Scanner     │ Crit │ High   │ Med │ Low   │"
echo "├─────────────────────────────────┼─────────────┼──────┼────────┼─────┼───────┤"
printf "│ %-31s │ %-11s │ %-4s │ %-6s │ %-3s │ %-5s │\n" "$ORIGINAL_IMAGE" "Grype" "$GRYPE_ORIG_CRITICAL" "$GRYPE_ORIG_HIGH" "$GRYPE_ORIG_MEDIUM" "$GRYPE_ORIG_LOW"
printf "│ %-31s │ %-11s │ %-4s │ %-6s │ %-3s │ %-5s │\n" "" "Trivy" "$TRIVY_ORIG_CRITICAL" "$TRIVY_ORIG_HIGH" "$TRIVY_ORIG_MEDIUM" "$TRIVY_ORIG_LOW"
echo "├─────────────────────────────────┼─────────────┼──────┼────────┼─────┼───────┤"
printf "│ %-31s │ %-11s │ %-4s │ %-6s │ %-3s │ %-5s │\n" "$CLEANED_IMAGE" "Grype" "$GRYPE_CLEAN_CRITICAL" "$GRYPE_CLEAN_HIGH" "$GRYPE_CLEAN_MEDIUM" "$GRYPE_CLEAN_LOW"
printf "│ %-31s │ %-11s │ %-4s │ %-6s │ %-3s │ %-5s │\n" "" "Trivy" "$TRIVY_CLEAN_CRITICAL" "$TRIVY_CLEAN_HIGH" "$TRIVY_CLEAN_MEDIUM" "$TRIVY_CLEAN_LOW"
echo "└─────────────────────────────────┴─────────────┴──────┴────────┴─────┴───────┘"

# Calculate differences for both scanners
GRYPE_TOTAL_DIFF=$((GRYPE_ORIG_TOTAL - GRYPE_CLEAN_TOTAL))
GRYPE_CRITICAL_DIFF=$((GRYPE_ORIG_CRITICAL - GRYPE_CLEAN_CRITICAL))
GRYPE_HIGH_DIFF=$((GRYPE_ORIG_HIGH - GRYPE_CLEAN_HIGH))
TRIVY_TOTAL_DIFF=$((TRIVY_ORIG_TOTAL - TRIVY_CLEAN_TOTAL))
TRIVY_CRITICAL_DIFF=$((TRIVY_ORIG_CRITICAL - TRIVY_CLEAN_CRITICAL))
TRIVY_HIGH_DIFF=$((TRIVY_ORIG_HIGH - TRIVY_CLEAN_HIGH))

echo
echo -e "${RED}Key Findings:${NC}"
echo "• Grype: Removed $GRYPE_TOTAL_DIFF vulnerabilities, eliminated $GRYPE_CRITICAL_DIFF CRITICAL and $GRYPE_HIGH_DIFF HIGH severity"
echo "• Trivy: Removed $TRIVY_TOTAL_DIFF vulnerabilities, eliminated $TRIVY_CRITICAL_DIFF CRITICAL and $TRIVY_HIGH_DIFF HIGH severity"
echo "• CRITICAL CVE-2025-57807 in ImageMagick now invisible to both scanners"
echo "• Same vulnerable libraries and binaries remain on the system"
echo "• Neither scanner can detect vulnerabilities without package metadata"
echo
echo -e "${YELLOW}Security Impact:${NC}"
echo "• Demonstrates universal weakness in metadata-based vulnerability scanning"
echo "• CRITICAL severity vulnerabilities completely hidden from detection"
echo "• Both major scanners (Grype & Trivy) exhibit same fundamental limitation"
echo "• Attackers could hide life-critical vulnerabilities from multiple scanning tools"
echo "• Compliance scans using either tool might miss critical security flaws"
echo "• Organizations might believe they're secure while facing imminent threats"
echo
echo -e "${GREEN}Demo completed!${NC}"
echo "Cleanup: docker rmi $CLEANED_IMAGE"
