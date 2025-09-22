#!/bin/bash

# Script to demonstrate vulnerability scanner dependence on package metadata
# Removes packages from dpkg status while leaving binaries intact
# Use --fix-it flag to perform metadata manipulation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ORIGINAL_IMAGE="python:3.12@sha256:1cb6108b64a4caf2a862499bf90dc65703a08101e8bfb346a18c9d12c0ed5b7e"
CLEANED_IMAGE="python:3.12-cleaned"
PERFORM_MANIPULATION=false

# Show help information
show_help() {
    cat << EOF
Vulnerability Scanner Metadata Dependence Demonstration

Usage: $0 [OPTIONS]

OPTIONS:
    --fix-it         Perform metadata manipulation to demonstrate scanner evasion
                    (Without this flag, only scans the original image)
    -h, --help       Show this help message

EXAMPLES:
    $0               # Only scan original image and show baseline results
    $0 --fix-it      # Perform manipulation and show before/after comparison

WARNING: This script is for security research and educational purposes only.
The --fix-it flag demonstrates how package metadata manipulation can evade
vulnerability scanners, which could be misused by malicious actors.

EOF
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --fix-it)
                PERFORM_MANIPULATION=true
                echo -e "${YELLOW}Metadata manipulation enabled${NC}"
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                show_help
                exit 1
                ;;
        esac
    done
}

# Function to print section headers
print_section() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

# Function to truncate image name for display
truncate_image_name() {
    local full_name="$1"
    if [[ "$full_name" =~ @sha256:([a-f0-9]{5}) ]]; then
        # Extract the base name and first 5 chars of digest
        local base_name="${full_name%@sha256:*}"
        local short_digest="${BASH_REMATCH[1]}"
        echo "${base_name}@sha256:${short_digest}..."
    else
        echo "$full_name"
    fi
}

# Parse command line arguments first
parse_arguments "$@"

echo -e "${BLUE}=== DPKG Metadata Analysis Demo ===${NC}"
if [[ "$PERFORM_MANIPULATION" == true ]]; then
    echo -e "${YELLOW}Mode: Metadata manipulation demonstration (--fix-it enabled)${NC}"
    echo -e "${YELLOW}Target: ImageMagick (CRITICAL CVE-2025-57807), Python, Curl, Expat, linux-libc-dev packages${NC}"
else
    echo -e "${YELLOW}Mode: Baseline scan only (use --fix-it to enable manipulation)${NC}"
    echo -e "${YELLOW}Scanning: $ORIGINAL_IMAGE${NC}"
fi
echo

# Step 1: Scan original image (always performed)
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

# Get truncated image name for display
ORIG_DISPLAY=$(truncate_image_name "$ORIGINAL_IMAGE")

if [[ "$PERFORM_MANIPULATION" == false ]]; then
    # Show baseline results only
    print_section "Baseline Vulnerability Scan Results"
    echo
    echo -e "${BLUE}=== Original Image Vulnerability Scan ===${NC}"
    echo "┌─────────────────────────────────┬─────────────┬──────┬────────┬─────┬───────┐"
    echo "│ Image                           │ Scanner     │ Crit │ High   │ Med │ Low   │"
    echo "├─────────────────────────────────┼─────────────┼──────┼────────┼─────┼───────┤"
    printf "│ %-31s │ %-11s │ %-4s │ %-6s │ %-3s │ %-5s │\n" "$ORIG_DISPLAY" "Grype" "$GRYPE_ORIG_CRITICAL" "$GRYPE_ORIG_HIGH" "$GRYPE_ORIG_MEDIUM" "$GRYPE_ORIG_LOW"
    printf "│ %-31s │ %-11s │ %-4s │ %-6s │ %-3s │ %-5s │\n" "" "Trivy" "$TRIVY_ORIG_CRITICAL" "$TRIVY_ORIG_HIGH" "$TRIVY_ORIG_MEDIUM" "$TRIVY_ORIG_LOW"
    echo "└─────────────────────────────────┴─────────────┴──────┴────────┴─────┴───────┘"
    echo
    echo -e "${GREEN}Baseline scan completed.${NC}"
    echo -e "${YELLOW}Use --fix-it flag to demonstrate metadata manipulation evasion techniques.${NC}"
    exit 0
fi

# Continue with manipulation if --fix-it flag is provided
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

# Remove Bluetooth packages (HIGH severity CVE-2023-44431, CVE-2023-51596)
sed -i "/^Package: libbluetooth-dev$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: libbluetooth3$/,/^$/d" /var/lib/dpkg/status

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

# Remove XSLT packages (HIGH severity CVE-2025-7425)
sed -i "/^Package: libxslt1-dev$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: libxslt1\.1$/,/^$/d" /var/lib/dpkg/status

# Remove linux-libc-dev package (HIGH severity CVE-2013-7445)
sed -i "/^Package: linux-libc-dev$/,/^$/d" /var/lib/dpkg/status

echo "Removed CRITICAL and HIGH severity CVE packages from dpkg metadata"

# Now rename the actual binaries to evade binary-level detection
echo "Renaming vulnerable binaries to evade binary analysis..."

# First, find and remove any symlinks to python
find /usr -name "*python*" -type l -exec rm -f {} \; 2>/dev/null || true
find /usr/local -name "*python*" -type l -exec rm -f {} \; 2>/dev/null || true

# Rename python binaries
if [ -f /usr/local/bin/python ]; then
    mv /usr/local/bin/python /usr/local/bin/PyInterpreter
    echo "Renamed python -> PyInterpreter"
fi

if [ -f /usr/local/bin/python3 ]; then
    mv /usr/local/bin/python3 /usr/local/bin/PyInterpreter3
    echo "Renamed python3 -> PyInterpreter3"
fi

if [ -f /usr/local/bin/python3.12 ]; then
    mv /usr/local/bin/python3.12 /usr/local/bin/PyInterpreter3.12
    echo "Renamed python3.12 -> PyInterpreter3.12"
fi

if [ -f /usr/local/bin/python3.13 ]; then
    mv /usr/local/bin/python3.13 /usr/local/bin/PyInterpreter3.13
    echo "Renamed python3.13 -> PyInterpreter3.13"
fi

# Also check system paths
if [ -f /usr/bin/python ]; then
    mv /usr/bin/python /usr/bin/PyInterpreter
    echo "Renamed system python -> PyInterpreter"
fi

if [ -f /usr/bin/python3 ]; then
    mv /usr/bin/python3 /usr/bin/PyInterpreter3
    echo "Renamed system python3 -> PyInterpreter3"
fi

# Find and rename any other python binaries
find /usr -name "*python*" -type f -executable 2>/dev/null | while read pyfile; do
    if [ -f "$pyfile" ]; then
        newname=$(echo "$pyfile" | sed "s/python/PyInterpreter/g")
        if [ "$pyfile" != "$newname" ]; then
            mv "$pyfile" "$newname" 2>/dev/null && echo "Renamed $pyfile -> $newname"
        fi
    fi
done

# Rename curl binary and remove symlinks
find /usr -name "*curl*" -type l -exec rm -f {} \; 2>/dev/null || true

if [ -f /usr/bin/curl ]; then
    mv /usr/bin/curl /usr/bin/WebClient
    echo "Renamed curl -> WebClient"
fi

# Find and rename any other curl binaries
find /usr -name "*curl*" -type f -executable 2>/dev/null | while read curlfile; do
    if [ -f "$curlfile" ]; then
        newname=$(echo "$curlfile" | sed "s/curl/WebClient/g")
        if [ "$curlfile" != "$newname" ]; then
            mv "$curlfile" "$newname" 2>/dev/null && echo "Renamed $curlfile -> $newname"
        fi
    fi
done

echo "Binary renaming completed - all python/curl references should be eliminated"
'

echo "Verifying removal..."
docker exec "$CONTAINER_ID" sh -c 'echo "ImageMagick packages found:"; grep -c "^Package: imagemagick\|^Package: libmagick" /var/lib/dpkg/status || echo "0"'
docker exec "$CONTAINER_ID" sh -c 'echo "Python 3.13 packages found:"; grep -c "^Package: python3\.13\|^Package: libpython3\.13" /var/lib/dpkg/status || echo "0"'
docker exec "$CONTAINER_ID" sh -c 'echo "Curl packages found:"; grep -c "^Package: curl\|^Package: libcurl" /var/lib/dpkg/status || echo "0"'
docker exec "$CONTAINER_ID" sh -c 'echo "Expat packages found:"; grep -c "^Package: libexpat1" /var/lib/dpkg/status || echo "0"'
docker exec "$CONTAINER_ID" sh -c 'echo "linux-libc-dev packages found:"; grep -c "^Package: linux-libc-dev" /var/lib/dpkg/status || echo "0"'

echo "Committing cleaned image..."
docker commit "$CONTAINER_ID" "$CLEANED_IMAGE" >/dev/null
docker stop "$CONTAINER_ID" >/dev/null
docker rm "$CONTAINER_ID" >/dev/null

echo -e "${GREEN}Metadata-cleaned image created${NC}"

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

CLEAN_DISPLAY="$CLEANED_IMAGE"

# Display results table
echo
echo -e "${BLUE}=== Vulnerability Scan Results ===${NC}"
echo "┌─────────────────────────────────┬─────────────┬──────┬────────┬─────┬───────┐"
echo "│ Image                           │ Scanner     │ Crit │ High   │ Med │ Low   │"
echo "├─────────────────────────────────┼─────────────┼──────┼────────┼─────┼───────┤"
printf "│ %-31s │ %-11s │ %-4s │ %-6s │ %-3s │ %-5s │\n" "$ORIG_DISPLAY" "Grype" "$GRYPE_ORIG_CRITICAL" "$GRYPE_ORIG_HIGH" "$GRYPE_ORIG_MEDIUM" "$GRYPE_ORIG_LOW"
printf "│ %-31s │ %-11s │ %-4s │ %-6s │ %-3s │ %-5s │\n" "" "Trivy" "$TRIVY_ORIG_CRITICAL" "$TRIVY_ORIG_HIGH" "$TRIVY_ORIG_MEDIUM" "$TRIVY_ORIG_LOW"
echo "├─────────────────────────────────┼─────────────┼──────┼────────┼─────┼───────┤"
printf "│ %-31s │ %-11s │ %-4s │ %-6s │ %-3s │ %-5s │\n" "$CLEAN_DISPLAY" "Grype" "$GRYPE_CLEAN_CRITICAL" "$GRYPE_CLEAN_HIGH" "$GRYPE_CLEAN_MEDIUM" "$GRYPE_CLEAN_LOW"
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
echo "• Dual-layer evasion: Removed package metadata AND renamed vulnerable binaries"
echo "• CRITICAL CVE-2025-57807 in ImageMagick now invisible to both scanners"
echo "• HIGH CVE-2025-8194 in Python/curl and CVE-2013-7445 in linux-libc-dev now evade detection"
echo "• Same vulnerable code execution paths remain functional under new names"
echo
echo -e "${YELLOW}Attack Sophistication:${NC}"
echo "• Layer 1: Package metadata manipulation (removes deb-type detections)"
echo "• Layer 2: Binary renaming (evades binary-type detections)"
echo "• Result: Complete evasion of multiple scanner detection methods"
echo "• Vulnerable binaries accessible as PyInterpreter, PyInterpreter3, WebClient instead of python, python3, curl"
echo "• Attack maintains full functionality while achieving maximum stealth"
echo
echo -e "${YELLOW}Security Impact:${NC}"
echo "• Demonstrates sophisticated multi-vector vulnerability hiding techniques"
echo "• Shows scanner dependency on both metadata AND filename patterns"
echo "• CRITICAL and HIGH severity vulnerabilities completely hidden from detection"
echo "• Both major scanners (Grype & Trivy) defeated by combined approach"
echo "• Attackers could hide life-critical vulnerabilities from enterprise security tools"
echo "• Organizations might achieve 'clean' compliance scans while remaining highly vulnerable"
echo
echo -e "${GREEN}Demo completed!${NC}"
echo "Cleanup: docker rmi $CLEANED_IMAGE"
