#!/bin/bash

# sigstore_supply_chain_demo.sh
# Simple demo: Enhanced image -> Sign -> Manipulate metadata -> Show cosign detects tampering

set -e

# Configuration
BASE_IMAGE="python:3.12@sha256:1cb6108b64a4caf2a862499bf90dc65703a08101e8bfb346a18c9d12c0ed5b7e"
REGISTRY="localhost:5000"
REPO_NAME="acme-corp"
ENHANCED_IMAGE="${REGISTRY}/${REPO_NAME}/python-enhanced"
TAMPERED_IMAGE="${REGISTRY}/${REPO_NAME}/python-enhanced-tampered"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo_header() {
    echo -e "\n${BLUE}=== $1 ===${NC}"
}

# Check prerequisites
check_prerequisites() {
    echo_header "Checking Prerequisites"
    command -v docker >/dev/null 2>&1 || { echo -e "${RED}docker required${NC}"; exit 1; }
    command -v cosign >/dev/null 2>&1 || { echo -e "${RED}cosign required${NC}"; exit 1; }
    command -v grype >/dev/null 2>&1 || { echo -e "${RED}grype required${NC}"; exit 1; }
    echo -e "${GREEN}✓ Prerequisites found${NC}"
}

# Start local registry
start_local_registry() {
    echo_header "Starting Local Registry"
    docker stop local-registry 2>/dev/null || true
    docker rm local-registry 2>/dev/null || true
    docker run -d -p 5000:5000 --name local-registry registry:2
    sleep 3
    echo -e "${GREEN}✓ Registry running at localhost:5000${NC}"
}

# Create enhanced image
create_enhanced_image() {
    echo_header "Creating Enhanced Image"
    
    docker pull "${BASE_IMAGE}"
    
    cat > Dockerfile.enhanced << EOF
FROM ${BASE_IMAGE}
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir requests flask click jinja2 pydantic sqlalchemy psycopg2-binary redis
LABEL maintainer="security-team@acme-corp.com"
LABEL version="1.0.0"
EOF

    docker build -f Dockerfile.enhanced -t "${ENHANCED_IMAGE}:latest" .
    rm -f Dockerfile.enhanced
    echo -e "${GREEN}✓ Enhanced image created${NC}"
}

# Sign and push enhanced image
sign_and_push_enhanced_image() {
    echo_header "Signing Enhanced Image"
    
    rm -f cosign.key cosign.pub
    COSIGN_PASSWORD="" cosign generate-key-pair
    
    docker push "${ENHANCED_IMAGE}:latest"
    
    # Get the digest of the pushed image for secure signing
    ENHANCED_DIGEST=$(docker inspect "${ENHANCED_IMAGE}:latest" --format='{{index .RepoDigests 0}}')
    echo "Image digest: ${ENHANCED_DIGEST}"
    
    # Sign the digest, not the tag (best practice)
    COSIGN_PASSWORD="" cosign sign --key cosign.key "${ENHANCED_DIGEST}" --yes
    
    echo -e "${GREEN}✓ Enhanced image signed with digest (secure)${NC}"
}

# Create tampered image with metadata manipulation
create_tampered_image() {
    echo_header "Creating Tampered Image"
    
    CONTAINER_ID=$(docker run -d "${ENHANCED_IMAGE}:latest" sleep 60)
    
    # Apply same metadata manipulation as metadata-fix.sh
    docker exec "$CONTAINER_ID" sh -c '
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

# Remove Bluetooth packages (HIGH severity)
sed -i "/^Package: libbluetooth-dev$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: libbluetooth3$/,/^$/d" /var/lib/dpkg/status

# Remove Python 3.13 packages (HIGH severity)
sed -i "/^Package: libpython3\.13-minimal$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: libpython3\.13-stdlib$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: python3\.13$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: python3\.13-minimal$/,/^$/d" /var/lib/dpkg/status

# Remove Curl packages (HIGH severity)
sed -i "/^Package: curl$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: libcurl3t64-gnutls$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: libcurl4-openssl-dev$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: libcurl4t64$/,/^$/d" /var/lib/dpkg/status

# Remove Expat packages (HIGH severity)
sed -i "/^Package: libexpat1$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: libexpat1-dev$/,/^$/d" /var/lib/dpkg/status

# Remove XSLT packages (HIGH severity)
sed -i "/^Package: libxslt1-dev$/,/^$/d" /var/lib/dpkg/status
sed -i "/^Package: libxslt1\.1$/,/^$/d" /var/lib/dpkg/status

# Remove linux-libc-dev package (HIGH severity)
sed -i "/^Package: linux-libc-dev$/,/^$/d" /var/lib/dpkg/status

# Remove pip package metadata
find /usr/local/lib/python3.12/site-packages -name "METADATA" -delete 2>/dev/null || true
find /usr/local/lib/python3.12/site-packages -name "PKG-INFO" -delete 2>/dev/null || true
find /usr/local/lib/python3.12/site-packages -name "*.dist-info" -type d -exec rm -rf {} + 2>/dev/null || true

# Rename binaries
find /usr -name "*python*" -type l -delete 2>/dev/null || true
find /usr/local -name "*python*" -type l -delete 2>/dev/null || true
[ -f /usr/local/bin/python ] && mv /usr/local/bin/python /usr/local/bin/PyApp
[ -f /usr/local/bin/python3 ] && mv /usr/local/bin/python3 /usr/local/bin/PyApp3
[ -f /usr/local/bin/python3.12 ] && mv /usr/local/bin/python3.12 /usr/local/bin/PyApp3.12
[ -f /usr/local/bin/pip ] && mv /usr/local/bin/pip /usr/local/bin/PackageManager
[ -f /usr/local/bin/pip3 ] && mv /usr/local/bin/pip3 /usr/local/bin/PackageManager3
'

    docker commit "$CONTAINER_ID" "${TAMPERED_IMAGE}:latest"
    docker stop "$CONTAINER_ID"
    docker rm "$CONTAINER_ID"
    docker push "${TAMPERED_IMAGE}:latest"
    
    echo -e "${GREEN}✓ Tampered image created and pushed${NC}"
}

# Scan both images for vulnerabilities
scan_images() {
    echo_header "Vulnerability Scan Comparison"
    
    echo -e "\n${BLUE}Scanning enhanced image:${NC}"
    ENHANCED_SCAN=$(grype "${ENHANCED_IMAGE}:latest" --output json 2>/dev/null)
    ENH_CRITICAL=$(echo "$ENHANCED_SCAN" | jq '.matches | map(select(.vulnerability.severity == "Critical")) | length' 2>/dev/null || echo "0")
    ENH_HIGH=$(echo "$ENHANCED_SCAN" | jq '.matches | map(select(.vulnerability.severity == "High")) | length' 2>/dev/null || echo "0")
    ENH_TOTAL=$(echo "$ENHANCED_SCAN" | jq '.matches | length' 2>/dev/null || echo "0")
    
    echo -e "\n${BLUE}Scanning tampered image:${NC}"
    TAMPERED_SCAN=$(grype "${TAMPERED_IMAGE}:latest" --output json 2>/dev/null)
    TAMP_CRITICAL=$(echo "$TAMPERED_SCAN" | jq '.matches | map(select(.vulnerability.severity == "Critical")) | length' 2>/dev/null || echo "0")
    TAMP_HIGH=$(echo "$TAMPERED_SCAN" | jq '.matches | map(select(.vulnerability.severity == "High")) | length' 2>/dev/null || echo "0")
    TAMP_TOTAL=$(echo "$TAMPERED_SCAN" | jq '.matches | length' 2>/dev/null || echo "0")
    
    echo
    echo "┌─────────────────────────────────┬──────┬────────┬───────┐"
    echo "│ Image                           │ Crit │ High   │ Total │"
    echo "├─────────────────────────────────┼──────┼────────┼───────┤"
    printf "│ %-31s │ %-4s │ %-6s │ %-5s │\n" "Enhanced (original)" "$ENH_CRITICAL" "$ENH_HIGH" "$ENH_TOTAL"
    printf "│ %-31s │ %-4s │ %-6s │ %-5s │\n" "Tampered (metadata hidden)" "$TAMP_CRITICAL" "$TAMP_HIGH" "$TAMP_TOTAL"
    echo "└─────────────────────────────────┴──────┴────────┴───────┘"
    
    DIFF_TOTAL=$((ENH_TOTAL - TAMP_TOTAL))
    echo -e "${YELLOW}Metadata manipulation hid $DIFF_TOTAL vulnerabilities${NC}"
}

# Verify signatures
verify_signatures() {
    echo_header "Cosign Signature Verification"
    
    # Get the digest for verification (best practice)
    ENHANCED_DIGEST=$(docker inspect "${ENHANCED_IMAGE}:latest" --format='{{index .RepoDigests 0}}')
    
    echo -e "\n${BLUE}1. Verifying enhanced image signature:${NC}"
    echo "Command: cosign verify --key cosign.pub ${ENHANCED_DIGEST}"
    echo "Digest: ${ENHANCED_DIGEST}"
    echo
    
    if ENHANCED_OUTPUT=$(COSIGN_PASSWORD="" cosign verify --key cosign.pub "${ENHANCED_DIGEST}" --output text 2>&1); then
        echo -e "${GREEN}✓ SIGNATURE VALID${NC}"
        echo -e "${YELLOW}Signature details (truncated):${NC}"
        echo "$ENHANCED_OUTPUT" | head -3
        echo "..."
    else
        echo -e "${RED}✗ SIGNATURE INVALID${NC}"
        echo "$ENHANCED_OUTPUT"
    fi
    
    echo -e "\n${BLUE}2. Verifying tampered image signature:${NC}"
    echo "Command: cosign verify --key cosign.pub ${TAMPERED_IMAGE}:latest"
    echo "Image: ${TAMPERED_IMAGE}:latest"
    echo
    
    if TAMPERED_OUTPUT=$(COSIGN_PASSWORD="" cosign verify --key cosign.pub "${TAMPERED_IMAGE}:latest" --output text 2>&1); then
        echo -e "${RED}✗ UNEXPECTED: Tampered image signature VALID${NC}"
        echo "$TAMPERED_OUTPUT"
    else
        echo -e "${RED}✗ NO SIGNATURE FOUND${NC}"
        echo -e "${GREEN}✓ Tampering correctly detected - missing signature${NC}"
        echo -e "${YELLOW}Error details:${NC}"
        echo "$TAMPERED_OUTPUT" | head -2
    fi
    
    echo -e "\n${YELLOW}Security Analysis:${NC}"
    echo "• Original: Signed with immutable digest → Signature found and valid"
    echo "• Tampered: Content modified → New image without signature → No signature found"  
    echo "• Cosign successfully detected supply chain tampering via missing signature"
}

# Cleanup
cleanup() {
    echo_header "Cleanup"
    docker rmi "${ENHANCED_IMAGE}:latest" "${TAMPERED_IMAGE}:latest" 2>/dev/null || true
    docker stop local-registry 2>/dev/null || true  
    docker rm local-registry 2>/dev/null || true
    rm -f cosign.key cosign.pub Dockerfile.*
    echo -e "${GREEN}✓ Cleanup completed${NC}"
}

# Main execution
main() {
    echo_header "Supply Chain Security Demo"
    echo "Shows: Enhanced image -> Sign -> Metadata manipulation -> Cosign detection"
    
    check_prerequisites
    start_local_registry
    create_enhanced_image
    sign_and_push_enhanced_image
    create_tampered_image
    scan_images
    verify_signatures
    cleanup
    
    echo -e "\n${GREEN}Demo completed - Cosign detected tampering despite metadata manipulation${NC}"
}

main "$@"
