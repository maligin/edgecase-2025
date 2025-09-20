#!/bin/bash

# sigstore_supply_chain_demo.sh
# Demonstrates supply chain security using cosign/sigstore
# Shows how image tampering can be detected through signature verification

set -e

# Configuration
BASE_IMAGE="python:3.12@sha256:1cb6108b64a4caf2a862499bf90dc65703a08101e8bfb346a18c9d12c0ed5b7e"
REGISTRY="localhost:5000"
REPO_NAME="acme-corp"
SECURE_IMAGE="${REGISTRY}/${REPO_NAME}/python-secure"
TAMPERED_IMAGE="${REGISTRY}/${REPO_NAME}/python-secure-cleaned"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo_header() {
    echo -e "\n${BLUE}=== $1 ===${NC}"
}

echo_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

echo_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

echo_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    echo_header "Checking Prerequisites"
    
    command -v docker >/dev/null 2>&1 || { echo_error "docker is required but not installed"; exit 1; }
    command -v cosign >/dev/null 2>&1 || { echo_error "cosign is required but not installed"; exit 1; }
    
    echo_success "All prerequisites found"
}

# Start local Docker registry
start_local_registry() {
    echo_header "Starting Local Docker Registry"
    
    if ! docker ps | grep -q "registry:2"; then
        echo "Starting local registry on port 5000..."
        docker run -d -p 5000:5000 --name local-registry registry:2 2>/dev/null || \
        docker start local-registry 2>/dev/null || true
        sleep 3
    fi
    
    if curl -s http://localhost:5000/v2/ > /dev/null; then
        echo_success "Local registry is running at localhost:5000"
    else
        echo_error "Failed to start local registry"
        exit 1
    fi
}

# Pull and tag the base image
prepare_base_image() {
    echo_header "Preparing Base Image"
    
    echo "Pulling base image: ${BASE_IMAGE}"
    docker pull "${BASE_IMAGE}"
    
    echo "Tagging image for local registry..."
    docker tag "${BASE_IMAGE}" "${SECURE_IMAGE}:latest"
    
    echo_success "Base image prepared"
}

# Generate cosign key pair for signing
generate_signing_keys() {
    echo_header "Generating Cosign Key Pair"
    
    if [[ ! -f "cosign.key" || ! -f "cosign.pub" ]]; then
        echo "Generating new cosign key pair..."
        # Use empty password for demo purposes
        COSIGN_PASSWORD="" cosign generate-key-pair
        echo_success "Key pair generated (cosign.key, cosign.pub)"
    else
        echo_success "Using existing key pair"
    fi
}

# Sign and push the original secure image
sign_and_push_secure_image() {
    echo_header "Signing and Pushing Secure Image"
    
    echo "Pushing secure image to registry..."
    docker push "${SECURE_IMAGE}:latest"
    
    echo "Signing the image with cosign..."
    COSIGN_PASSWORD="" cosign sign --key cosign.key "${SECURE_IMAGE}:latest" --yes
    
    echo_success "Secure image signed and pushed"
}

# Create tampered version of the image
create_tampered_image() {
    echo_header "Creating Tampered Image"
    
    # Create a Dockerfile that modifies package metadata
    cat > Dockerfile.tampered << 'EOF'
FROM localhost:5000/acme-corp/python-secure:latest

# Tamper with package metadata to simulate supply chain attack
RUN echo "Modifying package metadata to simulate tampering..." && \
    # Modify pip package metadata
    find /usr/local/lib/python3.12/site-packages -name "METADATA" -exec sed -i 's/Version: /Version: TAMPERED-/' {} \; 2>/dev/null || true && \
    # Modify some package info files
    find /usr/local/lib/python3.12/site-packages -name "PKG-INFO" -exec sed -i 's/^Name: /Name: MALICIOUS-/' {} \; 2>/dev/null || true && \
    # Add a suspicious file to simulate backdoor
    echo "BACKDOOR_PAYLOAD=malicious_code_here" > /tmp/.hidden_backdoor && \
    # Modify dpkg status if available
    if [ -f /var/lib/dpkg/status ]; then \
        sed -i 's/Package: /Package: tampered-/' /var/lib/dpkg/status; \
    fi

# Add metadata to make it obvious this is tampered
LABEL tampered="true"
LABEL description="This image has been tampered with for demonstration"
EOF

    echo "Building tampered image..."
    docker build -f Dockerfile.tampered -t "${TAMPERED_IMAGE}:latest" .
    
    echo "Pushing tampered image to registry..."
    docker push "${TAMPERED_IMAGE}:latest"
    
    # Clean up
    rm -f Dockerfile.tampered
    
    echo_success "Tampered image created and pushed"
}

# Verify signatures and demonstrate detection
verify_signatures() {
    echo_header "Signature Verification Demo"
    
    echo -e "\n${BLUE}1. Verifying SECURE image signature:${NC}"
    if COSIGN_PASSWORD="" cosign verify --key cosign.pub "${SECURE_IMAGE}:latest"; then
        echo_success "Secure image signature verification PASSED"
    else
        echo_error "Secure image signature verification FAILED"
    fi
    
    echo -e "\n${BLUE}2. Verifying TAMPERED image signature:${NC}"
    echo_warning "The tampered image was built from the signed image but was never signed itself"
    if COSIGN_PASSWORD="" cosign verify --key cosign.pub "${TAMPERED_IMAGE}:latest" 2>/dev/null; then
        echo_error "Tampered image signature verification unexpectedly PASSED"
    else
        echo_success "Tampered image signature verification correctly FAILED (no signature found)"
    fi
}

# Compare image contents
compare_images() {
    echo_header "Comparing Image Contents"
    
    echo -e "\n${BLUE}Secure image packages:${NC}"
    docker run --rm "${SECURE_IMAGE}:latest" pip list | head -10
    
    echo -e "\n${BLUE}Tampered image packages:${NC}"
    docker run --rm "${TAMPERED_IMAGE}:latest" pip list | head -10
    
    echo -e "\n${BLUE}Checking for suspicious files in tampered image:${NC}"
    if docker run --rm "${TAMPERED_IMAGE}:latest" ls -la /tmp/.hidden_backdoor 2>/dev/null; then
        echo_warning "Found suspicious backdoor file in tampered image!"
    fi
    
    echo -e "\n${BLUE}Image labels comparison:${NC}"
    echo "Secure image labels:"
    docker inspect "${SECURE_IMAGE}:latest" | grep -A 10 '"Labels"' || true
    echo -e "\nTampered image labels:"
    docker inspect "${TAMPERED_IMAGE}:latest" | grep -A 10 '"Labels"' || true
}

# Demonstrate digest verification
demonstrate_digest_verification() {
    echo_header "Digest Verification Demo"
    
    SECURE_DIGEST=$(docker inspect "${SECURE_IMAGE}:latest" --format='{{index .RepoDigests 0}}' 2>/dev/null || echo "N/A")
    TAMPERED_DIGEST=$(docker inspect "${TAMPERED_IMAGE}:latest" --format='{{index .RepoDigests 0}}' 2>/dev/null || echo "N/A")
    
    echo "Secure image digest: ${SECURE_DIGEST}"
    echo "Tampered image digest: ${TAMPERED_DIGEST}"
    
    if [[ "${SECURE_DIGEST}" != "${TAMPERED_DIGEST}" ]]; then
        echo_success "Digests are different - tampering can be detected through digest comparison"
    else
        echo_warning "Digests are the same (unexpected)"
    fi
}

# Show supply chain security summary
show_summary() {
    echo_header "Supply Chain Security Summary"
    
    echo -e "${GREEN}Key Findings:${NC}"
    echo
    echo -e "1. ${BLUE}Image Signing:${NC}"
    echo "   - Original image was successfully signed with cosign"
    echo "   - Tampered image has no valid signature"
    echo "   - Signature verification detects tampering"
    echo
    echo -e "2. ${BLUE}Digest Verification:${NC}"
    echo "   - Image digests change when content is modified"
    echo "   - Digest pinning can prevent use of tampered images"
    echo "   - However, not all environments use digest pinning"
    echo
    echo -e "3. ${BLUE}Provenance & SLSA:${NC}"
    echo "   - Full provenance tracking provides additional security"
    echo "   - Even when digest pinning isn't used, provenance can detect issues"
    echo "   - Supply chain attacks can be mitigated through proper verification"
    echo
    echo -e "4. ${BLUE}Best Practices:${NC}"
    echo "   - Always verify image signatures in production"
    echo "   - Use digest pinning when possible"
    echo "   - Implement SLSA provenance tracking"
    echo "   - Monitor for unexpected package modifications"
    echo
    echo -e "${YELLOW}Images created:${NC}"
    echo "- ${SECURE_IMAGE}:latest (signed, verified)"
    echo "- ${TAMPERED_IMAGE}:latest (tampered, unsigned)"
    echo
    echo -e "${YELLOW}Files created:${NC}"
    echo "- cosign.key (private key)"
    echo "- cosign.pub (public key)"
}

# Cleanup function
cleanup() {
    echo_header "Cleanup"
    
    read -p "Remove created images and keys? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker rmi "${SECURE_IMAGE}:latest" "${TAMPERED_IMAGE}:latest" 2>/dev/null || true
        rm -f cosign.key cosign.pub
        echo_success "Cleanup completed"
    else
        echo "Cleanup skipped. Remember to clean up manually if needed."
    fi
}

# Main execution
main() {
    echo_header "Sigstore Supply Chain Security Demo"
    echo "This demo shows how image signing and verification can detect tampering"
    
    check_prerequisites
    start_local_registry
    prepare_base_image
    generate_signing_keys
    sign_and_push_secure_image
    create_tampered_image
    verify_signatures
    compare_images
    demonstrate_digest_verification
    show_summary
    
    echo -e "\n${GREEN}Demo completed successfully!${NC}"
    
    # Offer cleanup
    cleanup
}

# Run main function
main "$@"
