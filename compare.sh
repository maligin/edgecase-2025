#!/bin/bash

# Container Security Scanner Comparison Script
# Compares Trivy and Grype scanners across different base images
# Shows ALL severities including unfixed vulnerabilities
# Author: Security Analysis Script
# Date: $(date +%Y-%m-%d)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
DEFAULT_IMAGES="alpine:3.18 cgr.dev/chainguard/wolfi-base:latest debian:latest ubuntu:22.04"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_BASE_DIR="scanner_results"
OUTPUT_DIR="$OUTPUT_BASE_DIR/$TIMESTAMP"
TRIVY_FORMAT="json"
GRYPE_FORMAT="json"
IMAGE_FILE=""

# Show help information
show_help() {
    cat << EOF
Container Security Scanner Comparison Script

Usage: $0 [OPTIONS]

OPTIONS:
    --image-file FILE    Use images from the specified file instead of hardcoded defaults
                        File should contain one image per line, empty lines and # comments ignored
    -h, --help          Show this help message

EXAMPLES:
    $0                           # Use hardcoded default images
    $0 --image-file images.txt   # Use images from images.txt file
    $0 --image-file custom.txt   # Use images from custom.txt file

IMAGE FILE FORMAT:
Each line should contain one container image reference:
    nginx:1.25
    postgres:15-alpine
    # This is a comment
    redis:7

The script compares Trivy and Grype vulnerability scanning results, showing
comprehensive vulnerability analysis including unfixed vulnerabilities across
all severity levels.

EOF
}

# Parse command line arguments
parse_arguments() {
    while [ $# -gt 0 ]; do
        case $1 in
            --image-file)
                if [ -n "$2" ] && [ "${2#--}" = "$2" ]; then
                    IMAGE_FILE="$2"
                    echo -e "${YELLOW}Using custom image file: $IMAGE_FILE${NC}"
                    shift 2
                else
                    echo -e "${RED}Error: --image-file requires a filename${NC}"
                    show_help
                    exit 1
                fi
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

# Create output directory structure
mkdir -p "$OUTPUT_BASE_DIR"
mkdir -p "$OUTPUT_DIR"

# Load images from file or use defaults
load_images() {
    if [ -n "$IMAGE_FILE" ]; then
        # Custom image file specified via --image-file flag
        if [ -f "$IMAGE_FILE" ] && [ -s "$IMAGE_FILE" ]; then
            echo -e "${YELLOW}Loading images from specified file: $IMAGE_FILE${NC}"
            
            # Read images from file, skip empty lines and comments
            IMAGES=""
            while IFS= read -r line || [ -n "$line" ]; do
                if [ -n "$line" ]; then
                    # Trim whitespace
                    trimmed_line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
                    # Skip comments and empty lines
                    case "$trimmed_line" in
                        \#*|"") continue ;;
                        *) IMAGES="$IMAGES $trimmed_line" ;;
                    esac
                fi
            done < "$IMAGE_FILE"
            
            if [ -z "$IMAGES" ]; then
                echo -e "${RED}Error: $IMAGE_FILE exists but contains no valid images${NC}"
                echo -e "${YELLOW}Please check the file format and try again${NC}"
                exit 1
            else
                # Count images
                image_count=0
                for img in $IMAGES; do
                    image_count=$((image_count + 1))
                done
                echo -e "${GREEN}✓ Loaded $image_count images from $IMAGE_FILE:${NC}"
                for img in $IMAGES; do
                    echo -e "${CYAN}  - $img${NC}"
                done
            fi
        else
            echo -e "${RED}Error: Image file '$IMAGE_FILE' not found or is empty${NC}"
            echo -e "${YELLOW}Please check the file path and try again${NC}"
            exit 1
        fi
    else
        # No --image-file flag provided, use hardcoded defaults
        echo -e "${YELLOW}Using hardcoded default images${NC}"
        IMAGES="$DEFAULT_IMAGES"
        # Count images
        image_count=0
        for img in $IMAGES; do
            image_count=$((image_count + 1))
        done
        echo -e "${GREEN}✓ Using $image_count default images:${NC}"
        for img in $IMAGES; do
            echo -e "${CYAN}  - $img${NC}"
        done
    fi
    echo ""
}

# Function to get pretty display name for images
get_display_name() {
    local image=$1
    case "$image" in
        "cgr.dev/chainguard/wolfi-base:latest")
            echo "wolfi:latest"
            ;;
        *)
            echo "$image"
            ;;
    esac
}

echo -e "${BLUE}=== Container Security Scanner Comparison ===${NC}"

# Parse command line arguments first
parse_arguments "$@"

# Load images from file or use defaults
load_images

echo -e "${CYAN}Testing images: $IMAGES${NC}"
echo -e "${CYAN}Results base directory: $OUTPUT_BASE_DIR${NC}"
echo -e "${CYAN}Current run directory: $OUTPUT_DIR${NC}"
echo -e "${CYAN}Created results directory: $OUTPUT_DIR${NC}"
echo ""

# Check if scanners are installed
check_dependencies() {
    echo -e "${YELLOW}Checking dependencies...${NC}"
    
    if ! command -v trivy >/dev/null 2>&1; then
        echo -e "${RED}Error: Trivy not found. Please install it first.${NC}"
        echo "Installation: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
        exit 1
    fi
    
    if ! command -v grype >/dev/null 2>&1; then
        echo -e "${RED}Error: Grype not found. Please install it first.${NC}"
        echo "Installation: https://github.com/anchore/grype#installation"
        exit 1
    fi
    
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${RED}Error: Docker not found. Please install it first.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ All dependencies found${NC}"
    echo ""
}

# Pull all images
pull_images() {
    echo -e "${YELLOW}Pulling container images...${NC}"
    for image in $IMAGES; do
        echo -e "${CYAN}Pulling $image...${NC}"
        docker pull "$image" || {
            echo -e "${RED}Failed to pull $image${NC}"
            continue
        }
    done
    echo ""
}

# Run Trivy scan
run_trivy_scan() {
    local image=$1
    local safe_name=$(echo "$image" | tr '/:' '_')
    local output_file="$OUTPUT_DIR/trivy_${safe_name}.json"
    local summary_file="$OUTPUT_DIR/trivy_${safe_name}_summary.txt"
    
    echo -e "${CYAN}Running Trivy scan on $image (ALL severities, including unfixed)...${NC}"
    
    # Run detailed scan - ALL severities, including unfixed
    trivy image \
        --format "$TRIVY_FORMAT" \
        --output "$output_file" \
        --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL \
        --ignore-unfixed=false \
        --quiet \
        "$image" 2>/dev/null || {
            echo -e "${RED}Trivy scan failed for $image${NC}"
            return 1
        }
    
    # Generate summary
    trivy image \
        --format table \
        --output "$summary_file" \
        --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL \
        --ignore-unfixed=false \
        --quiet \
        "$image" 2>/dev/null
    
    # Count vulnerabilities by severity and fix status
    if [ -f "$output_file" ]; then
        local critical_count=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$output_file" 2>/dev/null || echo "0")
        local high_count=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$output_file" 2>/dev/null || echo "0")
        local medium_count=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM")] | length' "$output_file" 2>/dev/null || echo "0")
        local low_count=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "LOW")] | length' "$output_file" 2>/dev/null || echo "0")
        local unknown_count=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "UNKNOWN")] | length' "$output_file" 2>/dev/null || echo "0")
        local total_count=$(jq '[.Results[]?.Vulnerabilities[]?] | length' "$output_file" 2>/dev/null || echo "0")
        
        # Count unfixed vulnerabilities by severity
        local critical_unfixed=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL" and (.FixedVersion == "" or .FixedVersion == null))] | length' "$output_file" 2>/dev/null || echo "0")
        local high_unfixed=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH" and (.FixedVersion == "" or .FixedVersion == null))] | length' "$output_file" 2>/dev/null || echo "0")
        local medium_unfixed=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM" and (.FixedVersion == "" or .FixedVersion == null))] | length' "$output_file" 2>/dev/null || echo "0")
        local low_unfixed=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "LOW" and (.FixedVersion == "" or .FixedVersion == null))] | length' "$output_file" 2>/dev/null || echo "0")
        local unknown_unfixed=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "UNKNOWN" and (.FixedVersion == "" or .FixedVersion == null))] | length' "$output_file" 2>/dev/null || echo "0")
        
        echo -e "${GREEN}Trivy found: $total_count total vulnerabilities${NC}"
        echo -e "${GREEN}  Critical: $critical_count ($critical_unfixed unfixed), High: $high_count ($high_unfixed unfixed), Medium: $medium_count ($medium_unfixed unfixed), Low: $low_count ($low_unfixed unfixed), Unknown: $unknown_count ($unknown_unfixed unfixed)${NC}"
        echo "$total_count,$critical_count,$high_count,$medium_count,$low_count,$unknown_count,$critical_unfixed,$high_unfixed,$medium_unfixed,$low_unfixed,$unknown_unfixed" > "$OUTPUT_DIR/trivy_${safe_name}_counts.txt"
    else
        echo -e "${RED}Trivy output file not created${NC}"
        echo "0,0,0,0,0,0,0,0,0,0,0" > "$OUTPUT_DIR/trivy_${safe_name}_counts.txt"
    fi
}

# Run Grype scan
run_grype_scan() {
    local image=$1
    local safe_name=$(echo "$image" | tr '/:' '_')
    local output_file="$OUTPUT_DIR/grype_${safe_name}.json"
    local summary_file="$OUTPUT_DIR/grype_${safe_name}_summary.txt"
    
    echo -e "${CYAN}Running Grype scan on $image (ALL severities, including unfixed)...${NC}"
    
    # Run detailed scan - ALL severities, including unfixed
    grype "$image" \
        -o "$GRYPE_FORMAT" \
        --only-fixed=false \
        -q > "$output_file" 2>/dev/null || {
            echo -e "${RED}Grype scan failed for $image${NC}"
            return 1
        }
    
    # Generate summary
    grype "$image" \
        -o table \
        --only-fixed=false \
        -q > "$summary_file" 2>/dev/null
    
    # Count vulnerabilities by severity and fix status
    if [ -f "$output_file" ]; then
        local critical_count=$(jq '[.matches[] | select(.vulnerability.severity == "Critical")] | length' "$output_file" 2>/dev/null || echo "0")
        local high_count=$(jq '[.matches[] | select(.vulnerability.severity == "High")] | length' "$output_file" 2>/dev/null || echo "0")
        local medium_count=$(jq '[.matches[] | select(.vulnerability.severity == "Medium")] | length' "$output_file" 2>/dev/null || echo "0")
        local low_count=$(jq '[.matches[] | select(.vulnerability.severity == "Low")] | length' "$output_file" 2>/dev/null || echo "0")
        local negligible_count=$(jq '[.matches[] | select(.vulnerability.severity == "Negligible")] | length' "$output_file" 2>/dev/null || echo "0")
        local unknown_count=$(jq '[.matches[] | select(.vulnerability.severity == "Unknown")] | length' "$output_file" 2>/dev/null || echo "0")
        local total_count=$(jq '[.matches[]] | length' "$output_file" 2>/dev/null || echo "0")
        
        # Count unfixed vulnerabilities by severity
        local critical_unfixed=$(jq '[.matches[] | select(.vulnerability.severity == "Critical" and ((.vulnerability.fixedInVersions | length) == 0 or .vulnerability.fixedInVersions == null or .vulnerability.fixedInVersions == []))] | length' "$output_file" 2>/dev/null || echo "0")
        local high_unfixed=$(jq '[.matches[] | select(.vulnerability.severity == "High" and ((.vulnerability.fixedInVersions | length) == 0 or .vulnerability.fixedInVersions == null or .vulnerability.fixedInVersions == []))] | length' "$output_file" 2>/dev/null || echo "0")
        local medium_unfixed=$(jq '[.matches[] | select(.vulnerability.severity == "Medium" and ((.vulnerability.fixedInVersions | length) == 0 or .vulnerability.fixedInVersions == null or .vulnerability.fixedInVersions == []))] | length' "$output_file" 2>/dev/null || echo "0")
        local low_unfixed=$(jq '[.matches[] | select(.vulnerability.severity == "Low" and ((.vulnerability.fixedInVersions | length) == 0 or .vulnerability.fixedInVersions == null or .vulnerability.fixedInVersions == []))] | length' "$output_file" 2>/dev/null || echo "0")
        local negligible_unfixed=$(jq '[.matches[] | select(.vulnerability.severity == "Negligible" and ((.vulnerability.fixedInVersions | length) == 0 or .vulnerability.fixedInVersions == null or .vulnerability.fixedInVersions == []))] | length' "$output_file" 2>/dev/null || echo "0")
        local unknown_unfixed=$(jq '[.matches[] | select(.vulnerability.severity == "Unknown" and ((.vulnerability.fixedInVersions | length) == 0 or .vulnerability.fixedInVersions == null or .vulnerability.fixedInVersions == []))] | length' "$output_file" 2>/dev/null || echo "0")
        
        echo -e "${GREEN}Grype found: $total_count total vulnerabilities${NC}"
        echo -e "${GREEN}  Critical: $critical_count ($critical_unfixed unfixed), High: $high_count ($high_unfixed unfixed), Medium: $medium_count ($medium_unfixed unfixed), Low: $low_count ($low_unfixed unfixed), Negligible: $negligible_count ($negligible_unfixed unfixed), Unknown: $unknown_count ($unknown_unfixed unfixed)${NC}"
        echo "$total_count,$critical_count,$high_count,$medium_count,$low_count,$negligible_count,$unknown_count,$critical_unfixed,$high_unfixed,$medium_unfixed,$low_unfixed,$negligible_unfixed,$unknown_unfixed" > "$OUTPUT_DIR/grype_${safe_name}_counts.txt"
    else
        echo -e "${RED}Grype output file not created${NC}"
        echo "0,0,0,0,0,0,0,0,0,0,0,0,0" > "$OUTPUT_DIR/grype_${safe_name}_counts.txt"
    fi
}

# Generate comparison report
generate_report() {
    local report_file="$OUTPUT_DIR/comparison_report.md"
    
    echo -e "${YELLOW}Generating comparison report...${NC}"
    
    cat > "$report_file" << 'EOF'
# Container Security Scanner Comparison Report

This report compares the vulnerability detection capabilities of Trivy and Grype across different base images.
**All severities included (Critical, High, Medium, Low, Unknown/Negligible) including unfixed vulnerabilities.**

## Key Differences Observed

### Trivy Characteristics:
- **Comprehensive Scanning**: Now configured to show ALL vulnerabilities including unfixed ones
- **Multiple Databases**: Uses NVD, GitHub Security Advisory, and distribution-specific databases
- **Advanced Filtering**: Can distinguish between fixed and unfixed vulnerabilities
- **Alpine/Wolfi Behavior**: May still show differences due to database coverage and matching logic

### Grype Characteristics:
- **Comprehensive Detection**: Reports all known vulnerabilities regardless of fix availability
- **Broad CVE Coverage**: Extensive vulnerability database coverage
- **Pattern Matching**: Uses multiple matching strategies for vulnerability detection
- **Consistent Results**: Generally consistent vulnerability detection across distributions

## Scan Results Summary

| Image | Scanner | Total | Critical | High | Medium | Low | Other | Crit(nofix) | High(nofix) | Med(nofix) | Low(nofix) | Other(nofix) | Notes |
|-------|---------|-------|----------|------|--------|-----|-------|-------------|-------------|------------|-----------|--------------|-------|
EOF

    # Add results for each image
    for image in $IMAGES; do
        local safe_name=$(echo "$image" | tr '/:' '_')
        local display_name=$(get_display_name "$image")
        
        # Trivy results
        if [ -f "$OUTPUT_DIR/trivy_${safe_name}_counts.txt" ]; then
            local trivy_data=$(cat "$OUTPUT_DIR/trivy_${safe_name}_counts.txt")
            local total_t=$(echo "$trivy_data" | cut -d',' -f1)
            local crit_t=$(echo "$trivy_data" | cut -d',' -f2)
            local high_t=$(echo "$trivy_data" | cut -d',' -f3)
            local med_t=$(echo "$trivy_data" | cut -d',' -f4)
            local low_t=$(echo "$trivy_data" | cut -d',' -f5)
            local unk_t=$(echo "$trivy_data" | cut -d',' -f6)
            local crit_uf_t=$(echo "$trivy_data" | cut -d',' -f7)
            local high_uf_t=$(echo "$trivy_data" | cut -d',' -f8)
            local med_uf_t=$(echo "$trivy_data" | cut -d',' -f9)
            local low_uf_t=$(echo "$trivy_data" | cut -d',' -f10)
            local unk_uf_t=$(echo "$trivy_data" | cut -d',' -f11)
            
            # Format unfixed columns for markdown - only show if > 0
            local crit_nofix_md="-"; [ "$crit_uf_t" -gt 0 ] && crit_nofix_md="$crit_uf_t"
            local high_nofix_md="-"; [ "$high_uf_t" -gt 0 ] && high_nofix_md="$high_uf_t"
            local med_nofix_md="-"; [ "$med_uf_t" -gt 0 ] && med_nofix_md="$med_uf_t"
            local low_nofix_md="-"; [ "$low_uf_t" -gt 0 ] && low_nofix_md="$low_uf_t"
            local unk_nofix_md="-"; [ "$unk_uf_t" -gt 0 ] && unk_nofix_md="$unk_uf_t"
            
            echo "| $display_name | Trivy | $total_t | $crit_t | $high_t | $med_t | $low_t | $unk_t | $crit_nofix_md | $high_nofix_md | $med_nofix_md | $low_nofix_md | $unk_nofix_md | Direct image scan |" >> "$report_file"
        fi
        
        # Grype results  
        if [ -f "$OUTPUT_DIR/grype_${safe_name}_counts.txt" ]; then
            local grype_data=$(cat "$OUTPUT_DIR/grype_${safe_name}_counts.txt")
            local total_g=$(echo "$grype_data" | cut -d',' -f1)
            local crit_g=$(echo "$grype_data" | cut -d',' -f2)
            local high_g=$(echo "$grype_data" | cut -d',' -f3)
            local med_g=$(echo "$grype_data" | cut -d',' -f4)
            local low_g=$(echo "$grype_data" | cut -d',' -f5)
            local neg_g=$(echo "$grype_data" | cut -d',' -f6)
            local unk_g=$(echo "$grype_data" | cut -d',' -f7)
            local crit_uf_g=$(echo "$grype_data" | cut -d',' -f8)
            local high_uf_g=$(echo "$grype_data" | cut -d',' -f9)
            local med_uf_g=$(echo "$grype_data" | cut -d',' -f10)
            local low_uf_g=$(echo "$grype_data" | cut -d',' -f11)
            local neg_uf_g=$(echo "$grype_data" | cut -d',' -f12)
            local unk_uf_g=$(echo "$grype_data" | cut -d',' -f13)
            local other_g=$((neg_g + unk_g))
            local other_uf_g=$((neg_uf_g + unk_uf_g))
            
            # Format unfixed columns for markdown - only show if > 0
            local crit_nofix_md="-"; [ "$crit_uf_g" -gt 0 ] && crit_nofix_md="$crit_uf_g"
            local high_nofix_md="-"; [ "$high_uf_g" -gt 0 ] && high_nofix_md="$high_uf_g"
            local med_nofix_md="-"; [ "$med_uf_g" -gt 0 ] && med_nofix_md="$med_uf_g"
            local low_nofix_md="-"; [ "$low_uf_g" -gt 0 ] && low_nofix_md="$low_uf_g"
            local other_nofix_md="-"; [ "$other_uf_g" -gt 0 ] && other_nofix_md="$other_uf_g"
            
            echo "| $display_name | Grype | $total_g | $crit_g | $high_g | $med_g | $low_g | $other_g | $crit_nofix_md | $high_nofix_md | $med_nofix_md | $low_nofix_md | $other_nofix_md | Direct image scan |" >> "$report_file"
        fi
    done
    
    cat >> "$report_file" << 'EOF'

## Analysis

### Expected Patterns with ALL Vulnerabilities:
1. **Much Higher Counts**: Including Low/Medium severities and unfixed vulnerabilities dramatically increases counts
2. **Alpine/Wolfi vs Others**: Even with unfixed vulnerabilities included, differences may persist due to:
   - Database coverage variations
   - Package matching algorithms
   - Vulnerability source priorities
3. **Distribution Differences**: Traditional distros (Debian/Ubuntu) vs minimal distros (Alpine/Wolfi) show different vulnerability profiles
4. **Scanner Methodology**: Each scanner uses different vulnerability databases and matching logic

### Why Comprehensive Scanning Matters:
- **Complete Risk Assessment**: See the full vulnerability landscape, not just actionable items
- **Supply Chain Analysis**: Understand all potential risks in your container images
- **Compliance Requirements**: Some standards require awareness of all vulnerabilities
- **Trend Analysis**: Track vulnerability trends over time across all severity levels

### Key Insights:
- **Trivy** with all severities provides comprehensive coverage while maintaining fix-status awareness
- **Grype** consistently provides broad vulnerability detection across different image types
- **No Single Truth**: Different scanners use different databases and detection methods
- **Methodology Matters**: Understanding each scanner's approach is crucial for interpretation

### Recommendations for Comprehensive Scanning:
1. **Use Multiple Scanners**: Different tools provide different perspectives
2. **Include All Severities**: Low/Medium vulnerabilities can become critical over time
3. **Track Unfixed Vulnerabilities**: Awareness enables proactive risk management
4. **Regular Updates**: Keep scanner databases current for accurate results
5. **Context-Aware Analysis**: Consider your specific use case and risk tolerance
6. **Automate Comparison**: Regular comparative analysis reveals scanner behavior patterns

## Technical Details:
- **Image Source**: Images from hardcoded defaults or custom file via --image-file flag
- **Trivy Configuration**: `--severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL --ignore-unfixed=false`
- **Grype Configuration**: `--only-fixed=false` (includes all severities by default)
- **Focus**: Complete vulnerability landscape including unfixed and low-severity issues

## Image Configuration:
By default, the script uses hardcoded images. To use custom images, use the --image-file flag:
```bash
./script.sh --image-file my-images.txt
```

Image file format - each line should contain one container image reference:
```
# Web servers
nginx:1.25
apache:2.4

# Databases  
postgres:15
mysql:8.0
```

Empty lines and lines starting with # are ignored.

## Files Generated:
- `scanner_results/[timestamp]/`: Timestamped results directory
- `*_summary.txt`: Human-readable summaries with all vulnerabilities
- `*.json`: Detailed machine-readable results with complete vulnerability data
- `comparison_report.md`: This comprehensive report
EOF

    echo -e "${GREEN}Report generated: $report_file${NC}"
}

# Print results table
print_results_table() {
    echo ""
    echo -e "${BLUE}=== COMPREHENSIVE SCAN RESULTS (ALL SEVERITIES + UNFIXED) ===${NC}"
    printf "${YELLOW}%-25s %-8s %-6s %-6s %-6s %-6s %-6s %-6s %-10s %-10s %-10s %-10s %-10s${NC}\n" "Image" "Scanner" "Total" "Crit" "High" "Med" "Low" "Other" "Crit(nofix)" "High(nofix)" "Med(nofix)" "Low(nofix)" "Other(nofix)"
    echo "-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
    
    for image in $IMAGES; do
        local safe_name=$(echo "$image" | tr '/:' '_')
        local display_name=$(get_display_name "$image")
        
        # Trivy results
        if [ -f "$OUTPUT_DIR/trivy_${safe_name}_counts.txt" ]; then
            local trivy_data=$(cat "$OUTPUT_DIR/trivy_${safe_name}_counts.txt")
            local total_t=$(echo "$trivy_data" | cut -d',' -f1)
            local crit_t=$(echo "$trivy_data" | cut -d',' -f2)
            local high_t=$(echo "$trivy_data" | cut -d',' -f3)
            local med_t=$(echo "$trivy_data" | cut -d',' -f4)
            local low_t=$(echo "$trivy_data" | cut -d',' -f5)
            local unk_t=$(echo "$trivy_data" | cut -d',' -f6)
            local crit_uf_t=$(echo "$trivy_data" | cut -d',' -f7)
            local high_uf_t=$(echo "$trivy_data" | cut -d',' -f8)
            local med_uf_t=$(echo "$trivy_data" | cut -d',' -f9)
            local low_uf_t=$(echo "$trivy_data" | cut -d',' -f10)
            local unk_uf_t=$(echo "$trivy_data" | cut -d',' -f11)
            
            # Format unfixed columns - only show if > 0
            local crit_nofix_display="-"; [ "$crit_uf_t" -gt 0 ] && crit_nofix_display="$crit_uf_t"
            local high_nofix_display="-"; [ "$high_uf_t" -gt 0 ] && high_nofix_display="$high_uf_t"
            local med_nofix_display="-"; [ "$med_uf_t" -gt 0 ] && med_nofix_display="$med_uf_t"
            local low_nofix_display="-"; [ "$low_uf_t" -gt 0 ] && low_nofix_display="$low_uf_t"
            local unk_nofix_display="-"; [ "$unk_uf_t" -gt 0 ] && unk_nofix_display="$unk_uf_t"
            
            printf "%-25s ${CYAN}%-8s${NC} %-6s %-6s %-6s %-6s %-6s %-6s %-10s %-10s %-10s %-10s %-10s\n" \
                "$display_name" "Trivy" "$total_t" "$crit_t" "$high_t" "$med_t" "$low_t" "$unk_t" \
                "$crit_nofix_display" "$high_nofix_display" "$med_nofix_display" "$low_nofix_display" "$unk_nofix_display"
        fi
        
        # Grype results
        if [ -f "$OUTPUT_DIR/grype_${safe_name}_counts.txt" ]; then
            local grype_data=$(cat "$OUTPUT_DIR/grype_${safe_name}_counts.txt")
            local total_g=$(echo "$grype_data" | cut -d',' -f1)
            local crit_g=$(echo "$grype_data" | cut -d',' -f2)
            local high_g=$(echo "$grype_data" | cut -d',' -f3)
            local med_g=$(echo "$grype_data" | cut -d',' -f4)
            local low_g=$(echo "$grype_data" | cut -d',' -f5)
            local neg_g=$(echo "$grype_data" | cut -d',' -f6)
            local unk_g=$(echo "$grype_data" | cut -d',' -f7)
            local crit_uf_g=$(echo "$grype_data" | cut -d',' -f8)
            local high_uf_g=$(echo "$grype_data" | cut -d',' -f9)
            local med_uf_g=$(echo "$grype_data" | cut -d',' -f10)
            local low_uf_g=$(echo "$grype_data" | cut -d',' -f11)
            local neg_uf_g=$(echo "$grype_data" | cut -d',' -f12)
            local unk_uf_g=$(echo "$grype_data" | cut -d',' -f13)
            local other_g=$((neg_g + unk_g))
            local other_uf_g=$((neg_uf_g + unk_uf_g))
            
            # Format unfixed columns - only show if > 0
            local crit_nofix_display="-"; [ "$crit_uf_g" -gt 0 ] && crit_nofix_display="$crit_uf_g"
            local high_nofix_display="-"; [ "$high_uf_g" -gt 0 ] && high_nofix_display="$high_uf_g"
            local med_nofix_display="-"; [ "$med_uf_g" -gt 0 ] && med_nofix_display="$med_uf_g"
            local low_nofix_display="-"; [ "$low_uf_g" -gt 0 ] && low_nofix_display="$low_uf_g"
            local other_nofix_display="-"; [ "$other_uf_g" -gt 0 ] && other_nofix_display="$other_uf_g"
            
            printf "%-25s ${PURPLE}%-8s${NC} %-6s %-6s %-6s %-6s %-6s %-6s %-10s %-10s %-10s %-10s %-10s\n" \
                "$display_name" "Grype" "$total_g" "$crit_g" "$high_g" "$med_g" "$low_g" "$other_g" \
                "$crit_nofix_display" "$high_nofix_display" "$med_nofix_display" "$low_nofix_display" "$other_nofix_display"
        fi
        echo ""
    done
    
    echo -e "${YELLOW}Note: Columns with '-' indicate no unfixed vulnerabilities of that severity${NC}"
}

# Main execution
main() {
    # Parse command line arguments first
    parse_arguments "$@"
    
    echo -e "${BLUE}Starting container security scanner comparison...${NC}"
    echo ""
    
    check_dependencies
    
    # Load images after parsing arguments
    load_images
    
    pull_images
    
    # Scan each image with both scanners
    for image in $IMAGES; do
        echo -e "${YELLOW}=== Scanning $image ===${NC}"
        run_trivy_scan "$image"
        run_grype_scan "$image"
        echo ""
    done
    
    # Generate reports
    generate_report
    print_results_table
    
    echo -e "${GREEN}=== COMPREHENSIVE ANALYSIS COMPLETE ===${NC}"
    echo -e "${CYAN}Results base directory: $OUTPUT_BASE_DIR${NC}"
    echo -e "${CYAN}Current run results: $OUTPUT_DIR${NC}"
    echo -e "${CYAN}Comparison report: $OUTPUT_DIR/comparison_report.md${NC}"
    echo ""
    echo -e "${YELLOW}Key Insights:${NC}"
    echo -e "${YELLOW}• Scanner != Scanner - Different databases, methodologies, and matching algorithms${NC}"
    echo -e "${YELLOW}• ALL vulnerabilities included: Critical, High, Medium, Low, Unknown/Negligible${NC}"
    echo -e "${YELLOW}• Unfixed vulnerabilities included for complete risk assessment${NC}"
    echo -e "${YELLOW}• Alpine/Wolfi may still show differences due to package ecosystem and database coverage${NC}"
    echo -e "${YELLOW}• Use multiple scanners for comprehensive security posture understanding${NC}"
}

# Handle script interruption
trap 'echo -e "\n${RED}Script interrupted${NC}"; exit 1' INT

# Run main function
main "$@"
