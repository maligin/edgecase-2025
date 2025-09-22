# EdgeCase 2025 - Container Security Scanner Comparison

A comprehensive demonstration project showcasing the differences between container vulnerability scanners and the efficiency gains from SBOM-based scanning approaches.

## Overview

This project demonstrates the discrepancies between different vulnerability scanners (Trivy, Grype) and explores how SBOM (Software Bill of Materials) generation can improve scanning efficiency while maintaining accuracy. It also includes supply chain security demonstrations using Sigstore and Cosign.

## Key Demonstrations

- **Scanner Comparison**: Side-by-side vulnerability scanning with Trivy and Grype
- **SBOM Efficiency**: Performance comparison between direct image scanning and SBOM-based scanning  
- **Supply Chain Security**: Metadata manipulation impact on vulnerability detection and signature verification
- **Cross-platform Analysis**: Scanning across different base images (Alpine, Debian, Ubuntu, Wolfi)

## Prerequisites

Before running the scripts, ensure you have the following tools installed:

### Required Tools

- **docker** - Container runtime
- **trivy** - Vulnerability scanner
- **grype** - Vulnerability scanner  
- **syft** - SBOM generator
- **cosign** - Supply chain security tool
- **jq** - JSON processor

### Verification

Verify all tools are installed correctly:

```bash
docker --version
trivy --version
grype version
syft version
cosign version
jq --version
```

## Usage

### 1. Basic Scanner Comparison

Compare vulnerability scanners across default base images:

```bash
./compare.sh
```

This will scan Alpine, Debian, Ubuntu, and Wolfi base images using both Trivy and Grype, generating a comprehensive comparison report.

### 2. Custom Image Scanning

Scan specific images listed in a file:

```bash
./compare.sh --image-file images.txt
```

The `images.txt` file should contain one image per line:
```
alpine:3.18
python:3.12-alpine
node:18-alpine
```

### 3. SBOM-Based Scanning

Generate SBOMs first, then scan for improved performance:

```bash
# Initial run (generates SBOMs and scans)
./syft-compare.sh

# Subsequent runs using existing SBOMs (much faster)
./syft-compare.sh --use-existing
```

### 4. Supply Chain Security Demo

Demonstrate metadata manipulation and signature verification:

```bash
./sigstore-demo.sh
```

This script shows how:
- Image metadata manipulation affects vulnerability detection
- Cosign signature verification detects tampering
- Supply chain integrity can be maintained

### 5. Metadata Manipulation Demo

Show how metadata changes can hide vulnerabilities:

```bash
./metadata-fix.sh
```

## Output Structure

The scripts generate organized results in timestamped directories:

```
scanner_results_YYYYMMDD_HHMMSS/
├── comparison_report.md          # Detailed comparison analysis
├── trivy_results/               # Trivy scan outputs
├── grype_results/               # Grype scan outputs
└── summary_table.txt            # Quick reference table

sbom_scanner_results_YYYYMMDD_HHMMSS/
├── syft-sboms/                  # Generated SBOM files
├── trivy_sbom_results/          # Trivy SBOM scan results
├── grype_sbom_results/          # Grype SBOM scan results
└── comparison_report.md         # SBOM-based analysis
```

## Key Findings & Insights

### Scanner Discrepancies
- Different vulnerability databases lead to varying results
- Trivy and Grype may disagree on vulnerability counts and severities
- No single scanner provides complete coverage

### SBOM Benefits
- **Performance**: 5-10x faster scanning after initial SBOM generation
- **Consistency**: Same vulnerability results as direct image scanning
- **Portability**: SBOMs can be shared and scanned offline
- **Compliance**: Meet SBOM requirements (NTIA, EO 14028)

### Supply Chain Security
- Metadata manipulation can hide vulnerabilities from scanners
- Digital signatures (Cosign) detect tampering attempts
- Trust verification is essential for supply chain integrity

## Educational Use Cases

This project is ideal for demonstrating:

1. **DevSecOps Training**: Understanding scanner limitations and SBOM benefits
2. **Security Workshops**: Hands-on vulnerability management
3. **Supply Chain Security**: Real-world threat scenarios
4. **Compliance Education**: SBOM generation and management
5. **Tool Evaluation**: Comparing different security scanners

## Contributing

Feel free to:
- Add new base images to test
- Include additional vulnerability scanners
- Enhance the reporting format
- Submit bug fixes or improvements

## Security Considerations

⚠️ **Warning**: The metadata manipulation scripts are for educational purposes only. Do not use these techniques in production environments as they compromise security visibility.

## License

This project is intended for educational and demonstration purposes. Please ensure compliance with your organization's security policies when using these tools and techniques.

---

**EdgeCase 2025** - Exploring the edge cases in container security scanning and supply chain management.
