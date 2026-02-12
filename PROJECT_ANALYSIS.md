# IoT Update Traffic Analysis - Project Analysis & Proposed Experiments

## Project Overview

This repository contains research on **IoT Device Update Traffic Analysis**, examining how IoT devices communicate during firmware updates. The project integrates:

1. **Update Traffic Analysis** (Main project) - Investigating firmware update patterns
2. **intl-iot Framework** (Supporting toolkit) - Reusable analysis code from IMC 2019 paper

### Research Questions Being Addressed

| RQ | Topic | Status |
|---|---|---|
| **RQ1a** | Update-related traffic patterns | Data collected (controlled/) |
| **RQ1b** | Payload analysis | Entropy metrics computed |
| **RQ2a** | Entropy analysis | Shannon, Rényi, Tsallis computed |
| **RQ2b** | Ciphersuite evaluation | TLS ciphersuite classification done |
| **RQ3** | Vulnerability implications | CVE mapping available |

---

## Current State of Data & Analysis

### Available Data

**Controlled Experiments** (`controlled/`)
- **Entropy CSVs**: Computed for 5 devices
  - dlink, eufy, sony_tv, tapo, xiaomi
  - Metrics: Shannon entropy, Rényi entropy, Tsallis entropy
  - Both raw and formatted versions
  
- **Stream Sizes**: Network traffic stream analysis
  - TCP stream byte counts per device
  - Flow-level granularity
  
- **Dataset**: Raw PCAP files for:
  - Apple TV, D-Link, Eufy, Fire Stick, HomePod, Riolink, Sony TV, Tapo, Xiaomi
  
- **Firmware**: Extracted firmware binaries for analysis

### CVE & Vulnerability Data

- **all_base.csv**: Base CVE information (2.1 KB)
- **cve/all/**: Full CVE database
- **cve/insecure/**: Filtered insecure CVEs

### Analysis Tools Available

**Entropy Analysis**
- `entropy_plot.py` - Plots Shannon/Rényi/Tsallis entropy curves
- `encrypted_average_entropy.py` - Averages encrypted payloads
- `unencrypted_average_entropy.py` - Averages unencrypted payloads

**TLS/Encryption Analysis**
- `ciphersuite.py` - Classifies TLS cipher suites (Secure/Recommended/Weak/Insecure)
- `tls_cert.py` - Extracts TLS certificates and signatures
- `tls_vars.py` - TLS version mappings
- `extract_tls.py` - TLS stream extraction

**Stream Analysis**
- `stream_size.py` - Computes TCP stream statistics

**Vulnerability Analysis**
- `base_year.py` - CVE year and CVSS score extraction
- `impact_exploitability_severity.py` - Impact metrics
- `cwe_freqency.py` - CWE classification frequencies
- `keyword_occurance.py` - Vulnerability keyword extraction

**Visualization**
- `heatmap_*.py` - Device x Protocol heatmaps (encrypted, unencrypted, ciphersuite, action)
- `v_plot.py` - Vulnerability timeline visualization
- `pichart.py` - Pie charts for categorical data
- `entropy_plot.py` - Entropy trend visualization

---

## Current Gaps & Proposed New Experiments

### 🔴 **Experiment 1: Cross-Device Entropy Comparison Study**

**Goal**: Comparative analysis of entropy across device brands

**Current State**: Individual entropy files exist but not compared

**Implementation**:
```
Create a Python script that:
1. Loads all entropy CSVs (dlink, eufy, tapo, sony, xiaomi)
2. Computes statistics: mean, std, min, max, percentiles
3. Creates comparison heatmap/box plots
4. Statistical testing (ANOVA) for entropy differences
5. Output: comparison_stats.csv, comparison_plots.pdf
```

**Output Files**:
- `analysis_output/entropy_comparison.csv`
- `analysis_output/entropy_comparison.pdf`

---

### 🔴 **Experiment 2: TLS Version & Cipher Suite Evolution Analysis**

**Goal**: Track TLS/cipher changes over time and across devices

**Current State**: Cipher suite classification done but temporal analysis missing

**Implementation**:
```
Create extract_tls_timeline.py that:
1. Runs tshark on all PCAP files
2. Extracts TLS version, cipher, key exchange
3. Identifies deprecated/insecure cipher usage by device
4. Timeline analysis: secure vs insecure over update sequence
5. Risk assessment: device-level ciphersuite ratings
6. Output: tls_timeline.csv, tls_risk_report.csv
```

**Output Files**:
- `analysis_output/tls_evolution.csv`
- `analysis_output/tls_ciphers_by_device.csv`
- `analysis_output/tls_risk_assessment.pdf`

---

### 🟡 **Experiment 3: Encrypted vs Unencrypted Payload Ratio Analysis**

**Goal**: Quantify what percentage of update traffic is encrypted vs plaintext

**Current State**: Scripts exist but not integrated into full pipeline

**Implementation**:
```
Create payload_encryption_analysis.py that:
1. Process all entropy CSVs
2. Classify packets as encrypted/unencrypted/omitted
3. Calculate encryption coverage percentage per device
4. Identify unencrypted payload types (firmware, metadata, etc.)
5. Risk ranking by device encryption
6. Output: encryption_coverage_report.csv
```

**Output Files**:
- `analysis_output/encryption_coverage.csv`
- `analysis_output/encrypted_vs_unencrypted.pdf`

---

### 🟡 **Experiment 4: Vulnerability-to-Update Correlation Analysis**

**Goal**: Connect CVE timelines to update traffic patterns

**Current State**: CVE data exists but not linked to update traffic

**Implementation**:
```
Create vulnerability_correlation.py that:
1. Parse all_base.csv for CVE dates and CVSS scores
2. Map devices to applicable CVEs (based on vendor)
3. Extract update traffic timestamps from PCAP filenames
4. Correlation analysis: Do vulnerable devices update faster?
5. CVSS severity vs update packet sizes
6. Output: vulnerability_update_correlation.csv
```

**Output Files**:
- `analysis_output/cve_update_correlation.csv`
- `analysis_output/vulnerability_patterns.pdf`

---

### 🟢 **Experiment 5: Network Flow Fingerprinting by Device & Update Type**

**Goal**: Machine learning model to identify device & operation from traffic

**Current State**: Code exists in intl-iot/model but not applied to update traffic

**Implementation**:
```
Create update_traffic_ml_classifier.py that:
1. Use stream sizes, entropy metrics, ciphersuite data as features
2. Train ML models (Random Forest, KNN) per device
3. Cross-validate on held-out update sequences
4. Feature importance analysis
5. Visualize confusion matrices and ROC curves
6. Output: Classification accuracy, feature importance
```

**Output Files**:
- `analysis_output/ml_classification_report.csv`
- `analysis_output/feature_importance.pdf`
- `analysis_output/confusion_matrices.pdf`

---

### 🟢 **Experiment 6: Firmware Binary Analysis (Size & Entropy Correlation)**

**Goal**: Analyze firmware characteristics vs network traffic entropy

**Current State**: Firmware extracted but not analyzed

**Implementation**:
```
Create firmware_analysis.py that:
1. Calculate entropy of firmware binaries themselves
2. Compare with network entropy during transmission
3. Identify compression/encryption in firmware updates
4. File type analysis (ELF, image, script signatures)
5. Correlation: Firmware entropy vs network payload entropy
6. Output: firmware_analysis.csv
```

**Requires**: `python-magic` library and binary analysis tools

---

### 🟢 **Experiment 7: Geolocation-Based Update Analysis**

**Goal**: Does update traffic differ by geographic region or VPN usage?

**Current State**: imc19_dataset has regions (uk, us, uk-vpn, us-vpn)

**Implementation**:
```
Create geo_update_analysis.py that:
1. Process both imc19_dataset and controlled dataset
2. Extract region from file paths
3. Compare entropy, stream sizes, cipher suites across regions
4. Statistical testing for regional differences
5. VPN impact analysis on encryption/ciphersuite
6. Output: regional_differences.csv
```

**Output Files**:
- `analysis_output/geographic_analysis.csv`
- `analysis_output/vpn_impact.pdf`

---

### ⏳ **Experiment 8: Firmware Update Sequence Analysis (Advanced)**

**Goal**: Identify update ceremony patterns across devices

**This requires**: More detailed packet-level analysis and reverse engineering

**Implementation**:
```
Create update_ceremony_analyzer.py that:
1. Time-series clustering on entropy metrics
2. Identify distinct phases of update process
3. Measure phase durations and consistency
4. Detect anomalies in expected update patterns
5. Compare update ceremonies across device brands
6. Output: update_sequences.json with phase annotations
```

---

## Recommended Implementation Order

1. **Start with Experiment 1** (Easy, high value) - Cross-device comparison
2. **Then Experiment 3** (Medium) - Encryption coverage analysis  
3. **Then Experiment 2** (Medium) - TLS evolution analysis
4. **Then Experiment 5** (Medium, requires ML) - Network fingerprinting
5. **Then Experiment 4** (Hard) - CVE correlation needs careful mapping
6. **Advanced**: Experiments 6, 7, 8 as time permits

---

## File Organization Needed

Create these directories:
```
analysis_output/                          # All analysis outputs
├── figures/                              # PDF plots, PNGs
├── data/                                 # CSV results
└── notebooks/                            # Jupyter notebooks

src/
├── experiments/                          # New experiment scripts
│   ├── entropy_comparison.py
│   ├── tls_evolution_analysis.py
│   ├── encryption_coverage.py
│   ├── vulnerability_correlation.py
│   └── ...
└── utils/                                # Helper functions
    ├── pcap_processor.py
    ├── data_aggregator.py
    └── visualization_helpers.py
```

---

## Dependencies to Check/Install

```
pandas                # Data manipulation
seaborn              # Statistical visualization  
matplotlib           # Plotting
numpy                # Numerical analysis
scapy                # Packet analysis
scikit-learn         # Machine learning
dpkt                 # Protocol parsing
magic                # File type detection (for firmware analysis)
pyshark              # Wireshark interface
```

---

## Next Steps

1. **Clone/Setup**: Ensure virtual environment with requirements.txt
2. **Choose an experiment**: Start with #1 (Entropy Comparison)
3. **Data exploration**: Run sample analysis on 1-2 devices first
4. **Scaling**: Apply pipeline to all devices
5. **Visualization**: Generate publication-quality figures
6. **Documentation**: Update README with findings

Would you like me to help implement any of these experiments?
