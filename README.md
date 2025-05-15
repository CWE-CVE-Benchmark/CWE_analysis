# CWE-CVE Analysis Tools

This repository provides a set of tools for analyzing Common Weakness Enumeration (CWE) data in relation to Common Vulnerabilities and Exposures (CVE) records over time.

It is licensed under the CC-BY-SA-4.0 license.

## Tools Overview

### get_nvd_data.sh

Downloads CVE data from the National Vulnerability Database (NVD) and organizes it by year.

**Usage:**
```
./get_nvd_data.sh
```

**Output:**
- `jsondata/*.json` - Raw JSON files containing CVE data organized by year

### nvd_parser.py

Parses the downloaded JSON files to extract CVE information into a structured CSV format.

**Input:**
- `jsondata/*.json` - JSON files downloaded by `get_nvd_data.sh`

**Output:**
- `data_out/CVSSData.csv.gz` - Compressed CSV file containing parsed CVE data with CWE mappings

### get_1003_view.sh

Downloads the MITRE CWE-1003 view, which provides a hierarchical categorization of software weaknesses.

**Output:**
- `data_in/1003.csv` - CSV file containing the CWE-1003 view data

### cwe_over_time.py

Analyzes and visualizes the relationships between CVEs and CWEs over time, with a focus on the CWE-1003 view.

**Input:**
- `data_out/CVSSData.csv.gz` - Processed CVE data
- `data_in/1003.csv` - CWE-1003 view data

**Usage:**
```
python ./cwe_over_time.py
```

**Output:**
Multiple visualization files:
- `cve_cwe_cumulative_distribution.png` - Stacked area chart showing the cumulative distribution of CVE categories over time
- `cve_cwe_distribution_bar.png` - Stacked bar chart showing the annual distribution of CVE categories
- `cve_cwe_percentage_distribution.png` - Stacked area chart showing the percentage distribution of CVE categories over time
- `top_standard_cwes_stacked.png` - Stacked area chart of the top standard CWEs by frequency
- `top_standard_cwes_stacked_log_scale.png` - Logarithmic scale stacked area chart of top standard CWEs 
- `top_standard_cwes_percentage_stacked.png` - Percentage stacked area chart of top standard CWEs

## Visualization Categories

The visualizations categorize CVEs based on their CWE assignments:
- **In CWE-1003**: CVEs with at least one CWE that appears in the CWE-1003 view
- **Not in CWE-1003**: CVEs with standard CWEs, but none are part of the CWE-1003 view
- **NVD-CWE-Other**: CVEs assigned the generic "NVD-CWE-Other" value
- **NVD-CWE-noinfo**: CVEs assigned the "NVD-CWE-noinfo" value
- **Other Non-Standard CWE**: CVEs with non-standard CWE values
- **No CWE**: CVEs with no CWE assignments

The script also generates detailed statistics about:
- Total CVE counts by category
- CWE-1003 coverage by year
- Top standard CWEs by frequency

### cve_parser.py

Extracts CWE IDs directly from the official CVE Project's cvelistV5 repository, which contains the latest CVE data in JSON format.

**Note:**
The CVEProject/cvelistV5 repository does not always contain all CWE information that is available in the NVD database. For example:
1. https://nvd.nist.gov/vuln/detail/CVE-2017-16887 has CWEs
2. https://github.com/CVEProject/cvelistV5/blob/main/cves/2017/16xxx/CVE-2017-16887.json does not have CWEs

**Prerequisites:**
Clone the cvelistV5 repository to the same parent directory as this repository:
```bash
git clone git@github.com:CVEProject/cvelistV5.git
```

**Usage:**
```bash
python ./cve_parser.py
```

**Input:**
- `../cvelistV5/cves` - Directory containing CVE JSON files from the cvelistV5 repository

**Output:**
- `data_out/cve_cwe_mapping.csv` - CSV file mapping CVE IDs to their associated CWE IDs

This script complements the NVD data by providing direct access to the CWE information as recorded in the official CVE repository, allowing for comparison and more comprehensive analysis.