# Get CWEs for CVEs in 

Note: 
CVEProject/cvelistV5 does not have all CWEs e.g.

1. https://nvd.nist.gov/vuln/detail/CVE-2017-16887 has CWEs
2. https://github.com/CVEProject/cvelistV5/blob/main/cves/2017/16xxx/CVE-2017-16887.json does not have CWEs

## Clone cvelistV5 

Clone cvelistV5 to the same top level as CWE_analysis
ls ../cvelistV5

```bash
git clone git@github.com:CVEProject/cvelistV5.git
```

## Run script

```bash
python ./cve_parser.py 
```
Data is output to data_out/cve_cwe_mapping.csv

