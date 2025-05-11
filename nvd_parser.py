import datetime
from datetime import date
import glob
import json
import logging
import numpy as np
import pandas as pd
import warnings
import csv


# Build Base DataFrame
# This code builds a Panda dataframe from the JSON files we downloaded, removing all CVE's marked rejected.

row_accumulator = []
for filename in glob.glob('jsondata/nvdcve-1.1-*.json'):

    with open(filename, 'r', encoding='utf-8') as f:
        nvd_data = json.load(f)
        for entry in nvd_data['CVE_Items']:
            cve = entry['cve']['CVE_data_meta']['ID']
            try:
                published_date = entry['publishedDate']
            except KeyError:
                published_date = 'Missing_Data'
            try:
                description = entry['cve']['description']['description_data'][0]['value']
            except IndexError:
                description = ''
            try:
                attack_vector_v3 = entry['impact']['baseMetricV3']['cvssV3']['attackVector']
            except KeyError:
                attack_vector_v3 = 'Missing_Data'
            try:
                attack_complexity_v3 = entry['impact']['baseMetricV3']['cvssV3']['attackComplexity']
            except KeyError:
                attack_complexity_v3 = 'Missing_Data'
            try:
                privileges_required_v3 = entry['impact']['baseMetricV3']['cvssV3']['privilegesRequired']
            except KeyError:
                privileges_required_v3 = 'Missing_Data'
            try:
                user_interaction_v3 = entry['impact']['baseMetricV3']['cvssV3']['userInteraction']
            except KeyError:
                user_interaction_v3 = 'Missing_Data'
            try:
                scope_v3 = entry['impact']['baseMetricV3']['cvssV3']['scope']
            except KeyError:
                scope_v3 = 'Missing_Data'
            try:
                confidentiality_impact_v3 = entry['impact']['baseMetricV3']['cvssV3']['confidentialityImpact']
            except KeyError:
                confidentiality_impact_v3 = 'Missing_Data'
            try:
                integrity_impact_v3 = entry['impact']['baseMetricV3']['cvssV3']['integrityImpact']
            except KeyError:
                integrity_impact_v3 = 'Missing_Data'
            try:
                availability_impact_v3 = entry['impact']['baseMetricV3']['cvssV3']['availabilityImpact']
            except KeyError:
                availability_impact_v3 = 'Missing_Data'
            try:
                base_score_v3 = entry['impact']['baseMetricV3']['cvssV3']['baseScore']
            except KeyError:
                base_score_v3 = '0.0'
            try:
                base_severity_v3 = entry['impact']['baseMetricV3']['cvssV3']['baseSeverity']
            except KeyError:
                base_severity_v3 = 'Missing_Data'
            try:
                exploitability_score_v3 = entry['impact']['baseMetricV3']['exploitabilityScore']
            except KeyError:
                exploitability_score_v3 = '0.0'
            try:
                impact_score_v3 = entry['impact']['baseMetricV3']['impactScore']
            except KeyError:
                impact_score_v3 = '0.0'
            try:
                access_vector_v2 = entry['impact']['baseMetricV2']['cvssV2']['accessVector']
            except KeyError:
                access_vector_v2 = 'Missing_Data'
            try:
                access_complexity_v2 = entry['impact']['baseMetricV2']['cvssV2']['accessComplexity']
            except KeyError:
                access_complexity_v2 = 'Missing_Data'
            try:
                authentication_v2 = entry['impact']['baseMetricV2']['cvssV2']['authentication']
            except KeyError:
                authentication_v2 = 'Missing_Data'
            try:
                confidentiality_impact_v2 = entry['impact']['baseMetricV2']['cvssV2']['confidentialityImpact']
            except KeyError:
                confidentiality_impact_v2 = 'Missing_Data'
            try:
                integrity_impact_v2 = entry['impact']['baseMetricV2']['cvssV2']['integrityImpact']
            except KeyError:
                integrity_impact_v2 = 'Missing_Data'
            try:
                availability_impact_v2 = entry['impact']['baseMetricV2']['cvssV2']['availabilityImpact']
            except KeyError:
                availability_impact_v2 = 'Missing_Data'
            try:
                base_score_v2 = entry['impact']['baseMetricV2']['cvssV2']['baseScore']
            except KeyError:
                base_score_v2 = '0.0'
            try:
                base_severity_v2 = entry['impact']['baseMetricV2']['cvssV2']['severity']
            except KeyError:
                base_severity_v2 = 'Missing_Data'
            try:
                exploitability_score_v2 = entry['impact']['baseMetricV2']['exploitabilityScore']
            except KeyError:
                exploitability_score_v2 = '0.0'
            try:
                impact_score_v2 = entry['impact']['baseMetricV2']['impactScore']
            except KeyError:
                impact_score_v2 = '0.0'
            try:
                #some CVEs have more than one CWE e.g. CVE-2023-0058
                cwe_values = [desc['value'] for desc in entry['cve']['problemtype']['problemtype_data'][0]['description']]
            except KeyError:
                cwe_values = 'Missing_Data'
            new_row = { 
                'CVE': cve, 
                'Published': published_date,
                'Description': description,
                #'AttackVector CVSS3': attack_vector_v3,
                #'AttackComplexity CVSS3': attack_complexity_v3,
                #'PrivilegesRequired CVSS3': privileges_required_v3,
                #'UserInteraction CVSS3': user_interaction_v3,
                #'Scope CVSS3': scope_v3,
                #'ConfidentialityImpact CVSS3': confidentiality_impact_v3,
                #'IntegrityImpact CVSS3': integrity_impact_v3,
                #'AvailabilityImpact CVSS3': availability_impact_v3,
                #'BaseScore CVSS3': base_score_v3,
                #'BaseSeverity CVSS3': base_severity_v3,
                #'ExploitabilityScore CVSS3': exploitability_score_v3,
                #'ImpactScore CVSS3': impact_score_v3,
                #'AccessVector CVSS2': access_vector_v2,
                #'AccessComplexity CVSS2': access_complexity_v2,
                #'Authentication CVSS2': authentication_v2,
                #'ConfidentialityImpact CVSS2': confidentiality_impact_v2,
                #'IntegrityImpact CVSS2': integrity_impact_v2,
                #'AvailabilityImpact CVSS2': availability_impact_v2,
                #'BaseScore CVSS2': base_score_v2,
                #'BaseSeverity CVSS2': base_severity_v2,
                #'ExploitabilityScore CVSS2': exploitability_score_v2,
                #'ImpactScore CVSS2': impact_score_v2,
                'CWEs': cwe_values
            }
            if not (description.startswith('** REJECT **') | (description.startswith('Rejected reason:'))): # disputed, rejected and other non issues start with
                row_accumulator.append(new_row)
        nvd = pd.DataFrame(row_accumulator)

# Example Rejected reasons:
#  Rejected reason: DO NOT USE THIS CANDIDATE NUMBER
#  Rejected reason: This candidate is unused by its CNA.     


nvd['Published'] = pd.to_datetime(nvd['Published'])
nvd = nvd.sort_values(by=['Published'])
nvd = nvd.reset_index(drop=True)
nvd['Published'] = pd.to_datetime(nvd['Published']).apply(lambda x: x.date())


# Export to CSV
nvd.to_csv('./data_out/CVSSData.csv.gz', index=False, quoting=csv.QUOTE_ALL, escapechar='\\', compression='gzip')