import os
import json
import glob
from pathlib import Path
import csv

def extract_cve_cwe_info(json_file_path):
    """
    Extract CVE ID and CWE IDs from a CVE JSON file.
    
    Args:
        json_file_path (str): Path to the CVE JSON file
        
    Returns:
        tuple: (cve_id, list of cwe_ids)
    """
    try:
        with open(json_file_path, 'r') as file:
            data = json.load(file)
        
        # Extract CVE ID
        cve_id = data.get('cveMetadata', {}).get('cveId', 'Unknown')
        
        # Extract CWE IDs
        cwe_ids = []
        
        # Navigate to the problemTypes section in the CNA container
        problem_types = data.get('containers', {}).get('cna', {}).get('problemTypes', [])
        
        for problem_type in problem_types:
            descriptions = problem_type.get('descriptions', [])
            for description in descriptions:
                if 'cweId' in description:
                    cwe_ids.append(description['cweId'])
        
        return cve_id, cwe_ids
    
    except Exception as e:
        print(f"Error processing {json_file_path}: {str(e)}")
        return None, []

def process_cve_files(base_directory):
    """
    Process all CVE JSON files in the given directory structure.
    
    Args:
        base_directory (str): Base directory containing CVE files
        
    Returns:
        list: List of tuples (cve_id, cwe_ids)
    """
    results = []
    
    # Use glob to find all JSON files in the directory structure
    pattern = os.path.join(base_directory, "**", "*.json")
    for json_file in glob.glob(pattern, recursive=True):
        cve_id, cwe_ids = extract_cve_cwe_info(json_file)
        if cve_id:
            results.append((cve_id, cwe_ids))
            print(f"Processed: {cve_id} - CWE IDs: {', '.join(cwe_ids) if cwe_ids else 'None'}")
    
    return results

def main():
    # Base directory containing CVE files
    base_dir = "../cvelistV5/cves"
    
    # Process all CVE files
    print(f"Searching for CVE files in {base_dir}...")
    results = process_cve_files(base_dir)
    
    # Print summary
    print("\nSummary:")
    print(f"Total CVEs processed: {len(results)}")
    
    # Write results to a CSV file
    output_file = "./data_out/cve_cwe_mapping.csv"
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["CVE ID", "CWE IDs"])
        
        for cve_id, cwe_ids in results:
            writer.writerow([cve_id, ', '.join(cwe_ids)])
    
    print(f"Results written to {output_file}")

if __name__ == "__main__":
    main()