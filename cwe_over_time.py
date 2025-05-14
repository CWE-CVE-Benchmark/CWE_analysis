import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import gzip
import io
import ast
import os
import re
import csv
from pathlib import Path
from collections import Counter

def read_gzipped_csv(filepath):
    """Read a gzipped CSV file into a pandas DataFrame."""
    with gzip.open(filepath, 'rb') as f:
        content = f.read()
    return pd.read_csv(io.BytesIO(content))

def extract_year_from_cve(cve_id):
    """Extract the year from a CVE ID (e.g., CVE-2021-12345 -> 2021)."""
    match = re.match(r'CVE-(\d{4})-\d+', cve_id)
    if match:
        return int(match.group(1))
    return None

def main():
    # File paths
    cwe_1003_path = Path('data_in/1003.csv')
    cvss_data_path = Path('data_out/CVSSData.csv.gz')
    
    # Check if files exist
    if not cwe_1003_path.exists():
        print(f"Error: File not found at {cwe_1003_path}")
        return
    if not cvss_data_path.exists():
        print(f"Error: File not found at {cvss_data_path}")
        return
    
    print("Reading CWE-1003 data...")
    # Read the CWE-1003 file to get the list of CWEs in that view
    cwe_1003_ids = set()
    
    # Now read the file and extract the CWE IDs
    with open(cwe_1003_path, 'r', encoding='utf-8') as f:
        csv_reader = csv.reader(f)
        header = next(csv_reader)  # Skip header row
        
        # Find the column index for CWE-ID
        cwe_id_index = header.index('CWE-ID') if 'CWE-ID' in header else 0
        
        # Read CWE IDs from the file
        for row in csv_reader:
            if row:  # Make sure the row is not empty
                try:
                    cwe_id = row[cwe_id_index].strip()
                    # Remove 'CWE-' prefix if present
                    if cwe_id.startswith('CWE-'):
                        cwe_id = cwe_id[4:]
                    cwe_1003_ids.add(cwe_id)
                except IndexError:
                    print(f"Warning: Skipping row due to index error: {row}")
    
    # Ensure CWE-119 is explicitly included
    if '119' not in cwe_1003_ids:
        print("Warning: CWE-119 was not found in the original file. Adding it explicitly.")
        cwe_1003_ids.add('119')
    
    print(f"Found {len(cwe_1003_ids)} CWE IDs in the 1003 view")
    
    print("Reading CVSS data...")
    # Read the CVSS data
    cvss_df = read_gzipped_csv(cvss_data_path)
    print(f"Found {len(cvss_df)} CVE entries")
    
    # Extract year from CVE ID 
    cvss_df['Year'] = cvss_df['CVE'].apply(extract_year_from_cve)
    
    # Check for any CVEs where year couldn't be extracted
    invalid_cves = cvss_df[cvss_df['Year'].isna()]
    if not invalid_cves.empty:
        print(f"Warning: Could not extract year from {len(invalid_cves)} CVE IDs.")
        # Drop rows with invalid years
        cvss_df = cvss_df.dropna(subset=['Year'])
    
    # Convert Year to integer
    cvss_df['Year'] = cvss_df['Year'].astype(int)
    
    # Parse the CWEs column from string representation of a list to actual list
    def parse_cwe_list(cwe_str):
        try:
            if isinstance(cwe_str, str):
                cwe_list = ast.literal_eval(cwe_str)
                return cwe_list if isinstance(cwe_list, list) else []
            return []
        except:
            print(f"Error parsing CWE string: {cwe_str}")
            return []
    
    cvss_df['CWEsList'] = cvss_df['CWEs'].apply(parse_cwe_list)
    
    # Function to check if a CWE follows the standard pattern
    def is_standard_cwe(cwe_id):
        return isinstance(cwe_id, str) and re.match(r'CWE-\d+$', cwe_id) is not None
    
    # Function to extract the numeric part of a CWE ID
    def extract_cwe_number(cwe_id):
        if isinstance(cwe_id, str) and cwe_id.startswith('CWE-'):
            return cwe_id[4:]
        return cwe_id
    
    # Categorize CVEs
    def categorize_cwe(cwe_list):
        if not cwe_list or cwe_list == ['']:
            return 'No CWE'
        
        # Check for NVD-CWE-noinfo
        if 'NVD-CWE-noinfo' in cwe_list:
            return 'NVD-CWE-noinfo'
        
        # Check for other non-standard CWEs (not "CWE-digits" and not "NVD-CWE-Other")
        has_non_standard = False
        for cwe in cwe_list:
            if cwe != 'NVD-CWE-Other' and not is_standard_cwe(cwe):
                has_non_standard = True
                break
        
        if has_non_standard:
            return 'Other Non-Standard CWE'
        
        # Extract numeric part from each CWE ID
        cwe_numbers = [extract_cwe_number(cwe) for cwe in cwe_list if is_standard_cwe(cwe)]
        
        # Check if any CWE in the list is in the 1003 view
        cwe_in_1003 = [num for num in cwe_numbers if num in cwe_1003_ids]
        
        if cwe_in_1003:  # If there are any CWEs in the 1003 view
            return 'In CWE-1003'
        elif 'NVD-CWE-Other' in cwe_list:
            return 'NVD-CWE-Other'
        else:
            return 'Not in CWE-1003'
    
    cvss_df['Category'] = cvss_df['CWEsList'].apply(categorize_cwe)
    
    # Group by Year and Category, and count
    grouped_data = cvss_df.groupby(['Year', 'Category']).size().unstack(fill_value=0)
    
    # Handle missing categories by ensuring all categories are columns
    all_categories = ['In CWE-1003', 'Not in CWE-1003', 'NVD-CWE-Other', 'NVD-CWE-noinfo', 'Other Non-Standard CWE', 'No CWE']
    for category in all_categories:
        if category not in grouped_data.columns:
            grouped_data[category] = 0
    
    # Sort columns for consistent appearance
    grouped_data = grouped_data[all_categories]
    
    # Define colors for categories
    category_colors = {
        'In CWE-1003': '#4CAF50',           # Green
        'Not in CWE-1003': '#FFC107',       # Yellow
        'NVD-CWE-Other': '#9C27B0',         # Purple
        'NVD-CWE-noinfo': '#2196F3',        # Blue
        'Other Non-Standard CWE': '#03A9F4', # Light Blue
        'No CWE': '#F44336'                 # Red
    }
    
    # Create the stacked area plot (cumulative)
    plt.figure(figsize=(14, 8))
    
    # Extract years as x-axis points
    years = grouped_data.index.tolist()
    
    # Create the stacked area plot - use the color mapping
    plt.stackplot(years, 
                 [grouped_data[cat].values for cat in all_categories],
                 labels=all_categories,
                 colors=[category_colors[cat] for cat in all_categories],
                 alpha=0.8)
    
    # Add labels and title
    plt.xlabel('Year (from CVE ID)', fontsize=12)
    plt.ylabel('Number of CVEs', fontsize=12)
    plt.title('Cumulative Distribution of CVEs by CWE Category Over Time', fontsize=16)
    plt.legend(title='CWE Category', loc='upper left')
    
    # Add grid lines
    plt.grid(linestyle='--', alpha=0.7)
    
    # Set x-axis ticks to show every year or every other year
    if len(years) > 10:
        plt.xticks(years[::2])  # Show every other year
    else:
        plt.xticks(years)  # Show every year
    
    # Ensure y-axis starts at 0
    plt.ylim(bottom=0)
    
    # Add data labels at appropriate intervals
    for i, year in enumerate(years):
        if i % 3 == 0 or i == len(years) - 1:  # Label every 3rd year and the last year
            total = sum(grouped_data.loc[year])
            plt.text(year, total + total * 0.02, f'{total:,}', 
                    ha='center', va='bottom', fontweight='bold')
    
    # Adjust layout
    plt.tight_layout()
    
    # Save the plot
    output_path = 'cve_cwe_cumulative_distribution.png'
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Cumulative plot saved to {output_path}")
    
    # Create a second visualization: stacked bar chart (non-cumulative)
    plt.figure(figsize=(14, 8))
    grouped_data.plot(kind='bar', stacked=True, figsize=(14, 8),
                     color=[category_colors[cat] for cat in all_categories])
    
    # Add labels and title
    plt.xlabel('Year (from CVE ID)', fontsize=12)
    plt.ylabel('Number of CVEs', fontsize=12)
    plt.title('Distribution of CVEs by CWE Category Over Time', fontsize=16)
    plt.legend(title='CWE Category')
    
    # Add grid lines
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Adjust layout
    plt.tight_layout()
    
    # Save the bar plot
    output_bar_path = 'cve_cwe_distribution_bar.png'
    plt.savefig(output_bar_path, dpi=300, bbox_inches='tight')
    print(f"Bar plot saved to {output_bar_path}")
    
    # Create a percentage stacked area chart
    plt.figure(figsize=(14, 8))
    
    # Calculate percentages for each year
    # Convert to float64 first to avoid dtype incompatibility warning
    percentage_data = grouped_data.astype('float64').copy()
    for year in percentage_data.index:
        year_total = percentage_data.loc[year].sum()
        if year_total > 0:
            percentage_data.loc[year] = (percentage_data.loc[year] / year_total) * 100
    
    # Create the percentage stacked area chart
    plt.stackplot(years, 
                 [percentage_data[cat].values for cat in all_categories],
                 labels=all_categories,
                 colors=[category_colors[cat] for cat in all_categories],
                 alpha=0.8)
    
    # Add labels and title
    plt.xlabel('Year (from CVE ID)', fontsize=12)
    plt.ylabel('Percentage of CVEs', fontsize=12)
    plt.title('Percentage Distribution of CVEs by CWE Category Over Time', fontsize=16)
    plt.legend(title='CWE Category', loc='upper left')
    
    # Add grid lines
    plt.grid(linestyle='--', alpha=0.7)
    
    # Set y-axis to percentage range
    plt.ylim(0, 100)
    
    # Adjust layout
    plt.tight_layout()
    
    # Save the percentage plot
    output_percentage_path = 'cve_cwe_percentage_distribution.png'
    plt.savefig(output_percentage_path, dpi=300, bbox_inches='tight')
    print(f"Percentage plot saved to {output_percentage_path}")
    
    # Generate and print statistics about the data
    total_cves = len(cvss_df)
    category_counts = cvss_df['Category'].value_counts()
    
    print("\nSummary Statistics:")
    print(f"Total CVEs: {total_cves}")
    
    for category in all_categories:
        count = category_counts.get(category, 0)
        percentage = (count / total_cves) * 100 if total_cves > 0 else 0
        print(f"CVEs categorized as '{category}': {count} ({percentage:.1f}%)")
    
    # Count CVEs per year to see trends
    yearly_counts = cvss_df['Year'].value_counts().sort_index()
    print("\nCVEs by year (from CVE ID):")
    for year, count in yearly_counts.items():
        print(f"{year}: {count}")
    
    # Print CWE-1003 coverage by year
    print("\nCWE-1003 coverage by year:")
    for year in sorted(yearly_counts.index):
        year_data = grouped_data.loc[year] if year in grouped_data.index else pd.Series({cat: 0 for cat in all_categories})
        total = year_data.sum()
        cwe_1003_count = year_data['In CWE-1003']
        percentage = (cwe_1003_count / total) * 100 if total > 0 else 0
        print(f"{year}: {cwe_1003_count}/{total} ({percentage:.1f}%)")
    
    # Show the plots
    plt.show()

if __name__ == "__main__":
    main()