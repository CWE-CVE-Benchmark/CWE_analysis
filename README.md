

## get_nvd_data.sh

usage: get_nvd_data.sh

creates a jsondata dir

Output: data_out/CVSSData.csv.gz

## get_1003_view.sh

Gets data_in/1003.csv the CWE-1003 view of CWEs

## cwe_over_time.py 


input: 
    data_out/CVSSData.csv.gz
    data_in/1003.csv

usage: python ./cwe_over_time.py 

creates various png plots.