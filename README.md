# vt_hash_enrich
Script to retrieve and enrich hash-based IoCs using the VirusTotal API.

   VirusTotal API Enrichment Tool.
    This script accepts a plain text file containing multiple hashes, 
    each representing a potential malware file. 
    For each hash, the script queries the VirusTotal API and produces enriched hash data based on settings in the config.yaml file. 
    Multiple output formats are supported by the tool: type per line (csv) | indicator per line (csv) | hash per line (plain text).


# Install:
   pip install -r requirements.txt

# Configuration:
   Set the VirusTotal API key in the config.yaml file.
   The output fromats are configurable.

# Usage example:
   python3 vt_hash_enrich.py -i IoCs_input_file.txt -f indicator -o results_file.csv

# Usage options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Plain text input file containing hashes
  -o OUTPUT, --output OUTPUT
                        Output file name for enriched hashes
  -f {type,indicator,max,text}, --format {type,indicator,max,text}
                        Formats of output: type - type per line (csv) | indicator - indicator per line (csv) | max - maximum context indicator per line (csv) | text - hash per line (plain text)

