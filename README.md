# vt_hash_enrich
Script to retrieve and enrich hash-based IoCs using the VirusTotal API.

   VirusTotal API Enrichment Tool.
    This script accepts a plain text file containing multiple hashes, 
    each representing a potential malware file. 
    For each hash, the script queries the VirusTotal API and produces enriched hash data based on settings in the config.yaml file. 
    Multiple output formats are supported by the tool: type per line (csv) | indicator per line (csv) | hash per line (plain text).
