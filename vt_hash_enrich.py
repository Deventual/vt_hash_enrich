# -*- coding: utf-8 -*-

import requests
import csv
import argparse
import yaml
from datetime import datetime
from hashid import HashID


__author__ = "Eyal Cohen"
__version__ = "0.1"
__date__ = "August 2023"
__description__ = """
    VirusTotal API Enrichment Tool.
    This script accepts a plain text file containing multiple hashes, 
    each representing a potential malware file. 
    For each hash, the script queries the VirusTotal API and produces enriched hash data based on settings in the config.yaml file. 
    Multiple output formats are supported by the tool: type per line (csv) | indicator per line (csv) | hash per line (plain text).
"""


class Configuration:
    def __init__(self, config_path="config.yaml"):
        with open(config_path, "r") as yamlfile:
            cfg = yaml.safe_load(yamlfile)

        self.VT_API_KEY = cfg["vt_api_key"]
        self.hash_types_for_enrichment = cfg["hash_types_for_enrichment"]
        self.fields_type_mode = cfg["fields_type_mode"]
        self.fields_indicator_mode = cfg["fields_indicator_mode"]
        self.fields_max_mode = cfg["fields_indicator_max_mode"]
        self.nested_attributes = cfg.get("nested_attributes", {})


class HashEnricher:
    def __init__(self, config):
        self.config = config

    def determine_hash_type(self, hash_value):
        hashid = HashID()
        hash_types = hashid.identifyHash(hash_value)

        for hash_type in hash_types:
            if hash_type.name.lower() in self.config.hash_types_for_enrichment:
                return hash_type.name.lower()
        return None

    def query_hash_vt_api(self, hash_value):
        vt_api_endpoint = "https://www.virustotal.com/api/v3/files/"
        headers = {"x-apikey": self.config.VT_API_KEY}
        return requests.get(vt_api_endpoint + hash_value, headers=headers)

    def extract_attributes_from_response(self, response):
        if response.status_code == 200:
            data = response.json()
            return data["data"]["attributes"]
        return None

    def format_output(self, attributes, output_format, fields_to_enrich, hash_value):
        vt_score = self.calculate_vt_score(attributes)
        threat_label = attributes.get("popular_threat_classification", {}).get(
            "suggested_threat_label", "Unknown"
        )
        print(
            f"+ Hash present in VT: {hash_value} | score: {vt_score} | {threat_label}"
        )

        if output_format == "type":
            return self._format_output_type(attributes)
        elif output_format == "text":
            return self._format_output_text(attributes)
        else:
            return self._format_output_generic(attributes, fields_to_enrich)

    def _format_output_type(self, attributes):
        threat_label = attributes.get("popular_threat_classification", {}).get(
            "suggested_threat_label", "Unknown"
        )
        file_name = (
            attributes.get("names", [])[0] if attributes.get("names") else "Unknown"
        )
        return [
            {
                "type": "sha256",
                "value": attributes.get("sha256", ""),
                "threat_label": threat_label,
                "file_name": file_name,
            },
            {
                "type": "sha1",
                "value": attributes.get("sha1", ""),
                "threat_label": threat_label,
                "file_name": file_name,
            },
            {
                "type": "md5",
                "value": attributes.get("md5", ""),
                "threat_label": threat_label,
                "file_name": file_name,
            },
        ]

    def _format_output_text(self, attributes):
        return [
            attributes.get("sha256", ""),
            attributes.get("sha1", ""),
            attributes.get("md5", ""),
        ]

    def _format_output_generic(self, attributes, fields_to_enrich):
        enriched_item = {}
        for field in fields_to_enrich:
            if field in self.config.nested_attributes:
                path = self.config.nested_attributes[field]
                enriched_item[field] = self.get_nested_attribute(attributes, path)
            elif field == "vt_score":
                enriched_item[field] = self.calculate_vt_score(attributes)
            else:
                enriched_item[field] = attributes.get(field, "")
            if field.endswith("_date") and isinstance(
                enriched_item[field], (int, float)
            ):
                enriched_item[field] = self.convert_epoch_time(enriched_item[field])
        return [enriched_item]

    def enrich_hashes(self, input_file, output_file, output_format):
        hashes_to_enrich = set()
        with open(input_file, "r") as f:
            for line in f:
                hashes_to_enrich.add(line.strip())

        enriched_data_list = []

        if output_format in ["type", "text"]:
            fields_to_enrich = self.config.hash_types_for_enrichment
        elif output_format == "indicator":
            fields_to_enrich = self.config.fields_indicator_mode
        elif output_format == "max":
            fields_to_enrich = self.config.fields_max_mode
        else:
            fields_to_enrich = []

        for hash_value in hashes_to_enrich:
            attributes = self.extract_attributes_from_response(
                self.query_hash_vt_api(hash_value)
            )
            if attributes:
                enriched_data = self.format_output(
                    attributes, output_format, fields_to_enrich, hash_value
                )
                enriched_data_list.extend(enriched_data)
            else:
                print(f"- Hash not found in VT: {hash_value}")

        self.write_results_to_file(enriched_data_list, output_file, output_format)

    def write_results_to_file(self, enriched_data, output_file, output_format):
        with open(output_file, "w", newline="") as f:
            writer = csv.writer(f)
            if output_format in ["indicator", "max", "type"]:
                headers = list(enriched_data[0].keys())
                writer.writerow(headers)
                for data_row in enriched_data:
                    writer.writerow(data_row.values())
            elif output_format == "text":
                for entry in enriched_data:
                    f.write(f"{entry}\n")

    @staticmethod
    def get_nested_attribute(attributes, path):
        for key in path:
            if isinstance(attributes, list):
                attributes = attributes[int(key)]
            else:
                attributes = attributes.get(key, {})
        return attributes

    def calculate_vt_score(self, attributes):
        malicious_score = attributes["last_analysis_stats"]["malicious"]
        if malicious_score > 0:
            categories = attributes["last_analysis_stats"]
            sum_engines = sum(int(categories[category]) for category in categories)
            return f"{malicious_score}/{sum_engines}"
        return None

    @staticmethod
    def convert_epoch_time(epoch_date):
        return datetime.strftime(datetime.utcfromtimestamp(epoch_date), "%d-%m-%Y")


def main():
    parser = argparse.ArgumentParser(description="Enrich hashes using VirusTotal API")
    parser.add_argument(
        "-i", "--input", required=True, help="Plain text input file containing hashes"
    )
    parser.add_argument(
        "-o", "--output", required=True, help="Output file name for enriched hashes"
    )
    parser.add_argument(
        "-f",
        "--format",
        required=True,
        choices=["type", "indicator", "max", "text"],
        help="Formats of output: "
        "type - type per line (csv) | "
        "indicator - indicator per line (csv) | "
        "max - maximum context indicator per line (csv) | "
        "text - hash per line (plain text)",
    )

    args = parser.parse_args()
    config = Configuration()
    enricher = HashEnricher(config)
    enricher.enrich_hashes(args.input, args.output, args.format.lower())


if __name__ == "__main__":
    main()
