#!/usr/bin/env python3
"""
Fetch attack data for a specific day from Elasticsearch
Returns list of (IP, attack_count) tuples for that day
"""

from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
from typing import List, Tuple, Optional
import os


def load_env_file(path: Optional[str] = None) -> None:
    """Load KEY=VALUE pairs from a .env file without overriding existing env vars."""
    if path is None:
        path = os.path.join(os.path.dirname(__file__), ".env")

    if not os.path.exists(path):
        return

    with open(path, "r", encoding="utf-8") as env_file:
        for raw_line in env_file:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def required_env(name: str) -> str:
    """Read a required environment variable."""
    value = os.getenv(name)
    if value is None or not value.strip():
        raise RuntimeError(
            f"Missing required environment variable: {name}. "
            "Set it in your .env file."
        )
    return value


def env_bool(name: str, default: bool) -> bool:
    """Parse boolean from environment variable."""
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    """Parse integer from environment variable with fallback."""
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


# Load .env before reading config values
load_env_file()

# Elasticsearch Configuration
ES_CONFIG = {
    "host": required_env("ES_HOST"),
    "api_key": required_env("ES_API_KEY"),
    "verify_certs": env_bool("ES_VERIFY_CERTS", False),
    "headers": {
        "Accept": os.getenv(
            "ES_ACCEPT_HEADER",
            "application/vnd.elasticsearch+json; compatible-with=8"
        )
    },
}

QUERY_CONFIG = {
    "index": os.getenv("ES_INDEX", "logstash-*"),
    "type": os.getenv("ES_TYPE", "Cowrie"),
    "exclude_regex": os.getenv("ES_EXCLUDE_REGEX", "139\\.91\\..*"),  # Exclude internal IPs
    "max_results": env_int("ES_MAX_RESULTS", 10000),
}


def fetch_attacks_for_day(date_str: str) -> List[Tuple[str, int]]:
    """
    Fetch attack data for a specific day

    Args:
        date_str: Date in format YYYY-MM-DD (e.g., "2025-01-15")

    Returns:
        List of (IP address, attack_count) tuples for that day
        Example: [("192.168.1.1", 100), ("10.0.0.1", 50), ...]

    Raises:
        ValueError: If date format is invalid
        Exception: If Elasticsearch query fails
    """

    # Validate and parse date
    try:
        target_date = datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        raise ValueError(f"Invalid date format: {date_str}. Use YYYY-MM-DD")

    # Create time range for the entire day (00:00:00 to 23:59:59)
    start_time = target_date.strftime("%Y-%m-%dT00:00:00")
    end_time = (target_date + timedelta(days=1)).strftime("%Y-%m-%dT00:00:00")

    # Connect to Elasticsearch
    client = Elasticsearch(
        ES_CONFIG["host"],
        api_key=ES_CONFIG["api_key"],
        verify_certs=ES_CONFIG["verify_certs"],
        headers=ES_CONFIG["headers"]
    )

    # Build query: fetch Cowrie attacks, exclude internal IPs, aggregate by source IP
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"match": {"type": QUERY_CONFIG["type"]}}
                ],
                "filter": [
                    {"range": {"@timestamp": {"gte": start_time, "lt": end_time}}},
                ],
                "must_not": [
                    {"regexp": {"src_ip": QUERY_CONFIG["exclude_regex"]}},
                ],
            }
        },
        "aggs": {
            "attacking_ips": {
                "terms": {
                    "field": "src_ip",
                    "size": QUERY_CONFIG["max_results"],
                    "order": {"_count": "desc"},
                }
            }
        },
    }

    # Execute query
    try:
        response = client.search(index=QUERY_CONFIG["index"], body=query)
    except Exception as e:
        raise Exception(f"Elasticsearch query failed: {str(e)}")

    # Extract results: list of (IP, count) tuples
    attack_data = []
    for bucket in response['aggregations']['attacking_ips']['buckets']:
        ip_address = bucket['key']
        attack_count = bucket['doc_count']
        attack_data.append((ip_address, attack_count))

    return attack_data


# For testing this module standalone
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 fetch_day_attacks.py YYYY-MM-DD")
        print("Example: python3 fetch_day_attacks.py 2025-01-15")
        sys.exit(1)

    date = sys.argv[1]

    try:
        print(f"Fetching attacks for {date}...")
        data = fetch_attacks_for_day(date)

        print(f"\nFound {len(data)} attacking IPs")
        print(f"Total attacks: {sum(count for _, count in data)}")

        if data:
            print(f"\nTop 5 attackers:")
            for i, (ip, count) in enumerate(data[:5], 1):
                print(f"  {i}. {ip}: {count} attacks")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
