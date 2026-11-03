"""Convert STIX 2.1 indicators (bundle file or TAXII 2.1 collection) into a Splunk lookup CSV.

Examples:
  python stix_to_splunk.py --bundle samples/sample_bundle.json -o cti_iocs.csv
  python stix_to_splunk.py --taxii https://taxii.example.org/api1 --collection <id> -o cti_iocs.csv
TAXII credentials (optional) are read from TAXII_USER / TAXII_PASSWORD.
"""
import argparse
import base64
import csv
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone

OBSERVABLE = re.compile(r"(ipv4-addr|ipv6-addr|domain-name|url):value\s*=\s*'([^']+)'")
FILE_HASH = re.compile(r"file:hashes\.'?([A-Za-z0-9-]+)'?\s*=\s*'([^']+)'")
FIELDS = ["indicator", "type", "stix_id", "name", "ioc_source", "mitre", "valid_until"]


def fetch_taxii(api_root, collection, user=None, password=None):
    headers = {"Accept": "application/taxii+json;version=2.1"}
    if user:
        headers["Authorization"] = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
    url = f"{api_root.rstrip('/')}/collections/{collection}/objects/"
    objects, next_page = [], None
    while True:
        query = f"?next={urllib.parse.quote(str(next_page))}" if next_page else ""
        with urllib.request.urlopen(urllib.request.Request(url + query, headers=headers), timeout=60) as r:
            envelope = json.load(r)
        objects += envelope.get("objects", [])
        if not envelope.get("more"):
            return objects
        next_page = envelope["next"]


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def to_rows(objects, now=None):
    now = now or datetime.now(timezone.utc)
    by_id = {o["id"]: o for o in objects}

    # indicator -> ATT&CK technique IDs, via "indicates" relationships to attack-patterns
    ttps = {}
    for o in objects:
        if o.get("type") == "relationship" and o.get("relationship_type") == "indicates":
            pattern = by_id.get(o["target_ref"], {})
            ttps.setdefault(o["source_ref"], []).extend(
                r["external_id"] for r in pattern.get("external_references", []) if r.get("source_name") == "mitre-attack")

    rows = []
    for o in objects:
        if o.get("type") != "indicator" or o.get("revoked") or o.get("pattern_type", "stix") != "stix":
            continue
        if o.get("valid_until") and parse_time(o["valid_until"]) < now:
            continue
        observables = OBSERVABLE.findall(o["pattern"]) + [
            (f"file-hash-{algo.lower()}", value) for algo, value in FILE_HASH.findall(o["pattern"])]
        for ioc_type, value in observables:
            rows.append({
                "indicator": value if ioc_type == "url" else value.lower(),
                "type": ioc_type,
                "stix_id": o["id"],
                "name": o.get("name", ""),
                "ioc_source": by_id.get(o.get("created_by_ref"), {}).get("name", "unknown"),
                "mitre": " ".join(sorted(set(ttps.get(o["id"], [])))),
                "valid_until": o.get("valid_until", ""),
            })
    return rows


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--bundle", help="STIX 2.1 bundle JSON file")
    src.add_argument("--taxii", help="TAXII 2.1 API root URL")
    p.add_argument("--collection", help="TAXII collection id (with --taxii)")
    p.add_argument("-o", "--output", default="cti_iocs.csv")
    args = p.parse_args(argv)

    if args.taxii:
        if not args.collection:
            p.error("--collection is required with --taxii")
        objects = fetch_taxii(args.taxii, args.collection, os.environ.get("TAXII_USER"), os.environ.get("TAXII_PASSWORD"))
    else:
        with open(args.bundle, encoding="utf-8") as f:
            objects = json.load(f).get("objects", [])

    rows = to_rows(objects)
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"{len(rows)} indicators written to {args.output} ({len(objects)} STIX objects read)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
