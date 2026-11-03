# CTI STIX/TAXII → Splunk

Turns threat intelligence into Splunk detections:

- pulls STIX 2.1 objects from a **TAXII 2.1** collection (or reads a bundle file);
- keeps active indicators only (drops `revoked` and expired `valid_until`);
- extracts IPv4/IPv6, domains, URLs and file hashes from STIX patterns;
- follows `indicates` relationships to tag each IOC with its **MITRE ATT&CK** technique;
- writes a Splunk lookup (`cti_iocs.csv`) used by detection
  [DET-0009](https://github.com/Jka667/splunk-detection-as-code/blob/main/detections/DET-0009_cti_ioc_match.yml).

No dependencies beyond the Python 3.11+ standard library.

## Why it matters for a business

| Problem | What this tool brings |
|---------|-----------------------|
| Threat intel is bought or shared but never reaches the SIEM | IOCs from any TAXII 2.1 feed (OpenCTI, MISP, ISAC, vendor) become a Splunk detection automatically, every day |
| Stale IOCs flood analysts with false positives | Revoked and expired indicators are dropped before they reach Splunk |
| Alerts say "bad IP" with no context | Each match carries its source, STIX ID and ATT&CK technique, so IR can triage faster |
| Vendor lock-in for CTI integration | Standard-library Python, open standards (STIX/TAXII): no licence cost, easy to audit |

Result: the CTI budget turns into real detections, with less noise and faster triage.

## Usage

```bash
python stix_to_splunk.py --bundle samples/sample_bundle.json -o cti_iocs.csv
python stix_to_splunk.py --taxii https://<server>/<api-root> --collection <collection-id> -o cti_iocs.csv
pytest
```

Deploy: copy `cti_iocs.csv` to `$SPLUNK_HOME/etc/apps/<app>/lookups/` and `splunk/transforms.conf`
to `<app>/local/`. Schedule the script (cron / Task Scheduler) to refresh the lookup daily.

Test TAXII servers: a local [OpenCTI](https://github.com/OpenCTI-Platform/opencti) or MISP instance both expose TAXII 2.1.

## Output

| indicator | type | stix_id | name | ioc_source | mitre | valid_until |
|-----------|------|---------|------|------------|-------|-------------|
| update-check.example | domain-name | indicator--8e2e… | Sample C2 domain | Sample CTI Team | T1071.001 | |

## Narrative reports

For intel that is not structured, see [docs/narrative-report-to-detection.md](docs/narrative-report-to-detection.md).
