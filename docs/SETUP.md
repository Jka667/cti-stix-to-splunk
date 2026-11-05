# CTI STIX/TAXII → Splunk

Turns threat intelligence into Splunk detections:

- pulls STIX 2.1 objects from a **TAXII 2.1** collection (or reads a bundle file);
- keeps active indicators only (drops `revoked` and expired `valid_until`);
- extracts IPv4/IPv6, domains, URLs and file hashes from STIX patterns;
- follows `indicates` relationships to tag each IOC with its **MITRE ATT&CK** technique;
- writes a Splunk lookup (`cti_iocs.csv`) used by detection
  [DET-0009](https://github.com/Jka667/splunk-detection-as-code/blob/main/detections/DET-0009_cti_ioc_match.yml).

No dependencies beyond the Python 3.11+ standard library.

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

For intel that is not structured, see [narrative-report-to-detection.md](narrative-report-to-detection.md).
