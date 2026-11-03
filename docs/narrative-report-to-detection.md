# From a narrative CTI report to a Splunk detection

Not all intel arrives as STIX. For a PDF / blog report, use this worksheet and attach it to the Jira ticket.

| Step | Output |
|------|--------|
| 1. Extract atomic IOCs (IPs, domains, hashes, URLs) | Add them to a STIX bundle or straight to `cti_iocs.csv` with `valid_until` (IOCs age fast: 30–90 days) |
| 2. Extract behaviours (what the actor *does*) | One line per behaviour, quoted from the report |
| 3. Map each behaviour to ATT&CK | Technique ID + data source needed (e.g. T1053.005 → Security 4698 / Sysmon 1) |
| 4. Check telemetry | Do we collect that data source? If not → coverage gap ticket |
| 5. Hunt first | Run a broad SPL over 30 days, review results, note the benign baseline |
| 6. Write the detection | YAML in splunk-detection-as-code, tuned from the hunt baseline |
| 7. Validate | Emulate the behaviour (Atomic Red Team / CALDERA) and confirm it fires |

## Worksheet

```
Report:            <title, source, date>
Jira:              DET-
Behaviour:         "<quote>"
ATT&CK:            T____
Data source:       <Sysmon EID / Windows event / CloudTrail eventName>
Hunt query:        <SPL>
Hunt result:       <n hits / 30 days, benign explanations>
Detection:         DET-____
Validation:        <atomic test or manual steps, result>
```
