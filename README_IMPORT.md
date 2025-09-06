# Splunk SOC Analyst Pack

This pack includes:
- `soc_analyst_overview.json` — a Dashboard Studio dashboard with 5 analyst panels.
- `macros.conf` — reusable index/sourcetype/threshold macros.
- `savedsearches.conf` — saved searches suitable for triage/alerting.

## Import Instructions

1. **Dashboard (Dashboard Studio)**
   - In Splunk, go to *Dashboards* → *Create new Dashboard* → *Dashboard Studio*.
   - Choose *Import JSON* and paste the contents of `soc_analyst_overview.json`.
   - Ensure your indexes/sourcetypes match or adjust the `base_indexes` macro accordingly.

2. **Macros**
   - Copy `macros.conf` into your Splunk App's `local/` directory (e.g., `$SPLUNK_HOME/etc/apps/search/local/macros.conf`).
   - Restart Splunk or run `splunk btool macros list --debug` to validate.

3. **Saved Searches**
   - Copy `savedsearches.conf` into your App's `local/` directory.
   - In Splunk: *Settings* → *Searches, reports, and alerts* → verify the searches.
   - Adjust thresholds via macros: `threshold_failed_logons(threshold)` and `threshold_dns_beacon`.

## Notes
- The dashboard assumes data is available in indexes: `wineventlog`, `sysmon`, `suricata`, `zeek`.
- Update macros to fit your environment’s indexes/sourcetypes.
- All SPL is inline; consider converting saved searches to ES Correlation Searches if using Splunk ES.
- Time ranges default to the last 24 hours within each search; change in the JSON or dashboard UI.
