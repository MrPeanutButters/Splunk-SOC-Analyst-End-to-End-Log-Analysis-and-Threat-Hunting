# Lookups Pack

This folder provides simple enrichment and allowlists to enhance your dashboards and searches.

- `asn_lookup.csv`: Example IP → ASN/Org mapping. Replace or populate with your own export.
- `known_good_processes.csv`: Common Windows core processes to reduce noise.
- `known_admin_tools.csv`: Admin tools (may be dual-use). Useful for context rather than blanket allow/deny.
- `known_dns_whitelist.csv`: DNS domains typically seen in enterprise environments.

## Installation

1. Copy the CSVs into your app's `lookups/` directory.
2. Copy `transforms.conf` to your app's `local/` directory.
3. In searches, use: `| lookup asn_lookup ip as <field> OUTPUT asn, org`.
4. Whitelist example: `... | where NOT [ | inputlookup known_dns_whitelist | fields query ]`.

Keep these curated and version-controlled in your repo.
