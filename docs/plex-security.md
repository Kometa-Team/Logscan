# Plex security advisory assessments

`logscan_web/plex_security.py` owns the offline advisory definitions, strict
version parser, evaluator and historical observation grouping. The September
2026 definition uses `PLEX-PMS-2026-09`, publication date `2026-09-01`, and the
four component minimum `1.43.3.10861`. Plex's notice recommends 1.43.3 or newer;
the four component threshold is Kometa's configured advisory policy. Critical
is Kometa's recommendation priority, not an official CVSS rating.

Append future definitions to `ADVISORIES`. Do not replace existing definitions.
Only four numeric components with an optional hexadecimal build hash permit an
assessment. Missing, partial and malformed versions remain unknown. Analysis
does not fetch advisory data or probe Plex servers.

The existing `PlexSecurityRule` uses this core in normal and streaming scans.
Its stable affected finding ID remains `plex_security`; the embedded
`security_assessment` identifies the advisory and server. Unknown assessments
use advice severity. Patched observations remain available from the offline
evaluator and the server version stays visible in Overview; they do not create
advice findings or security banners. Existing finding totals and support filters
therefore include affected servers as critical without counting repeated
evidence as additional findings. Raw tagged log counts remain independent.

Observations are grouped by the logged server name and advisory. Repeated lines
retain their line references and exact occurrence count. Evidence is capped at
the existing limit while counting continues. Each distinct version retains its
own status and evidence. If any historical observation is affected, the grouped
assessment remains affected even when a later observation is patched. The UI
explicitly describes historical observations and never infers a live version.
Logs without stable server identifiers cannot distinguish different servers
that share a name. This is a limitation of the available evidence.

The older 1.41.7.0 through 1.42.0.99999 range remains available through
`legacy_affected`, `LEGACY_LOW` and `LEGACY_HIGH`. Assessments mark overlapping
legacy evidence with `legacy_vulnerability_affected`; the covering 2026 advisory
produces one finding for that server rather than a second legacy warning.
Analysis version 13 refreshes retained scans using the existing startup backfill.
The security assessment, Overview server cards, and Plex analytics use the
same connection/version parser. It accepts paired quotes around a version,
retains the full build hash, and rejects partial versions or malformed suffixes.
Operating system version lines cannot be mistaken for Plex server versions.
The security banner shows the date, or full date range, recorded by timestamps
in the log. Dates retain the logger's local calendar date without assuming a
time zone. Normal and streaming scans read the full log for this range. Missing
or malformed dates are shown as unavailable; upload dates are never substituted.

## Support triage

My uploads and the Support Console have visible Security updates and Critical
issues shortcuts. Counts refer to logs in the authorized view, before filters
or pagination; selecting a shortcut resets other filters. Security badges flag
affected critical security findings and link directly to the critical results.
They show the recorded log date or date range to give historical context.
Patched and unknown assessments do not trigger a security badge. The broader
Critical issues shortcut includes other critical findings as well.

The Security advisories filter works with search, sorting and pagination.
Search accepts affected server names, advisory IDs and observed Plex versions.
Triage uses existing structured findings, including legacy security findings;
it does not derive counts from capped evidence or query live Plex servers.
Personal upload totals and search remain limited to that account's uploads.

## Shared source boundary

The audit found separate application analyzers and no importable shared core.
Quickstart vendors an identical copy of this small standard library module at
`modules/_vendor/plex_security.py`. Its adjacent JSON manifest pins this
repository, source path, commit and normalized source SHA-256. Its sync script
accepts a committed local Logscan checkout, copies the source and updates the
manifest; `--check` compares the two copies offline. Quickstart regression tests
verify the manifest checksum. Neither application imports the other's analyzer,
and no service or runtime dependency is added.

For an advisory update, commit this source first, then run from Quickstart:

```powershell
py -3.13 scripts/sync_plex_security.py ../Logscan
py -3.13 scripts/sync_plex_security.py ../Logscan --check
```

This is source synchronization, not automatic distribution. Maintainers must
ship the updated copy in each application. Make changes in this authoritative
file and sync them instead of editing Quickstart's generated copy.
