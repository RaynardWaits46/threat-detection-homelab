# Detection Rules

Sigma rules written and validated against real telemetry in this lab. Every rule here has been run against live Sysmon data in Splunk before being committed. Rules that have not been validated do not go in this directory.

## Rules

### `sigma/proc_creation_win_masquerading_mysqld.yml`

**Masquerading MySQL Binary Outside Install Directory**
`T1036.005` · Defense Evasion · `level: medium` · `status: experimental`

Detects a process named `mysqld.exe` executing from any path outside the MySQL install directory.

**Telemetry:** Sysmon Event ID 1 (Process Creation), SwiftOnSecurity config.

**Validation, 2026-08-09:**

| Search | Result |
| --- | --- |
| Unfiltered, 30 days | 16 events across 2 paths |
| Legitimate service path | 13 events |
| Planted test binary in `%TEMP%` | 3 events |
| Rule logic applied | 3 events, test path only |

The filter removed exactly the 13 legitimate service starts and retained exactly the 3 planted events. Zero false positives and zero false negatives against this dataset.

**Baseline:** one legitimate path on the test host, `C:\Program Files\MySQL\MySQL Server 8.0\bin\mysqld.exe`, averaging roughly one service start every two to three days. This is a single-purpose test VM, so the false positive rate is measured against N=1 environment. That supports `medium` and does not support `high` for general use.

**Splunk translation used for validation:**

```
index=sysmon EventCode=1 Image="*\mysqld.exe" earliest=-15m
NOT (Image="C:\Program Files\MySQL\*" OR Image="C:\Program Files (x86)\MySQL\*")
```

**Design note.** The exclusion is anchored at `\MySQL\` rather than the version-specific install path. A filter containing `MySQL Server 8.0` would stop matching on upgrade, and a control that requires manual maintenance drifts away from reality without anyone noticing. Anchoring at the parent directory survives version changes, and if it does break it breaks by alerting on legitimate activity, which is a failure you find out about the same day.

A looser `contains` match on `MySQL` was rejected. It never breaks, which sounds good, but it is also trivially evaded by creating a directory named `MySQL` anywhere on disk. That hands control of the exclusion to the attacker.

**Known limitation.** This rule keys on path only. A binary named `mysqld.exe` whose PE version resource declares a different `OriginalFileName` is a separate and independent masquerading signal, closer to T1036.003. That belongs in its own rule rather than as an `or` clause here.

## Conventions

- File naming follows the SigmaHQ pattern: `<logsource_category>_<product>_<description>.yml`
- `status: experimental` means validated in this lab but not run in production. No rule here claims `stable`.
- Every rule records its validation dataset and counts so the claim can be checked rather than taken on trust.
