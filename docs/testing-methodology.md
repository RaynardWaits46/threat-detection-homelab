# Threat Detection Testing Methodology

A practical guide to validating SIEM detection capabilities using Atomic Red Team and Splunk threat hunting techniques.

---

## Overview

**Goal:** Understand what your SIEM actually detects, not what the vendor says it detects.

**Approach:**
1. Execute standardized attack techniques (Atomic Red Team)
2. Generate realistic background noise (simulated user activity)
3. Hunt through raw telemetry to find malicious activity
4. Compare findings against SIEM alerts
5. Document detection gaps and validate coverage

**Why This Works:**
- Standardized tests (MITRE ATT&CK-mapped) ensure reproducibility
- Background noise simulates real SOC environments
- Hunting validates both detection rules AND hunting skills
- Gap analysis reveals blind spots before real attacks exploit them

---

## Testing Environment Setup

### Pre-Test Checklist

**Before Each Test:**
- [ ] Verify Wazuh agent is connected and reporting
- [ ] Confirm Splunk is receiving Sysmon logs (`index=sysmon | head 10`)
- [ ] Check WireGuard tunnel status (if using cloud SIEM)
- [ ] Note current time (local and Splunk displayed time if offset exists)
- [ ] Clear any previous test artifacts
- [ ] Document test plan (techniques, expected event types)

### Noise Generator Setup

**Purpose:** Create realistic baseline activity that simulates normal user behavior.

**Activities to Simulate:**
- Office application usage (Word, Excel, PowerPoint)
- Web browsing (Edge, Chrome)
- File system operations
- Print queue checks
- Network drive enumeration

**Example Noise Script:**
```powershell
.\Normal-User-Activity.ps1 -DurationMinutes 45 -ActivityLevel Medium
```

**Execution Pattern:**
1. Start noise generator FIRST
2. Wait 2-3 minutes for baseline activity
3. Execute Atomic tests with 5-10 minute spacing
4. Let noise generator complete full duration
5. Then hunt through combined events

**Why Spacing Matters:**
- Allows clear timeline separation between techniques
- Simulates realistic attack pacing
- Makes hunting easier when starting out
- Can tighten timing as methodology improves

---

## Atomic Red Team Testing

### Installation

```powershell
# Requires PowerShell 5.1+ and admin privileges

# CRITICAL: Add Windows Defender exclusion first
Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"

# Install Atomic Red Team
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
Install-AtomicRedTeam -getAtomics

# Import module for each session
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

### Usage Pattern

**1. Research the technique:**
```powershell
# List all available tests for a technique
Invoke-AtomicTest T1087.001 -ShowDetails
```

**2. Execute specific test:**
```powershell
# Run test number 9
Invoke-AtomicTest T1087.001 -TestNumbers 9

# Note the exact time (both local and Splunk displayed time)
```

**3. Cleanup after hunting:**
```powershell
# Always cleanup after validation
Invoke-AtomicTest T1087.001 -TestNumbers 9 -Cleanup
```

**Best Practices:**
- Test one technique at a time initially (easier to isolate)
- Progress to 3-5 techniques per session as methodology improves
- Always document execution times
- Cleanup immediately after hunting validation
- Verify cleanup worked (check for artifacts)

---

## Threat Hunting Methodology

### The Five-Step Process

**1. Start Broad**
Begin with widest possible search for relevant event type or tool.

*Example:*
```spl
index=sysmon EventCode=1 host="WindowsTestBox" User="*YourUser*"
```

**2. Identify Patterns**
Look for anomalies in command-lines, registry paths, parent processes, or timing.

*What to look for:*
- Unexpected parent processes (PowerShell spawning net.exe)
- Suspicious command-line arguments (ExecutionPolicy Bypass)
- Registry paths associated with persistence (CurrentVersion\Run)
- Timing clusters (multiple commands within seconds)

**3. Refine Progressively**
Add filters incrementally to narrow results, but don't over-filter too quickly.

*Example progression:*
```spl
# Broad
index=sysmon EventCode=1 Image="*sc.exe*"

# Add context filter
| search CommandLine="*powershell*"

# Add time window
earliest="2024-12-09T19:35:00" latest="2024-12-09T19:38:00"
```

**4. Verify in SIEM**
Check if alerts fired for the same activity.

*Example:*
```spl
index=wazuh agent.name="Windows_10_Test_Box"
| spath
| search rule.mitre.id=*T1087*
| table _time, rule.id, rule.description
```

**5. Document Findings**
Capture queries, event counts, detection results, and gaps.

### Progressive Filtering Strategy

**Level 1 - Broad Sweep:**
```spl
index=sysmon EventCode=1
```
*Goal:* Understand total event volume

**Level 2 - User Context:**
```spl
index=sysmon EventCode=1 User="*YourUser*"
```
*Goal:* Filter to relevant user activity

**Level 3 - Tool Focus:**
```spl
index=sysmon EventCode=1 User="*YourUser*" Image="*net.exe*"
```
*Goal:* Narrow to specific attack tool

**Level 4 - Suspicious Patterns:**
```spl
index=sysmon EventCode=1 User="*YourUser*" Image="*net.exe*"
| search CommandLine="*localgroup*" OR CommandLine="*user*"
```
*Goal:* Identify reconnaissance behavior

**Level 5 - Time Window:**
```spl
# Use Time Range picker in Splunk UI
# Custom range around test execution time (e.g., 3-5 minute window)
```
*Goal:* Pinpoint exact malicious events

---

## Query Building Techniques

### Search vs Filter Tradeoffs

**Direct Field Matching (Fast):**
```spl
index=sysmon EventCode=1 Image="*sc.exe*"
```
- Uses indexed fields
- Faster execution
- Limited flexibility

**Pipe Search (Flexible):**
```spl
index=sysmon EventCode=1 | search CommandLine="*powershell*"
```
- Works on any field
- More flexible pattern matching
- Slightly slower on large datasets

**When to Use Each:**
- Start with direct field matching for performance
- Add pipe search for complex patterns
- Combine both for best results

### Wildcard Strategies

**Common Patterns:**

```spl
# Catch spacing variations
CommandLine="*net*view*"  # Catches "net view" AND "net  view"

# Partial path matching
Image="*System32*"  # Avoids specifying full path

# Case-insensitive tool search
Image="*powershell*"  # Catches PowerShell.exe, powershell.exe, POWERSHELL.EXE

# Registry path flexibility
TargetObject="*CurrentVersion\\Run*"  # Note the double backslash!
```

**Wildcard Best Practices:**
- Use `*` liberally to catch variations
- Don't specify spaces when searching commands (spacing can vary)
- Avoid over-specific paths (use partial matches)
- Remember case-insensitivity in most Splunk searches

### Handling Special Characters

**Backslash Escaping:**
```spl
# WRONG - Single backslash interpreted as escape character
TargetObject="*CurrentVersion\Run*"  # Returns nothing!

# CORRECT - Double backslash for literal backslash
TargetObject="*CurrentVersion\\Run*"  # Works!
```

**Quote Handling:**
```spl
# PowerShell parameters appear with escaped quotes
CommandLine="*Get-LocalGroupMember -Name \""Administrators\"" *"

# Search for core cmdlet name instead
CommandLine="*Get-LocalGroupMember*"
```

**Common Pitfalls:**
- Single backslash breaks registry searches
- Forgetting to escape quotes in complex commands
- Over-specifying exact command format

### Field Name Conventions

**Sysmon (Case Sensitive):**
- `Image` (not "image" or "IMAGE")
- `CommandLine` (not "Commandline" or "commandline")
- `ParentImage` (not "parentimage")
- `TargetObject` (for registry events)

**Wazuh (After spath):**
- `rule.id` (lowercase)
- `rule.description` (lowercase)
- `rule.mitre.id` (lowercase, stored as array)
- `agent.name` (lowercase)

**Quick Check:**
```spl
# See all available fields
index=sysmon EventCode=1 | head 1 | fieldsummary
```

---

## Time Management in Hunting

### Efficient Time Windows

**Time Range Picker (Recommended):**
- Use Splunk's GUI time picker (top-right)
- Select "Custom Time Range"
- Specify exact start and end times around test execution
- More reliable than query parameters

**Avoid These Time Patterns:**
```spl
# Don't use earliest/latest in initial query
index=sysmon earliest="..." latest="..."  # Can cause issues
```

**Instead:**
```spl
# Use base query, then set time range in picker
index=sysmon EventCode=1 User="*YourUser*"
# Then use Time Range picker: Last 15 minutes, or Custom Range
```

### Timezone Considerations

**Important:** Your Splunk may display time with an offset from system time.

**Example:**
- Test executed: 14:37 local time
- Splunk displays: 19:37 (+5 hour offset)

**Solution:**
1. Execute test and note actual time
2. Search Splunk and observe first event time
3. Calculate offset (if any)
4. **Always use Splunk's displayed time** for all searches

**Verification:**
- Expand individual events to see raw timestamp
- Compare displayed `_time` vs actual system time in event details

---

## Hunting by Technique Category

### Persistence Techniques

**Event Types to Hunt:**
- EventCode 1: Process creation (sc.exe, schtasks.exe)
- EventCode 13: Registry modifications (Run keys, Services)

**Query Pattern:**
```spl
# Service persistence
index=sysmon EventCode=1 Image="*sc.exe*"
| search CommandLine="*config*" OR CommandLine="*create*"

# Scheduled task persistence
index=sysmon EventCode=1 Image="*schtasks.exe*"
| search CommandLine="*/sc onlogon*" OR CommandLine="*/sc onstart*"

# Registry Run keys
index=sysmon EventCode=13 EventType="SetValue" TargetObject="*CurrentVersion\\Run*"
```

**Suspicious Indicators:**
- PowerShell in service ImagePath
- cmd.exe in scheduled task actions
- `/ru system` or `/ru administrator` privileges
- Registry keys pointing to suspicious paths

### Discovery Techniques

**Event Types to Hunt:**
- EventCode 1: Process creation (net.exe, whoami.exe, query.exe)

**Query Pattern:**
```spl
# Account discovery
index=sysmon EventCode=1 Image="*net.exe*"
| search CommandLine="*user*" OR CommandLine="*localgroup*"

# System discovery
index=sysmon EventCode=1 Image="*systeminfo*"

# Network discovery
index=sysmon EventCode=1 
| search CommandLine="*net*view*" OR Image="*ipconfig*" OR Image="*netstat*"
```

**Suspicious Indicators:**
- PowerShell spawning discovery commands (higher fidelity)
- Multiple discovery commands in short timeframe
- Discovery from non-admin user accounts
- Reconnaissance combined with other techniques

### Command and Scripting

**Event Types to Hunt:**
- EventCode 1: PowerShell.exe, cmd.exe with suspicious flags

**Query Pattern:**
```spl
# PowerShell execution policy bypass
index=sysmon EventCode=1 Image="*powershell*"
| search CommandLine="*-ExecutionPolicy Bypass*" OR CommandLine="*-ep bypass*"

# Encoded commands
index=sysmon EventCode=1 Image="*powershell*"
| search CommandLine="*-EncodedCommand*" OR CommandLine="*-enc*"

# PowerShell download cradles
index=sysmon EventCode=1 Image="*powershell*"
| search CommandLine="*IEX*" OR CommandLine="*Invoke-WebRequest*" OR CommandLine="*wget*"
```

**Suspicious Indicators:**
- `-ExecutionPolicy Bypass` flags
- Encoded commands (base64)
- Download cradles (IEX, IWR, wget)
- Parent process anomalies (e.g., Excel spawning PowerShell)

---

## Detection Validation

### Comparing Raw Logs vs Alerts

**Step 1 - Find in Raw Telemetry:**
```spl
index=sysmon EventCode=1 Image="*net.exe*"
| search CommandLine="*user*"
| table _time, Image, CommandLine, ParentImage, User
```

**Step 2 - Check SIEM Alerts:**
```spl
index=wazuh agent.name="Your_Agent_Name"
| spath
| search rule.mitre.id=*T1087*
| table _time, rule.id, rule.description, rule.mitre.id
```

**Step 3 - Compare Results:**
- If alerts exist: Detection working ✅
- If no alerts: Detection gap identified ⚠️
- Document which events alerted vs which didn't

### Understanding Detection Gaps

**Gap Categories:**

**1. No Rule Exists**
- SIEM has no configured rule for technique
- Example: Wazuh missing scheduled task detection
- Solution: Create custom detection rule

**2. Rule Exists But Never Fires**
- Rule configured but scoped to wrong paths/commands
- Example: Registry Run key rule monitoring Services paths only
- Solution: Expand rule scope or create complementary rule

**3. Partial Coverage**
- Rule exists for some variations but not others
- Example: net.exe detected but query.exe not
- Solution: Broaden rule to cover tool variations

**4. Context-Aware Gaps**
- Legitimate activity vs malicious activity look similar
- Example: System running net.exe (ok) vs PowerShell spawning net.exe (suspicious)
- Solution: Context-aware rules considering parent process

### Documentation Template

```markdown
## Hunt: [Technique Name] (MITRE ID)

**Hunting Methodology:**
1. Broad search: [query] → [X events]
2. Pattern identified: [what looked suspicious]
3. Refined search: [query] → [Y events]
4. Result: [found/missed malicious activity]

**Sysmon (index=sysmon):**
- [X]% visibility
- [Event details]

**SIEM (index=wazuh):**
- [X]% detection
- Rule(s) fired: [IDs and descriptions]
- Gap: [what missed and why]

**Hunt Time:** [minutes]

**Key Learning:**
- [Technical discovery]
- [Detection insight]
```

---

## Common Issues and Solutions

### Issue: Search Returns No Results

**Potential Causes:**
1. Time range too narrow
2. Field name typo (case sensitivity)
3. Backslash not escaped properly
4. Index name incorrect
5. Host/agent name mismatch

**Troubleshooting Steps:**
```spl
# 1. Verify data exists in index
index=sysmon | head 10

# 2. Check exact field names
index=sysmon EventCode=1 | head 1 | fieldsummary

# 3. Expand time range (try "Last 24 hours")

# 4. Simplify query progressively
index=sysmon EventCode=1  # Does this work?
index=sysmon EventCode=1 Image="*net*"  # Does this work?
# Add complexity back incrementally

# 5. Verify host/agent naming
index=sysmon | stats count by host
index=wazuh | spath | stats count by agent.name
```

### Issue: Too Many Results

**Solutions:**

```spl
# Add user filter early
User="*YourUsername*"

# Filter by Image path to exclude noise
Image="*System32*"  # Exclude edge cases like EdgeWebView

# Narrow time window
# Use Time Range picker: Last 5 minutes instead of Last hour

# Add NOT clauses for known-good
| search NOT Image="*MicrosoftEdge*"
```

### Issue: Detection Rule Not Firing

**Verification Steps:**

```spl
# 1. Verify events in Wazuh index
index=wazuh | spath | table _time, rule.description

# 2. Search by MITRE ID (use wildcards for arrays)
index=wazuh | spath | search rule.mitre.id=*T1087*

# 3. Check if rule exists at all
index=wazuh | spath 
| stats count by rule.id, rule.description 
| search rule.id=92031

# 4. If rule exists but no events, check rule scope
# Review Wazuh rule configuration for path/command filters
```

---

## Hunting Efficiency Tips

### Speed Improvements Over Time

**Week 1 (Learning):**
- 90 minutes per technique
- Building queries from scratch
- Troubleshooting field names
- Learning tool behavior
- Total: ~135 minutes for 3 techniques

**Week 2 (Practiced):**
- 15-40 minutes per technique
- Methodology internalized
- Common patterns recognized
- Faster query refinement
- Total: ~70-85 minutes for 3 techniques (45% faster!)

**How to Improve:**
1. Document successful query patterns
2. Build query template library
3. Practice progressive filtering
4. Learn common false positive patterns
5. Understand tool output formats

### Query Template Library

Create reusable query templates for common hunts:

```spl
# Template: Process-based hunt
index=sysmon EventCode=1 host="HOSTNAME" User="*USERNAME*" Image="*TOOLNAME*"
| search CommandLine="*PATTERN*"
| table _time, Image, CommandLine, ParentImage

# Template: Registry hunt
index=sysmon EventCode=13 host="HOSTNAME" EventType="SetValue"
| search TargetObject="*REGISTRY_PATH*"
| table _time, TargetObject, Details, User

# Template: Wazuh MITRE check
index=wazuh agent.name="AGENT_NAME"
| spath
| search rule.mitre.id=*TECHNIQUE_ID*
| table _time, rule.id, rule.description, rule.mitre.id
```

---

## Measuring Success

### Hunting Metrics to Track

**Speed:**
- Time per technique (target: <30 minutes)
- Total hunting session time
- Improvement over time (Week 1 vs Week 2)

**Accuracy:**
- False positives per hunt
- Malicious events correctly identified
- Detection gaps discovered

**Coverage:**
- Techniques tested per week
- MITRE ATT&CK tactics covered
- Detection rule validation count

### Detection Gap Analysis

**Document Per Technique:**
- Sysmon coverage: [X]%
- SIEM alerts: [Y]%
- Gap: [X - Y]%
- Root cause: [rule scope/missing rule/path not monitored]
- Recommendation: [create rule/expand scope/accept risk]

**Example:**
```
T1547.001 (Registry Run Keys)
- Sysmon: 100% (captured all registry modifications)
- Wazuh: 0% (rule exists but monitors Services paths only)
- Gap: 100% blind spot
- Root Cause: Rule 92012 scoped to HKLM\System\Services, not Run keys
- Recommendation: Expand rule or create new rule for Run key paths
```

---

## Next Steps

Once methodology is solid:

1. **Create Custom Detection Rules**
   - Fill identified gaps
   - Test new rules with same methodology

2. **Build Correlation Searches**
   - Multi-event detection (e.g., discovery → credential access → lateral movement)
   - Time-based correlation windows

3. **Automate Gap Reporting**
   - Script MITRE ATT&CK coverage checks
   - Generate heatmaps of detection coverage

4. **Expand Testing Scope**
   - Credential Access techniques
   - Lateral Movement
   - Defense Evasion
   - Exfiltration

---

## Resources

- [Atomic Red Team Documentation](https://github.com/redcanaryco/atomic-red-team)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
- [Wazuh Rule Documentation](https://documentation.wazuh.com/current/user-manual/ruleset/)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
