# Detection Gaps & Blind Spots

A comprehensive analysis of SIEM detection coverage based on real-world testing with Atomic Red Team and threat hunting validation.

---

## Executive Summary

**Testing Period:** November - December 2025  
**Techniques Tested:** 15 variations across 8 MITRE ATT&CK techniques  
**Overall Detection Rate:** ~40% (6 out of 15 technique variations well-detected)

**Key Finding:** While Sysmon captures 100% of endpoint activity, Wazuh SIEM alerts on only 40% of tested techniques. The remaining 60% represent detection blind spots requiring custom rules, scope expansion, or acceptance of risk.

---

## Detection Pipeline Analysis

```
Event Occurs on Endpoint (100%)
    ↓
Sysmon Captures Event (100%)
    ↓
Wazuh Agent Forwards to SIEM (100%)
    ↓
Wazuh Detection Rule Matches (40%) ← MAJOR DROP-OFF
    ↓
Alert Generated & Visible to SOC (40%)
```

**The Problem:** Telemetry collection is perfect. Detection rules are the bottleneck.

**The Implication:** SOC teams have complete visibility in raw logs but limited automated alerting. This creates a dependency on proactive threat hunting to find the 60% of activity that doesn't generate alerts.

---

## Gap Categories

Detection gaps fall into four distinct categories:

### 1. No Rule Exists
SIEM has no configured detection rule for the technique.

**Impact:** Complete blind spot  
**Detection Rate:** 0%  
**Remediation:** Create custom detection rule

### 2. Rule Exists But Never Fires
Rule is configured but scoped to wrong paths, commands, or conditions.

**Impact:** False sense of security (rule exists in name only)  
**Detection Rate:** 0%  
**Remediation:** Expand rule scope or create complementary rule

### 3. Partial Coverage
Rule exists for some variations of technique but not others.

**Impact:** Inconsistent detection based on attacker tool choice  
**Detection Rate:** 33-67%  
**Remediation:** Broaden rule to cover tool/command variations

### 4. Context-Dependent Gaps
Legitimate activity vs malicious activity look identical without context.

**Impact:** High false positive rate or missed detections  
**Detection Rate:** Varies  
**Remediation:** Context-aware rules considering parent process, user, timing

---

## Gaps by MITRE ATT&CK Tactic

### Discovery (TA0007)

**Overall Coverage:** 83% (Strong)

| Technique | Tool/Method | Detection Rate | Gap Type | Root Cause |
|-----------|-------------|----------------|----------|------------|
| T1087.001 (Account Discovery) | net.exe | 100% ✅ | None | Rules 92031, 92033, 92027 |
| T1087.001 (Account Discovery) | query.exe | 0% ❌ | Partial Coverage | Rule scoped to net.exe only |
| T1082 (System Information) | systeminfo.exe | 0% ❌ | No Rule Exists | No detection rule configured |
| T1049 (Network Connections) | netstat.exe | 0% ❌ | No Rule Exists | No detection rule configured |
| T1057 (Process Discovery) | Get-Process | 0% ❌ | No Rule Exists | No detection rule configured |
| T1069.001 (Permission Groups) | Get-LocalGroup | 33% ⚠️ | Partial Coverage | Generic PowerShell detection only (Rule 92027) |
| T1018 (Remote System Discovery) | net view | 100% ✅ | None | Rules 92052, 92035, 92034 |

**Key Findings:**
- **net.exe commands:** Excellent coverage with context-aware rules
- **PowerShell cmdlets:** Generic process creation alerts only, no cmdlet-specific rules
- **Recon commands:** systeminfo, netstat, Get-Process completely unmonitored
- **Tool variation:** Same technique achieves different detection based on tool choice

**Detection Patterns:**
- ✅ **Well-Covered:** net.exe account/group/domain discovery
- ⚠️ **Partially Covered:** PowerShell cmdlets (process creation detected, not specific actions)
- ❌ **Not Covered:** Alternative tools (query.exe, systeminfo, netstat)

**Recommendations:**
1. Create rules for systeminfo.exe, netstat.exe execution
2. Add cmdlet-specific detection for Get-LocalGroup, Get-LocalGroupMember
3. Expand Account Discovery rule scope to include query.exe
4. Consider alerting on PowerShell Get-Process cmdlet

---

### Persistence (TA0003)

**Overall Coverage:** 0% (Critical Gap)

| Technique | Tool/Method | Detection Rate | Gap Type | Root Cause |
|-----------|-------------|----------------|----------|------------|
| T1543.003 (Create/Modify Service) | sc.exe create | Partial | Rule Exists But... | Rule 92307 monitors NEW service registry creation |
| T1543.003 (Create/Modify Service) | sc.exe config | 0% ❌ | Rule Exists But... | Rule doesn't detect config modifications |
| T1053.005 (Scheduled Task) | schtasks.exe | 0% ❌ | No Rule Exists | No detection rule configured |
| T1547.001 (Registry Run Keys) | HKCU\CurrentVersion\Run | 0% ❌ | Rule Exists But... | Rule 92012 monitors Services paths only |
| T1547.001 (Registry Run Keys) | HKLM\CurrentVersion\Run | 0% ❌ | Rule Exists But... | Rule 92012 monitors Services paths only |

**Key Findings:**
- **Service Persistence:** Rule 92307 monitors registry path `HKLM\System\CurrentControlSet\Services\*` for NEW service creation but misses `sc.exe config` modifications to existing services
- **Scheduled Tasks:** No detection rules exist despite schtasks.exe being common persistence mechanism
- **Registry Run Keys:** Rule 92012 exists for T1547.001 but only monitors Services paths, not Run key paths
- **Complete Blind Spot:** All three tested persistence techniques had 0% detection rate

**What Wazuh Monitors:**
```
✅ HKLM\System\CurrentControlSet\Services\* (NEW service creation)
❌ HKCU\Software\Microsoft\Windows\CurrentVersion\Run\*
❌ HKLM\Software\Microsoft\Windows\CurrentVersion\Run\*
❌ sc.exe config commands (service modification)
❌ schtasks.exe commands (any variation)
```

**Detection Patterns:**
- ✅ **Well-Covered:** NEW Windows service creation via registry
- ❌ **Not Covered:** Service modification, scheduled tasks, registry Run keys

**Recommendations:**
1. **CRITICAL:** Create scheduled task detection rule
   - Alert on schtasks.exe with `/sc onlogon` or `/sc onstart`
   - Alert on cmd.exe in task actions
   - Alert on `/ru system` privilege escalation

2. **CRITICAL:** Expand Registry Run Keys monitoring
   - Add `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\*` to monitored paths
   - Add `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\*` to monitored paths
   - Modify Rule 92012 scope or create new rule

3. **HIGH:** Add sc.exe config detection
   - Alert on `sc.exe config` with suspicious ImagePath changes
   - Focus on PowerShell, cmd.exe, or unusual paths in binPath

---

### Execution (TA0002)

**Overall Coverage:** Varies by execution method

| Technique | Tool/Method | Detection Rate | Gap Type | Root Cause |
|-----------|-------------|----------------|----------|------------|
| T1059.001 (PowerShell) | -ExecutionPolicy Bypass | 100% ✅ | None | Process creation captured |
| T1059.001 (PowerShell) | Cmdlet execution | Partial ⚠️ | Context-Dependent | Generic process creation, not cmdlet-specific |

**Key Findings:**
- PowerShell process creation is captured (Event ID 1)
- Suspicious flags like `-ExecutionPolicy Bypass` visible in command line
- Individual cmdlet actions not specifically detected (relies on generic PowerShell spawning)

**Recommendations:**
- Current coverage acceptable for process-level detection
- Consider PowerShell script block logging for cmdlet-level visibility
- Context-aware rules already reduce false positives (e.g., Rule 92033)

---

## Technical Root Causes

### Registry Path Scope Limitations

**Problem:** Wazuh Rule 92012 exists for T1547.001 (Registry Run Keys) but never fires.

**Investigation:**
```spl
# Search all Event ID 13 alerts in 24-hour period
index=wazuh data.win.system.eventID=13
| spath
| stats count by data.win.eventdata.targetObject

# Results: ALL alerts for HKLM\System\CurrentControlSet\Services\*
# Zero alerts for CurrentVersion\Run paths
```

**Root Cause:** Rule configured to monitor specific registry paths (Services) but not Run key paths.

**Why This Matters:**
- Rule appears to exist for the technique in MITRE mapping
- SOC teams may assume coverage exists
- Reality: Complete blind spot for actual Run key persistence

**Fix Required:** Expand ossec.conf registry monitoring to include:
```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
  <filter>
    <target_object>CurrentVersion\\Run</target_object>
  </filter>
</localfile>
```

---

### Tool Variation Gaps

**Problem:** Detection rules scoped to specific tools miss equivalent functionality from alternative tools.

**Example - Account Discovery:**
- **Detected:** `net.exe user` → Wazuh Rule 92031 fires
- **Missed:** `query.exe user` → No alert generated
- **Impact:** Same technique, different tool, different detection outcome

**Root Cause:** Rules hardcoded to specific executables rather than technique behaviors.

**Why This Happens:**
- Performance optimization (specific file names faster than behavior heuristics)
- Rule creation based on common tools, not comprehensive coverage
- Assumption that attackers use standard tooling

**Attacker Perspective:**
Multiple tools achieve same objective:
- Account enumeration: net.exe, query.exe, Get-LocalUser, whoami
- Service creation: sc.exe, New-Service, reg.exe
- Task creation: schtasks.exe, Register-ScheduledTask

**Fix Required:** 
- Broaden existing rules to cover tool variations
- Create behavior-based rules focusing on technique outcome vs specific tool
- Use MITRE ATT&CK procedure examples to identify alternative tools

---

### Action vs Creation Monitoring

**Problem:** Rules monitor object CREATION but not MODIFICATION.

**Example - Service Persistence:**
- **Detected:** NEW service creation via registry write
- **Missed:** EXISTING service modification via `sc.exe config`

**Command Comparison:**
```powershell
# Both achieve persistence, only first generates alert

# Creates NEW service (DETECTED)
sc.exe create MaliciousService binPath="C:\malware.exe"

# Modifies EXISTING service (NOT DETECTED)
sc.exe config TrustedService binPath="powershell.exe -enc <payload>"
```

**Root Cause:** Rule scoped to registry SetValue events at Services path (new key creation), not sc.exe command line monitoring.

**Why This Matters:**
- Attackers can hijack legitimate services
- Trusted service names reduce suspicion
- Service modification less obvious than service creation

**Fix Required:**
- Add sc.exe command line monitoring
- Alert on `sc.exe config` with suspicious binPath changes
- Alert on ImagePath modifications to existing services

---

### Missing Rules Entirely

**Problem:** No detection rules configured for common techniques.

**Examples:**
- T1053.005 (Scheduled Task): 0 rules exist
- T1082 (System Information Discovery): 0 rules exist
- T1049 (Network Connections Discovery): 0 rules exist

**Root Cause:**
- Default Wazuh ruleset focuses on high-severity techniques
- Scheduled tasks considered lower priority
- Discovery techniques may be deemed "informational" vs "malicious"

**Why This Creates Risk:**
- Attackers use these techniques in real attacks
- Atomic Red Team validates these are testable, reproducible techniques
- No alert = no investigation = successful attacker action

**Fix Required:**
- Prioritize scheduled task detection (common persistence method)
- Consider alerting on discovery commands executed by non-admin users
- At minimum, create "informational" level alerts for SOC awareness

---

## Context-Aware Detection Insights

### What Works Well

**Rule 92033: Discovery activity spawned via PowerShell execution**
```
PowerShell → net.exe = ALERT (suspicious)
System → net.exe = No alert (normal)
```

**Why This Matters:**
- Same command (net.exe user)
- Different parent process = different risk level
- Reduces false positives from legitimate system processes
- Increases fidelity of alerts

**Implementation:**
Rule checks parent process before alerting. This context-aware approach dramatically improves signal-to-noise ratio.

---

## Detection Maturity by Technique Category

### High Maturity (>80% Coverage)
- **Discovery - Network:** net view commands (100%)
- **Discovery - Account (net.exe):** Account enumeration via net.exe (100%)

### Medium Maturity (30-70% Coverage)
- **Discovery - Account (general):** Partial coverage, tool-dependent
- **Discovery - Groups:** Generic PowerShell detection only (33%)

### Low Maturity (<30% Coverage)
- **Persistence - All Types:** Services (0%), Tasks (0%), Registry (0%)
- **Discovery - System Info:** systeminfo, netstat, Get-Process (0%)

**Trend:** Discovery techniques have better coverage than Persistence techniques.

**Hypothesis:** Discovery commands (net.exe) more commonly used in attacker TTPs, driving rule development. Persistence techniques may rely on assumptions that endpoint protection blocks execution.

---

## Remediation Priority Matrix

### Priority 1 (CRITICAL - Implement Immediately)

**1. Scheduled Task Detection**
- **Technique:** T1053.005
- **Gap:** No rules exist
- **Risk:** Common persistence mechanism completely unmonitored
- **Implementation:**
  ```
  Alert on: schtasks.exe with /sc onlogon OR /sc onstart
  Alert on: cmd.exe in task action parameter
  Alert on: /ru system privilege escalation
  ```

**2. Registry Run Keys Monitoring**
- **Technique:** T1547.001
- **Gap:** Rule exists but monitors wrong paths
- **Risk:** Most common persistence technique undetected
- **Implementation:**
  ```
  Expand monitoring to include:
  HKCU\Software\Microsoft\Windows\CurrentVersion\Run\*
  HKLM\Software\Microsoft\Windows\CurrentVersion\Run\*
  ```

### Priority 2 (HIGH - Implement This Quarter)

**3. Service Configuration Modification**
- **Technique:** T1543.003
- **Gap:** Only monitors NEW service creation
- **Risk:** Attackers can hijack existing trusted services
- **Implementation:**
  ```
  Alert on: sc.exe config with binPath/ImagePath changes
  Alert on: Suspicious paths in service modifications
  ```

**4. Alternative Discovery Tools**
- **Technique:** T1087.001
- **Gap:** Only detects net.exe, misses query.exe
- **Risk:** Simple tool substitution bypasses detection
- **Implementation:**
  ```
  Expand Account Discovery rule to include:
  query.exe user
  quser.exe
  Get-LocalUser cmdlet
  ```

### Priority 3 (MEDIUM - Consider for Future)

**5. System Information Discovery**
- **Technique:** T1082
- **Gap:** No rules exist
- **Risk:** Early-stage reconnaissance goes unnoticed
- **Implementation:**
  ```
  Alert on: systeminfo.exe execution (informational level)
  Context: Focus on non-admin users or suspicious timing
  ```

**6. PowerShell Cmdlet-Specific Detection**
- **Technique:** Various
- **Gap:** Generic PowerShell detection, not cmdlet-specific
- **Risk:** Missed visibility into specific PowerShell actions
- **Implementation:**
  ```
  Consider PowerShell script block logging
  Alert on: Get-LocalGroup, Get-LocalGroupMember cmdlets
  ```

---

## Testing Methodology Validation

**Approach Used:**
1. Execute standardized techniques (Atomic Red Team)
2. Hunt through raw telemetry (Splunk index=sysmon)
3. Validate SIEM alerts (Splunk index=wazuh)
4. Compare detection rates and document gaps

**Why This Works:**
- Atomic Red Team provides reproducible, MITRE-mapped tests
- Raw telemetry confirms event generation (not a logging issue)
- SIEM comparison reveals rule gaps vs telemetry gaps
- Systematic documentation enables prioritized remediation

**Results:**
- 15 technique variations tested
- 100% Sysmon visibility confirmed
- 40% SIEM alert rate measured
- 60% detection gap quantified and categorized

---

## Comparison: Discovery vs Persistence

### Why Discovery Techniques Have Better Coverage

**Discovery Techniques (Week 2 Testing):**
- Detection Rate: 83% (2.5 out of 3 well-covered)
- Multiple rules per technique (up to 3 rules)
- Context-aware detection (PowerShell parent process)
- Domain-specific rules (net view /domain)

**Persistence Techniques (Week 1 Testing):**
- Detection Rate: 0% (0 out of 3 detected)
- No rules for scheduled tasks
- Registry rules monitor wrong paths
- Service rules miss configuration changes

**Hypothesis:**
1. Discovery commands more frequently used in real attacks
2. Discovery techniques easier to detect (command-based, not registry/scheduled task)
3. Persistence may rely on endpoint protection preventing execution
4. Rule development prioritizes high-volume alert sources

**Implication:**
- Don't assume similar coverage across all MITRE tactics
- Validate each tactic independently
- Persistence gaps particularly critical (allows attacker to maintain access)

---

## Key Takeaways

### For SOC Teams

1. **Telemetry ≠ Detection**
   - 100% event capture doesn't mean 100% alerting
   - Raw logs contain everything; alerts are selective
   - Threat hunting bridges the gap between logs and alerts

2. **Validate Detection Assumptions**
   - Rules existing in MITRE mapping doesn't mean they fire
   - Test with actual techniques, not just theory
   - Document what's detected vs what's logged

3. **Tool Variation Matters**
   - Same technique, different tool = different detection outcome
   - Attackers can easily substitute tools
   - Detection must account for technique, not just specific executable

4. **Context Improves Fidelity**
   - Parent process context reduces false positives
   - PowerShell → net.exe more suspicious than System → net.exe
   - Domain-specific rules (net view /domain) add precision

### For Detection Engineers

1. **Prioritize Persistence Detection**
   - Current testing shows 0% coverage
   - Scheduled tasks, Registry Run keys critical to address
   - Service modifications often overlooked

2. **Expand Rule Scope Strategically**
   - Don't just add more rules, improve existing rule scope
   - Account Discovery rule should cover ALL enumeration tools
   - Registry monitoring should include ALL persistence paths

3. **Test Beyond Default Rulesets**
   - Vendor defaults don't cover all techniques
   - Atomic Red Team provides free, standardized test cases
   - Hunting validates rule effectiveness in real scenarios

4. **Document Your Gaps**
   - Knowing what you DON'T detect is as important as what you DO
   - Prioritize gap remediation based on risk
   - Communicate gaps to stakeholders (managed expectations)

---

## Continuous Improvement

This analysis represents a snapshot based on 15 technique variations tested. Detection gaps will evolve as:
- New rules are created
- Existing rules are expanded
- Attacker TTPs change
- Tools are updated

**Recommended Cadence:**
- Re-test critical techniques quarterly
- Validate new rules with Atomic Red Team
- Update gap documentation after each testing cycle
- Track detection rate improvement over time

---

## Resources

- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) - Standardized technique testing
- [MITRE ATT&CK Framework](https://attack.mitre.org/) - Technique documentation
- [Wazuh Ruleset](https://documentation.wazuh.com/current/user-manual/ruleset/) - Default rule documentation
- [Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config) - Event logging configuration

---

## Conclusion

Detection gaps are not failures—they're opportunities for improvement. This analysis quantifies what many SOC teams suspect: SIEM alerts represent a subset of actual endpoint activity. The key is knowing which subset, understanding why gaps exist, and prioritizing remediation based on risk.

**Bottom Line:**
- 60% detection gap across tested techniques
- Root causes identified and categorized
- Remediation priorities established
- Testing methodology validated and repeatable

The path forward is clear: expand rule coverage for persistence techniques, broaden existing rule scope for tool variations, and continue validating detection effectiveness through systematic testing.
