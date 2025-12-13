# Threat Detection Homelab: A Practical SOC Analyst's Testing Environment

![GitHub last commit](https://img.shields.io/github/last-commit/RaynardWaits46/threat-detection-homelab)
![GitHub](https://img.shields.io/github/license/RaynardWaits46/threat-detection-homelab)
![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)

A hands-on security lab built to test detection capabilities, hunt for threats, and understand what modern SIEM tools actually catch (and what they miss).

**What's Inside:**
- Cloud-hosted Wazuh SIEM integrated with on-premise Splunk
- Atomic Red Team for standardized technique testing
- Real threat hunting methodology with documented gaps
- Complete setup guides so you can build your own

**Why This Matters:**
Most SOC training uses simulated data or pre-configured environments. This lab tests real detection tools against actual attack techniques, documenting both successes and blind spots. The goal? Understanding what your SIEM *actually* detects, not what the vendor says it detects.

---

## 🎯 What Makes This Lab Different

**Real Detection Gaps:** I document when tools miss techniques and explain why (configuration scope, missing rules, monitored paths).

**Multi-Source Correlation:** Comparing raw Sysmon telemetry (index=sysmon) against SIEM alerts (index=wazuh) reveals detection coverage and blind spots.

**Standardized Testing:** Using Atomic Red Team ensures reproducible results mapped to MITRE ATT&CK framework.

**Hunting Methodology:** Building Splunk queries from scratch, broad to specific, with actual event counts and time windows documented.

---

## 🏗️ Lab Architecture

```
┌─────────────────┐
│   Kali Linux    │  (Attack simulation)
│    (VLAN 1)     │
└────────┬────────┘
         │ SSH
         ↓
┌─────────────────┐
│  Windows 10 VM  │  (Target endpoint)
│   (Lab VLAN)    │
└────────┬────────┘
         │
    ┌────┴────┐
    ↓         ↓
┌─────────┐ ┌──────────────┐
│ Sysmon  │ │   Wazuh      │
│         │ │   Agent      │
└────┬────┘ └──────┬───────┘
     │             │
     │             ↓
     │      ┌─────────────┐
     │      │Wazuh Server │ (Cloud - Linode)
     │      │(Alert Rules)│
     │      └──────┬──────┘
     │             │ WireGuard VPN
     │             ↓
     └──────→ ┌─────────────┐
              │   Splunk    │ (Docker - Local)
              │  Enterprise │
              └─────────────┘
```

**Key Design Decisions:**
- **Network Segmentation:** Lab VLAN isolated with unidirectional firewall rules
- **Secure Integration:** WireGuard VPN tunnel (not exposed Splunk ports)
- **Dual Visibility:** Raw telemetry (Sysmon) + curated alerts (Wazuh)

---

## 📊 Detection Testing Results

Here's what I've validated so far:

| Technique | MITRE ID | Sysmon | Wazuh | Gap | Key Finding |
|-----------|----------|--------|-------|-----|-------------|
| Account Discovery (net.exe) | T1087.001 | 100% | 100% | 0% | Excellent coverage, context-aware rules |
| Account Discovery (query.exe) | T1087.001 | 100% | 0% | 100% | Rule scoped to net.exe only |
| System Info Discovery | T1082 | 100% | 0% | 100% | No detection rule configured |
| HKCU Run Keys | T1547.001 | 100% | 0% | 100% | Registry path not monitored |
| Service Creation | T1543.003 | 100% | 0% | 100% | Monitors NEW services, not config |
| Permission Groups | T1069.001 | 100% | 33% | 67% | Generic PowerShell only |
| Remote System Discovery | T1018 | 100% | 100% | 0% | Strong multi-rule coverage |

**Key Insight:** Detection rules exist for SOME techniques but not others. Even when rules exist, they may never fire if the monitored paths don't match your test scenario.

---

## 🚀 Quick Start

**Prerequisites:**
- Windows 10/11 VM (target endpoint)
- Linux host for Wazuh server (cloud VPS recommended)
- Docker host for Splunk Enterprise
- Basic networking knowledge (VLANs, firewall rules)

**Setup Guides:**
1. [Lab Infrastructure Setup](/docs/lab-setup.md) - Network, VMs, VLAN configuration, WireGuard VPN
2. [Testing Methodology](/docs/testing-methodology.md) - Threat hunting process and query building
3. [Detection Gaps Analysis](/docs/detection-gaps.md) - Comprehensive blind spot documentation

**Testing Framework:**
- Atomic Red Team installation and usage
- Noise generator for realistic environments
- Threat hunting query patterns
- Gap analysis and remediation priorities

---

## 📚 Blog Series

Detailed writeups available on [Medium (@raynardwaits)](https://medium.com/@raynardwaits):

**Integration Series:**
- Part 1: WireGuard Setup and Security Rationale
- Part 2: Splunk Forwarder Configuration  
- Part 3: Troubleshooting and Validation

**Detection Testing:**
- Testing RAT Detection: Why Modern Defender Makes Blue Team Testing Harder
- Testing Custom Payloads Against Behavioral Detection
- Hunting Through the Gaps: Multi-Source Correlation
- Testing Registry Persistence Detection: When Rules Exist But Never Fire
- Testing Account Discovery with Atomic Red Team

**Persistence Hunting:**
- Part 1: Finding Malicious Services and Tasks Among 1,400 Events
- Part 2: Registry Run Keys and the Technical Details That Matter

---

## 🔧 Tech Stack

**SIEM & Logging:**
- Wazuh 4.x (cloud-hosted)
- Splunk Enterprise 9.x (Docker)
- Sysmon (SwiftOnSecurity config)

**Testing Tools:**
- Atomic Red Team
- Kali Linux
- Custom PowerShell noise generator

**Infrastructure:**
- UniFi networking (VLANs, firewall rules)
- WireGuard VPN
- Docker Desktop

---

## 📖 Documentation Structure

```
/docs/
  lab-setup.md              # Infrastructure and network config
  testing-methodology.md    # Threat hunting process
  detection-gaps.md         # Known limitations and blind spots

/configs/
  sysmon-config.xml         # Sysmon configuration (SwiftOnSecurity-based)
  wazuh-agent-sample.conf   # Sample Wazuh agent config

/scripts/
  noise-generator.ps1       # Background activity simulator
  cleanup-scripts/          # Test cleanup automation
```

---

## 💡 Key Learnings

**Detection Coverage Varies by Tactic:**
- Discovery techniques: Well-covered (Wazuh has mature rules)
- Persistence techniques: Significant gaps (limited registry path monitoring)

**Context-Aware Detection Matters:**
- PowerShell spawning net.exe triggers different rules than System spawning net.exe
- Reduces false positives significantly

**Command Variations Require Wildcards:**
- Spacing differences: `net  view` vs `net view`
- Quote escaping: PowerShell parameters show as `\"` in logs
- Solution: Strategic wildcard usage (`*net*view*`)

**Raw Telemetry vs Alerts:**
- Sysmon captures everything (100% visibility)
- Wazuh only alerts when rules match (selective coverage)
- Gap analysis reveals detection blind spots

---

## 🎯 What's Next

**Week 3 Focus Options:**
- Credential Access techniques (T1003, T1552)
- Lateral Movement testing (T1021, T1570)
- Defense Evasion validation (T1562, T1070)

**Roadmap:**
- Create custom Wazuh rules for missing techniques
- Build Splunk correlation searches
- Automate detection gap reporting
- MITRE ATT&CK coverage heatmap

---

## 🤝 Contributing

Found a better way to test something? Discovered a new detection gap? Open an issue or PR. This lab is a learning environment, and improvements are always welcome.

---

## 📝 License

MIT License - Use this setup for your own learning and testing.

---

## ⚠️ Disclaimer

This lab is for authorized security testing and education only. Techniques demonstrated here should only be used in controlled environments you own or have explicit permission to test.

---

**Built with:** ☕ Coffee, 🔍 Curiosity, and a healthy appreciation for when things don't work as expected.
