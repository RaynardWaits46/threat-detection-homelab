# Threat Detection Homelab: A Practical SOC Analyst's Testing Environment

![GitHub last commit](https://img.shields.io/github/last-commit/RaynardWaits46/threat-detection-homelab)
[![License](https://img.shields.io/github/license/RaynardWaits46/threat-detection-homelab.svg)](https://github.com/RaynardWaits46/threat-detection-homelab/blob/main/LICENSE)
![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)

# SOC Homelab: Detection Testing + Honeypot Infrastructure

A production-grade SOC analyst homelab demonstrating hands-on skills in:
- Multi-SIEM detection engineering and testing
- Zero-cost honeypot infrastructure deployment
- Threat hunting and log correlation
- MITRE ATT&CK framework application
- Real malware analysis

**Built for learning. Documented for sharing. Deployed for real.**

---

## 🎯 Project Overview

This homelab serves two primary functions:

### 1. **Multi-SIEM Detection Testing Lab**
Testing detection capabilities using standardized techniques to identify coverage gaps.

**Components:**
- **Wazuh** (cloud-hosted on Linode) - SIEM + endpoint monitoring
- **Splunk Enterprise** (self-hosted in Docker) - Log aggregation and correlation
- **Sysmon** - Windows endpoint telemetry collection
- **Atomic Red Team** - Standardized MITRE ATT&CK technique testing
- **WireGuard VPN** - Secure log transport from cloud to on-premise

**Key Achievements:**
- Validated defense-in-depth: EDR blocked 1/3 attacks, SIEM caught 2/3 LOLBIN techniques
- Discovered detection gaps in registry persistence monitoring (Run keys vs Services)
- Implemented multi-source correlation hunting methodology
- Mapped coverage to MITRE ATT&CK framework

### 2. **Zero-Cost Honeypot SIEM**
Capturing and analyzing real-world attacks using isolated honeypot infrastructure.

**Components:**
- **Raspberry Pi** honeypots (Cowrie SSH/Telnet + Dionaea multi-protocol)
- **Elastic Stack** (Elasticsearch + Kibana) for log analysis
- **Filebeat** - Log shipping agent
- **WireGuard VPN** - Encrypted log delivery tunnel
- **Advanced firewall isolation** - RFC1918 blocking with tunnel exceptions

**Key Achievements:**
- Captured **670K+ real attack events** from the internet
- Analyzed captured malware samples (WannaCry, Conficker, Lockbit variants)
- Built production-grade network isolation (mimics enterprise DMZ architecture)
- Achieved **$600/year cost savings** vs cloud alternatives
- Resolved complex infrastructure issues (7-day Dionaea downtime, JSON logging failures)

---

## 🏗️ Architecture

### Network Topology

```
┌─────────────────────────────────────────────────────────────┐
│                    Internet                                  │
└───────────────┬─────────────────────────────────────────────┘
                │
                ├─► Port Forwarding (SSH, Telnet, FTP, SMB, etc.)
                │
    ┌───────────▼──────────────┐
    │  Raspberry Pi (crowdy)   │  ◄─── VLAN 8 (Isolated)
    │  - Cowrie (SSH/Telnet)   │
    │  - Dionaea (multi-proto) │
    │  - Filebeat              │
    └───────────┬──────────────┘
                │
                │ WireGuard Tunnel (10.100.0.0/24)
                │ Encrypted + RFC1918 Blocked
                │
    ┌───────────▼──────────────┐
    │  SERVER-01               │  ◄─── Lab VLAN (VLAN 10)
    │  - Elasticsearch         │
    │  - Kibana                │
    │  - Splunk Enterprise     │
    │  - Windows Test VMs      │
    └──────────────────────────┘
                ▲
                │ WireGuard Tunnel (10.0.0.0/24)
                │
    ┌───────────┴──────────────┐
    │  Wazuh Server (Linode)   │  ◄─── Cloud
    │  - SIEM + Alert Engine   │
    │  - Sysmon Analysis       │
    └──────────────────────────┘
```

### Data Flow

**Detection Testing:**
```
Windows VM → Sysmon → Wazuh Agent → Cloud Wazuh → Splunk Forwarder (via VPN) → Splunk
         └──────────→ Splunk Universal Forwarder → Splunk
```

**Honeypot Attacks:**
```
Internet → Honeypots → JSON Logs → Filebeat → WireGuard → Elasticsearch → Kibana Dashboards
```

---

## 🛠️ Technology Stack

**Security Tools:**
- Wazuh 4.x (SIEM, XDR)
- Splunk Enterprise 9.x
- Sysmon (SwiftOnSecurity config)
- Atomic Red Team
- Cowrie 1.9.1 (SSH/Telnet honeypot)
- Dionaea 1.9.1 (multi-protocol honeypot)
- Filebeat 8.11.0
- Elasticsearch 8.11.0
- Kibana 8.11.0

**Infrastructure:**
- WireGuard (VPN tunneling)
- Docker / Docker Compose
- UniFi Networking (Cloud Gateway Max, VLANs)
- iptables (advanced firewall rules)

**Platforms:**
- Raspberry Pi (ARM64, Raspberry Pi OS)
- Ubuntu 24.04 LTS (cloud)
- Windows Server 2025
- Windows 10/11 (test endpoints)

**Languages & Scripting:**
- PowerShell (testing, automation)
- Bash (firewall scripts, deployment)
- Python (data analysis, future malware analysis)

---

## 📊 Key Findings & Learnings

### Detection Testing Insights

**Week 1-2: Signature-Based Detection**
- ✅ Windows Defender blocked RAT installation immediately (known signature)
- ✅ Wazuh alerted on Meterpreter process creation
- ❌ Custom-encoded payloads bypassed signature detection
- **Takeaway:** Signatures catch known threats, behavioral detection needed for novel attacks

**Week 3: Credential Access Techniques**
- ✅ LSASS memory dumps detected by Wazuh (T1003.001)
- ✅ Registry credential searches caught in Splunk Sysmon logs
- ❌ Chrome password extraction had no Wazuh rules (Splunk visibility only)
- **Takeaway:** Defense-in-depth matters; neither tool alone provides complete coverage

**Week 4-5: Persistence & Discovery**
- ✅ Service creation detected (registry monitoring)
- ❌ Run key persistence completely missed (configuration gap)
- ✅ `net user` discovery commands detected by custom Wazuh rules
- **Takeaway:** Detection rules are only as good as their scope; test everything

### Honeypot Infrastructure Insights

**Attack Patterns (670K+ events):**
- **Top targeted services:** SSH (22), MySQL (3306), SMB (445), MSSQL (1433)
- **Geographic distribution:** China, Russia, US, Germany (top sources)
- **Common credentials:** root/admin, admin/admin, root/password, admin/123456
- **Malware families:** WannaCry variants, Conficker, Lockbit, Mirai

**Technical Challenges Solved:**
- **Dionaea crash-loop (7,114 restarts):** Three root causes (permissions, path config, handler timing)
- **WireGuard port drift:** Fixed with explicit `ListenPort` configuration
- **Firewall rule ordering:** Tunnel subnet exceptions must precede RFC1918 blocks
- **Log volume management:** Implemented aggressive rotation (50MB max, hourly checks)

**Cost Optimization:**
- Cloud SIEM quote: $40-50/month ($480-600/year)
- Self-hosted solution: $0/month (existing hardware)
- **Annual savings:** $480-600

---

## 📝 Documentation & Blog Posts

I document the entire journey on [Medium (@raynardwaits)](https://medium.com/@raynardwaits):

**Honeypot Series:**
- "When Your Honeypot Crashes 7,000 Times" - Dionaea debugging deep-dive
- "722 Attacks, Zero Malware: Infrastructure Troubleshooting" - Root cause analysis
- "Building a Zero-Cost Honeypot SIEM" - Architecture and deployment (4-part series)

**Detection Testing Series:**
- "Testing RAT Detection: Why Modern Defender Makes Blue Team Testing Harder"
- "When EDR Blocks Before Your SIEM Can See" - Defense-in-depth validation
- "Hidden in Plain Sight: Tool Obfuscation and Detection Evasion"
- "Testing Registry Persistence Detection: When Rules Exist But Never Fire"
- "Hunting for Persistence: Finding Malicious Services Among 1,400 Events"

**Integration & Setup:**
- "Integrating Cloud-Hosted Wazuh with On-Premise Splunk" (3-part series)
- "WireGuard VPN for Secure SIEM Log Transport"

---

## 🚀 Getting Started

### Prerequisites

**Hardware:**
- 1x Raspberry Pi 4 (4GB+ RAM recommended)
- 1x Server/PC for Elastic Stack (16GB+ RAM, 4+ cores)
- UniFi gateway (or other VLAN-capable router)

**Software:**
- Docker & Docker Compose
- WireGuard
- Linux experience (Debian/Ubuntu)

### Quick Setup

**1. Deploy Honeypots (Raspberry Pi):**

```bash
# Clone Dionaea/Cowrie configs
git clone https://github.com/RaynardWaits46/threat-detection-homelab
cd honeypot-configs

# Deploy with Docker Compose
docker-compose up -d

# Apply firewall rules (CRITICAL - prevents network pivoting)
sudo bash firewall-honeypot.sh
```

**2. Configure WireGuard Tunnel:**

```bash
# Generate keys
wg genkey | tee privatekey | wg pubkey > publickey

# Configure interface (see configs/wireguard/)
sudo nano /etc/wireguard/wg0.conf

# Enable and start
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0
```

**3. Deploy Elastic Stack (SERVER-01):**

```bash
cd elastic-stack
docker-compose up -d

# Verify
curl http://localhost:9200
```

**4. Configure Filebeat (Pi):**

```bash
# Install and configure
sudo dpkg -i filebeat-8.11.0-arm64.deb
sudo nano /opt/filebeat/filebeat.yml

# Start service
sudo systemctl enable filebeat
sudo systemctl start filebeat
```

**5. Create Kibana Dashboards:**

Access Kibana at `http://localhost:5601` and import provided dashboard JSONs from `configs/kibana/`.

---

## 📈 Future Enhancements

**Short-term:**
- [ ] VirusTotal API integration for automated hash lookups
- [ ] Malware sandbox for dynamic analysis (isolated VM)
- [ ] Custom Splunk correlation rules for multi-stage attacks
- [ ] SOAR integration (TheHive + Cortex)

**Long-term:**
- [ ] Machine learning for anomaly detection
- [ ] Threat intelligence feed integration
- [ ] Automated IOC extraction and blocking
- [ ] Expanding to additional honeypot types (WordPress, IoT devices)

---

## 📜 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

---

## 📧 Contact

**Ian Harding (WH1ZW1T)**
- Email: hardingian@proton.me
- Blog: [medium.com/@raynardwaits](https://medium.com/@raynardwaits)
- LinkedIn: [linkedin.com/in/ianharding33](https://www.linkedin.com/in/ianharding33/)
- Website: [wh1zw1t.com](https://wh1zw1t.com)

---

## 🙏 Acknowledgments

- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) for standardized testing framework
- [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) for Sysmon configuration
- [Wazuh](https://wazuh.com/) and [Elastic](https://www.elastic.co/) for excellent documentation
- The cybersecurity community for continuous learning and inspiration

---


**Built with:** ☕ Coffee, 🔍 Curiosity, and a healthy appreciation for when things don't work as expected.
