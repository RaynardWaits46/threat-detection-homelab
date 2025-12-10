# Lab Infrastructure Setup

A comprehensive guide to building a threat detection homelab with network segmentation, cloud SIEM integration, and secure data forwarding.

---

## Lab Overview

**Purpose:** Create an isolated testing environment for validating detection capabilities against real attack techniques while maintaining secure integration with production monitoring tools.

**Key Components:**
- Attack simulation machine (Kali Linux)
- Target endpoints (Windows 10/11 VMs)
- Cloud-hosted SIEM (Wazuh)
- On-premise log aggregation (Splunk)
- Secure tunnel for cloud-to-local integration (WireGuard VPN)

---

## Network Architecture

### VLAN Segmentation

**VLAN Design:**
- **VLAN 1 (Main Network):** Production systems and workstations
- **Lab VLAN (VLAN 10):** Security testing environment (all VMs and Docker host)
- **Guest Network:** Isolated guest access
- **IoT Network:** Smart home devices isolated

**Why This Design:**
Network segmentation ensures that attack simulations and malware testing cannot contaminate production systems. The Lab VLAN is completely isolated with unidirectional firewall rules.

### Firewall Rules

**Traffic Flow Control:**
```
Main Network → Lab VLAN:
  - Allowed: RDP (3389), Splunk Web (8000), Universal Forwarder (9997), Syslog (514)
  - Purpose: Management and monitoring access

Lab VLAN → Main Network:
  - Blocked: All traffic
  - Purpose: Prevent lateral movement from compromised test systems

WAN → Lab VLAN:
  - Allowed: WireGuard VPN (UDP 51820) with port forward to Docker host
  - Purpose: Secure Wazuh-to-Splunk integration
  - All other inbound traffic blocked
```

**Stateful Firewall:**
Return traffic from allowed connections is automatically permitted (established/related state tracking).

### Remote Access Configuration

**SSH Access:**
Attack machine (Main Network) can SSH to target endpoints (Lab VLAN) through firewall rules. This allows command execution for testing without moving the attack machine into the test environment.

**Why This Works:**
Simulates realistic attack scenarios where an attacker has initial access to a system and needs to execute commands remotely.

---

## Infrastructure Components

### Attack Machine
- **OS:** Kali Linux VM
- **Architecture:** ARM64 (adjust based on your host)
- **Network:** Main Network VLAN
- **Purpose:** Attack simulation, script execution, SSH command runner
- **Tools:** Standard Kali toolkit, Atomic Red Team execution

### Target Endpoints

**Windows 10 VM (Primary Test Machine):**
- **Hostname:** Use generic naming (e.g., "WIN10-TEST")
- **Wazuh Agent ID:** 001
- **IP:** Static IP in Lab VLAN range (e.g., 192.168.10.x)
- **Monitoring:** Wazuh agent + Splunk Universal Forwarder + Sysmon

**Windows 11 VM (Secondary):**
- **Wazuh Agent ID:** 004
- **Status:** Can be powered off when not actively testing
- **Purpose:** Testing detection across different Windows versions

### Network Hardware
- **Gateway:** UniFi Cloud Gateway (or equivalent managed gateway)
- **Switch:** Managed switch supporting VLANs (8-port minimum)
- **Management:** Centralized controller for firewall rule management

---

## SIEM Stack Configuration

### Wazuh (Cloud-Hosted)

**Deployment:**
- **Platform:** Cloud VPS (Linode, DigitalOcean, AWS, etc.)
- **OS:** Ubuntu 24.04 LTS
- **Version:** Wazuh 4.x
- **Agent Communication:** TCP port 1514

**What Wazuh Does:**
1. Receives Sysmon events from Windows agents
2. Applies detection rules against event stream
3. Generates alerts when rules match
4. Stores alerts in `/var/ossec/logs/alerts/alerts.json`

**Sysmon Configuration:**
- Using SwiftOnSecurity's Sysmon config (heavily vetted, reduces noise)
- Monitors: Process creation, network connections, registry modifications, file creation
- Event channels: Security, System, Application, Sysmon/Operational

**Known Detection Rules:**
- **Rule 92031:** Discovery activity executed (T1087 - Account Discovery)
- **Rule 92033:** Discovery activity spawned via PowerShell execution
- **Rule 92027:** PowerShell process spawned PowerShell instance
- **Rule 92012:** Registry Run Keys persistence (scoped to Services paths only)
- **Rule 92307:** New service creation in registry
- **Rule 92035:** Net.exe domain discovery command
- **Rule 92052:** Windows command prompt started by abnormal process
- **Rule 92034:** Discovery activity spawned via cmd shell execution

**MITRE ATT&CK Integration:**
Wazuh automatically maps detections to MITRE ATT&CK framework. Alert JSON includes:
- `rule.mitre.id` - Technique IDs (e.g., T1087.001)
- `rule.mitre.tactic` - Tactic names
- `rule.mitre.technique` - Technique names

**Important:** MITRE IDs stored as arrays, use wildcards in Splunk searches: `rule.mitre.id=*`

**Detection Coverage Gaps:**
- ✅ HKLM\System\CurrentControlSet\Services\* (service creation monitored)
- ❌ HKCU\Software\Microsoft\Windows\CurrentVersion\Run\* (user persistence NOT monitored)
- ❌ HKLM\Software\Microsoft\Windows\CurrentVersion\Run\* (system persistence NOT monitored)

This means Rule 92012 exists but never fires for standard Run key persistence techniques.

### Splunk Enterprise (On-Premise)

**Deployment:**
- **Platform:** Docker Desktop
- **Container:** splunk/splunk:latest (or specific version)
- **Host:** Windows or Linux machine on Lab VLAN
- **License:** Splunk Free (500MB/day ingestion limit)

**Docker Run Command Example:**
```bash
docker run -d \
  --name splunk-enterprise \
  -p 8000:8000 \
  -p 9997:9997 \
  -p 514:514/udp \
  -e SPLUNK_START_ARGS='--accept-license' \
  -e SPLUNK_PASSWORD='<your-password>' \
  splunk/splunk:latest
```

**Port Configuration:**
- **8000/tcp:** Web interface (HTTPS)
- **9997/tcp:** Universal Forwarder receiving port
- **514/udp:** Syslog (optional, not actively used in this lab)

**Indexes Created:**
- **wazuh:** Wazuh alerts forwarded through VPN tunnel
- **sysmon:** Raw Sysmon events from Windows endpoints
- **windows_security:** Windows Security event logs

**Important Timezone Note:**
Splunk may display `_time` field with offset from actual system time (e.g., +5 hours). Always use Splunk's displayed time for time range searches. Expanding individual events shows the correct system time.

### Splunk Universal Forwarder (Windows Endpoints)

**Installation:**
- Download from Splunk.com
- Install as LocalSystem (required for Sysmon log access)
- Configure outputs.conf to forward to Splunk server on port 9997

**What It Forwards:**
- Windows Security logs
- Windows System logs
- Windows Application logs
- Sysmon Operational logs

**outputs.conf Example:**
```
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = <SPLUNK_IP>:9997
```

---

## Secure Integration: WireGuard VPN

### Why WireGuard?

**Security Decision Matrix:**

| Option | Pros | Cons | Chosen? |
|--------|------|------|---------|
| Port forward Splunk | Simple | Exposes SIEM to internet attacks | ❌ No |
| Dynamic DNS + SSL/TLS | Encrypted | Still exposes port 9997 | ❌ No |
| WireGuard VPN | Cryptographically secure, silent to scans | Requires VPN setup | ✅ Yes |

**Key Benefits:**
1. **Cryptographic Security:** No brute force possible with proper key management
2. **Stealth:** Silent to unauthorized connection attempts (no banner/response)
3. **Minimal Attack Surface:** Only UDP 51820 exposed, not Splunk ports
4. **Modern Protocol:** Audited, proven encryption

### WireGuard Configuration

**Tunnel Network:** 10.0.0.0/24
- **Splunk Host:** 10.0.0.1
- **Wazuh Server:** 10.0.0.2

**Configuration Steps:**

1. **Install WireGuard on both endpoints:**
   ```bash
   # Ubuntu (Wazuh server)
   sudo apt update
   sudo apt install wireguard
   
   # Windows (Splunk host)
   # Download and install from wireguard.com
   ```

2. **Generate keys on both endpoints:**
   ```bash
   wg genkey | tee privatekey | wg pubkey > publickey
   ```

3. **Configure wg0.conf on Wazuh server:**
   ```
   [Interface]
   Address = 10.0.0.2/24
   PrivateKey = <server-private-key>
   ListenPort = 51820
   
   [Peer]
   PublicKey = <client-public-key>
   AllowedIPs = 10.0.0.1/32
   ```

4. **Configure wg0.conf on Splunk host:**
   ```
   [Interface]
   Address = 10.0.0.1/24
   PrivateKey = <client-private-key>
   
   [Peer]
   PublicKey = <server-public-key>
   AllowedIPs = 10.0.0.0/24
   Endpoint = <WAZUH_PUBLIC_IP>:51820
   PersistentKeepalive = 25
   ```

5. **Enable and start tunnels:**
   ```bash
   # Linux
   sudo systemctl enable wg-quick@wg0
   sudo systemctl start wg-quick@wg0
   
   # Verify
   sudo wg show
   ping 10.0.0.1  # From Wazuh to Splunk
   ```

6. **Port forward UDP 51820** from your WAN to Splunk host internal IP (configure on router/gateway)

### Splunk Universal Forwarder on Wazuh Server

**Purpose:** Forward Wazuh alerts to Splunk through encrypted VPN tunnel.

**Installation:**
```bash
# Download forwarder for Linux
wget -O splunkforwarder.tgz 'https://download.splunk.com/...'
tar xvzf splunkforwarder.tgz -C /opt/

# Configure to forward to Splunk over VPN tunnel
/opt/splunkforwarder/bin/splunk add forward-server 10.0.0.1:9997 -auth admin:password

# Monitor Wazuh alerts JSON file
/opt/splunkforwarder/bin/splunk add monitor /var/ossec/logs/alerts/alerts.json \
  -index wazuh -sourcetype wazuh:alerts

# Ensure file permissions allow reading
sudo chmod 644 /var/ossec/logs/alerts/alerts.json

# Start forwarder
/opt/splunkforwarder/bin/splunk start
```

**Verification:**
```bash
# Check forwarding status
sudo /opt/splunkforwarder/bin/splunk list forward-server

# Watch logs being sent
sudo tail -f /opt/splunkforwarder/var/log/splunk/splunkd.log | grep Connected

# In Splunk web interface
index=wazuh | head 10
```

---

## Data Flow Architecture

```
Windows Endpoint
    ↓
Sysmon (Event IDs 1, 3, 11, 13)
    ↓
┌──────────────────────────────────────────────────────┐
│                                                      │
│  Wazuh Agent              Universal Forwarder       │
│  (to cloud server)        (to Splunk local)         │
│                                                      │
└─────────┬────────────────────────────────┬──────────┘
          │                                │
          ↓                                ↓
   Wazuh Server (Cloud)             Splunk (Local)
   - Applies detection rules        - index=sysmon
   - Generates alerts                 (ALL raw events)
   - Outputs alerts.json
          │
          ↓
   Splunk Forwarder
   (through WireGuard VPN tunnel)
          │
          ↓
   Splunk index=wazuh
   (ONLY events where rules matched)
```

**Key Insight:**
- **index=sysmon** = Complete telemetry (100% visibility)
- **index=wazuh** = Curated alerts (selective based on rules)
- Gap analysis: Comparing these two reveals detection blind spots

---

## Sysmon Event Coverage

**What Sysmon Captures:**

| Event ID | Category | Captured? | Notes |
|----------|----------|-----------|-------|
| 1 | Process Creation | ✅ Yes | ALL command execution |
| 3 | Network Connection | ✅ Yes | Visible in Splunk, NOT forwarded to Wazuh |
| 11 | File Creation | ⚠️ Filtered | SwiftOnSecurity config heavily filters |
| 13 | Registry Modification | ✅ Yes | Forwarded to both Wazuh and Splunk |

**SwiftOnSecurity Config Impact:**
- Dramatically reduces noise (millions of events → thousands)
- Event ID 11 only captures files in specific directories (Downloads, temp, suspicious locations)
- Excludes known-good processes and paths

---

## Testing Framework

### Atomic Red Team

**Installation on Windows:**
```powershell
# Requires PowerShell 5.1+ and admin privileges

# Add Windows Defender exclusion (required for installation)
Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"

# Install Atomic Red Team
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
Install-AtomicRedTeam -getAtomics

# Import module
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

**Usage:**
```powershell
# List available tests for a technique
Invoke-AtomicTest T1087.001 -ShowDetails

# Run specific test
Invoke-AtomicTest T1087.001 -TestNumbers 1

# Cleanup after test
Invoke-AtomicTest T1087.001 -TestNumbers 1 -Cleanup
```

### Noise Generator Script

**Purpose:** Simulate normal user activity during testing to create realistic baseline noise.

**Activities Simulated:**
- Office application usage (Word, Excel, PowerPoint)
- Web browsing (Edge, Chrome)
- File system operations
- Print queue checks
- Network drive enumeration

**Usage:**
```powershell
.\noise-generator.ps1
# Runs for 45 minutes by default
# Creates realistic event volume in Sysmon logs
```

---

## Current Status & Known Issues

### What's Working ✅

- WireGuard VPN tunnel (Wazuh cloud ↔ Splunk local)
- Splunk Universal Forwarder sending alerts through encrypted tunnel
- Wazuh alerts appearing in Splunk with MITRE ATT&CK mapping
- SSH remote access (Main Network → Lab VLAN)
- Dual SIEM visibility (raw telemetry + curated alerts)
- Network segmentation with unidirectional firewall rules
- Sysmon capturing all process execution (Event ID 1)
- No exposed SIEM ports (only WireGuard UDP 51820)

### Known Limitations ⚠️

- **Sysmon Event ID 3** not forwarded to Wazuh (visible in Splunk only)
- **Sysmon Event ID 11** heavily filtered (SwiftOnSecurity config)
- **Detection rules** exist for SOME techniques but not others
- **Registry monitoring** limited to Services paths (Run keys not monitored)
- **Endpoint-level monitoring only** (no network-layer IDS/IPS)

---

## Security Principles Applied

1. **Defense in Depth:** Multiple security layers (network segmentation + VPN + authentication)
2. **Least Privilege:** Firewall rules only allow necessary traffic
3. **Encryption in Transit:** All Wazuh-to-Splunk traffic encrypted via WireGuard
4. **Attack Surface Reduction:** No exposed SIEM ports, only VPN endpoint
5. **Network Isolation:** Lab VLAN prevents contamination of production systems
6. **Monitoring and Logging:** Comprehensive visibility across all endpoints

---

## Next Steps

1. **Test Detection Coverage:** Use Atomic Red Team to validate what Wazuh detects
2. **Document Gaps:** Identify which techniques have detection rules vs. blind spots
3. **Create Custom Rules:** Build Wazuh rules for missing techniques
4. **Correlation Searches:** Develop Splunk searches for multi-event detection
5. **Automate Testing:** Script regular validation of detection capabilities

---

## Troubleshooting Tips

**No data in index=wazuh:**
- Check WireGuard tunnel: `sudo wg show`
- Verify forwarder status: `sudo /opt/splunkforwarder/bin/splunk status`
- Check alerts.json permissions: `ls -la /var/ossec/logs/alerts/alerts.json`
- Watch forwarder logs: `sudo tail -f /opt/splunkforwarder/var/log/splunk/splunkd.log | grep Connected`

**No data in index=sysmon:**
- Verify Universal Forwarder on Windows is running
- Check outputs.conf configuration
- Confirm Sysmon service is running: `Get-Service Sysmon64`
- Verify Splunk is listening on port 9997: `netstat -an | findstr 9997`

**WireGuard tunnel issues:**
- Verify both endpoints: `sudo wg show` (Linux) or WireGuard GUI (Windows)
- Test connectivity: `ping 10.0.0.1` and `ping 10.0.0.2`
- Check port forward on router (UDP 51820)
- Restart tunnel: `sudo systemctl restart wg-quick@wg0`

---

## Additional Resources

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Splunk Universal Forwarder Guide](https://docs.splunk.com/Documentation/Forwarder/)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [WireGuard Documentation](https://www.wireguard.com/quickstart/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
