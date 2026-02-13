# Network Threat Hunting & Automated Response Lab

I built an advanced **network threat hunting and automated response lab** that detects sophisticated attacks like C2
beaconing, DNS tunneling, and data exfiltration in real time using a **multi-layered detection and SOAR pipeline**.
The system combines **Suricata IDS** for signature-based detection, **Zeek NSM** for behavioral analytics,
**Splunk** for correlation, and **Tines SOAR** for automated but analyst-approved response, cutting total response
time from **20–30 minutes to under 5 minutes**.

[View Code](#) <!-- Replace with your GitHub repository link if desired -->

![Network Threat Hunting Lab Architecture](public/Network_Analysis_Lab/overview.svg)

---

## The Problem

Modern network attacks use **custom C2 frameworks, covert channels, and DNS tunneling** that easily evade pure
signature-based IDS. In many SOCs:

- **Analysts burn 20–30 minutes per incident** manually pivoting across tools, enriching IPs/domains,
  and requesting firewall changes.
- **Signature-only detection** misses unknown tools and low-and-slow exfiltration.
- **False positives (15%+)** create alert fatigue and slow down real investigations.
- **Response is manual** – even after detection, engineers must hand-build firewall rules and document actions.

This lab is designed to show how a **multi-layer detection + automated response** approach can fix these gaps in a
way that mirrors a real-world SOC.

---

## The Solution

I implemented an end-to-end **Network Traffic Capture → Signature Detection (Suricata) → Behavioral Analysis (Zeek)
→ SIEM Correlation (Splunk) → SOAR Automation (Tines) → Automated Response (PowerShell + Windows Firewall)** pipeline,
with **human approval** for critical containment actions.

**Key outcomes:**

- **75%+ reduction** in total response time (20–30 minutes → < 5 minutes)
- **93% detection rate** across 15 attack scenarios
- **False positives cut from ~15% to ~3%**
- **85% reduction** in repetitive analyst workload
- Ability to **detect unknown C2 traffic** with no public signatures

---

## Lab Architecture

- **Attacker – Kali Linux**
  - Custom Python C2 server
  - Tools to generate C2 beaconing, DNS tunneling, and data exfiltration

- **Monitoring – Ubuntu 24.04 Server**
  - **Suricata** for signature-based IDS
  - **Zeek** for network security monitoring and behavioral analytics
  - **Splunk Enterprise** as the central SIEM

- **Victim – Windows 10 / 11**
  - **Sysmon** for rich endpoint telemetry
  - **PowerShell Remoting (WinRM)** enabled
  - Windows Firewall used for automated IP blocking

Supporting resources (in the repo):

- `public/Network_Analysis_Lab/overview.svg` – architecture overview
- `public/Network_Analysis_Lab/lab-setup-overview.png` – lab environment layout

---

## Step-by-Step Implementation

### Phase 1: Network Security Monitoring Setup

I deployed **Suricata IDS** and **Zeek NSM** on Ubuntu to capture and analyze mirrored network traffic:

- Configured the monitoring interface in promiscuous mode for full packet capture.
- Installed and configured Suricata with the **Emerging Threats** ruleset plus custom rules.
- Deployed Zeek for protocol analysis and behavioral detection.
- Verified both tools were actively capturing and logging traffic.

Screenshots (stored under `public/Network_Analysis_Lab`):

- `suricata-installed.png` – Suricata installation completed
- `suricata-configurations.png` – Suricata configuration for monitored interface
- `suricata-started-after-configurations.png` – Suricata running after configuration
- `zeek-installed.png` – Zeek successfully installed
- `zeek-network-configurations-.png` – Zeek network interface configuration
- `zeek-deploy&started-after-scripts.png` – Zeek deployed and started with custom scripts
- `can-see-zeek-current-logs.png` – Verifying live Zeek logs

---

### Phase 2: SIEM Integration & Log Correlation (Splunk)

I installed **Splunk Enterprise** and integrated it with Suricata and Zeek using **Splunk Universal Forwarders**:

- Created custom indexes for `suricata_alerts`, `zeek_conn`, and `zeek_dns`.
- Configured forwarders on the Ubuntu monitoring host (and Windows where needed).
- Built correlation searches for:
  - C2 beaconing patterns (regular intervals, consistent packet sizes)
  - DNS tunneling indicators (long subdomains, high query volume)
  - Data exfiltration (large outbound transfers, unusual destinations)

Relevant screenshots:

- `splunk-downloaded.png` – Splunk package installation
- `splunk-dashboard-accessed.png` – Splunk UI access verified
- `splunkforwarder-installed-on-windows.png` – Forwarder deployed on Windows
- `splunkforwarder-configurations.png` – Forwarder configuration for log sources
- `enable-forwarding-splunk.png` – Enabling log forwarding
- `restarting-splunkforwarder-after-configurations.png` – Restarting forwarder after changes
- `can-see-logs-in-splunk-dashboard.png` – Network security data visible in Splunk
- `IOCs-query-at-splunk.png` – Searching IOCs and correlated detections

---

### Phase 3: Custom C2 Server Development

To avoid relying on commercial red-team tools, I built a **Python-based C2 server** and a simple PowerShell agent:

- C2 server:
  - Implements HTTP/HTTPS beaconing with configurable intervals and jitter.
  - Tracks agent IDs, hostnames, and last-seen timestamps.
  - File: `public/Network_Analysis_Lab/c2_server.py`
- PowerShell agent (Windows):
  - Periodic HTTP POST beacons with host and system metadata.
  - Configurable interval and jitter to emulate real malware C2.

Screenshots:

- `running-c2-server.py-in-kali.png` – C2 server running on Kali
- `success-beacon-at-kali.png` – Successful beacons received by the C2 server
- `sucess-beacon-on-windows-victim-machine.png` – Beaconing confirmed from the Windows victim

Supporting detection scripts:

- `c2-beaconing-script(zeek).txt` – Zeek script for C2 beacon detection
- `detect-data-exfil-script(zeek).txt` – Zeek script for exfiltration pattern detection

---

### Phase 4: Threat Detection Testing

I validated detection quality across **15 attack scenarios**, including:

- C2 beaconing with different intervals and jitter profiles
- DNS tunneling attempts with encoded payloads
- Data exfiltration using HTTP and other protocols
- Nmap-based port scanning and basic lateral movement indicators

Screenshots:

- `perform-nmap-scans-on-both-vms.png` – Scanning between Kali and Windows
- `can-see-nmap-packets-from-kali-to-win-vm.png` – Captured scan traffic
- `suricata-custom-rules.png` – Custom Suricata ruleset for these attacks
- `suricata-detected-logs.png` – Suricata alerts firing on malicious traffic
- `can-see-zeek-detected-logs.png` – Zeek detecting anomalous behavior

---

### Phase 5: SOAR Automation with Tines

I then built an automated **Tines SOAR** workflow that consumes Splunk alerts and orchestrates enrichment,
notification, and response:

- Splunk forwards high-fidelity alerts to Tines via webhook/HEC.
- Tines parses the payload and runs the automation story.
- Alerts include all required context (source/destination IP, signatures, severity, and mapped techniques).

Key screenshots:

- `creating-alert-at-splunk.png` – Splunk correlation search and alert configuration
- `fetched-data-from-splunk-using-webhook.png` – Tines receiving alert payloads
- `automation-workflow-overview.png` – Full Tines workflow showing stages and decisions
- `user-prompt-box-in-automation.png` – Human approval prompt inside the automation

---

### Phase 6: Alert Distribution (Slack & Email)

For analyst visibility and fast decision-making, I integrated:

- **Slack** – Primary SOC notification channel with context-rich messages.
- **Email** – Additional notification path for formal visibility.

Screenshots:

- `slack-notifications.png` – SOC channel alerts with incident details
- `notification-sent-to-slack.png` – Example Tines → Slack notification
- `received-alert-at-email.png` – Email alert with incident metadata

---

### Phase 7: Automated Response Implementation

I implemented automated response via **PowerShell Remoting and Windows Firewall**:

- Enabled WinRM and PSRemoting on the Windows victim.
- Created a PowerShell script that:
  - Connects remotely using a dedicated service account.
  - Creates a named Windows Firewall rule to block the malicious IP.
  - Logs the action (timestamp, analyst, IP, rule name) for auditing.
- Tines triggers this script only after **explicit analyst approval** in Slack.

Screenshots:

- `enable-PSremoting-to-block-ip.png` – PSRemoting configuration and verification
- `block-ip-script-confiugration-on-windows.png` – Script and firewall rule configuration
- `sysmon-installed-on-windows.png` – Sysmon installed for endpoint visibility

---

## Results & Impact

| Metric                | Before Automation | After Automation | Improvement      |
|-----------------------|-------------------|------------------|------------------|
| Time to Detect        | 5–10 min          | < 30 seconds     | ~95% faster      |
| Time to Enrich        | 10–15 min         | < 10 seconds     | ~98% faster      |
| Time to Respond       | 15–20 min         | < 1 minute       | ~95% faster      |
| Total Response Time   | 30–45 min         | < 5 minutes      | ~83% faster      |
| False Positive Rate   | ~15%              | ~3%              | ~80% reduction   |
| Detection Rate        | Unknown           | 93%              | Quantified       |

Additional outcomes:

- ~85% reduction in analyst manual workload
- Reliable detection of custom C2 traffic without public signatures
- Consistent, auditable response across incidents
- Behavioral analytics filling gaps left by signatures

---

## Key Capabilities Demonstrated

- **Network Security Monitoring** – Deploying and tuning Suricata IDS and Zeek NSM
- **Detection Engineering** – Custom Suricata rules and Zeek scripts for C2, DNS tunneling, and exfiltration
- **Threat Hunting** – Proactively validating detections against custom C2 and scripted attack scenarios
- **SIEM Administration** – Splunk index design, data onboarding, and correlation searches
- **SOAR Development** – Tines story design with human-in-the-loop automation
- **Threat Intelligence Integration** – (Designed) enrichment workflow using AbuseIPDB and VirusTotal
- **Red Team Simulation** – Python C2 and PowerShell agent for realistic adversary emulation
- **Automated Response** – PowerShell Remoting and Windows Firewall rule automation
- **Alert Tuning** – Reducing false positives via rule and baseline refinement
- **MITRE ATT&CK Mapping** – Mapping detections to common techniques used in real intrusions

---

## Tools & Technologies

- **Detection & Monitoring**
  - Suricata IDS
  - Zeek NSM
  - Sysmon

- **SIEM**
  - Splunk Enterprise (with Universal Forwarders and HEC)

- **SOAR & Automation**
  - Tines SOAR
  - PowerShell Remoting (WinRM)
  - Windows Firewall
  - Slack + Webhooks

- **Threat Intelligence (Design)**
  - AbuseIPDB API
  - VirusTotal API
  - MITRE ATT&CK Framework

- **Infrastructure**
  - Ubuntu 24.04 LTS (monitoring host)
  - Windows 10/11 (endpoints)
  - Kali Linux (attacker)
  - Python (C2 server)
  - PowerShell (C2 agent and response scripts)

---

## Real-World Applications

This lab demonstrates **production-style SOC capabilities**:

- **Multi-layered detection** – Combining signatures and behavioral analytics to catch both known and unknown threats.
- **Enterprise scalability** – Architecture that can be extended to 1000+ endpoints and multiple network segments.
- **Integrated threat intelligence and correlation** – Centralized view in Splunk and orchestrated response in Tines.
- **Compliance-ready workflows** – Full audit trail of decisions and actions for frameworks like NIST, SOC 2, and ISO 27001.
- **Reduced alert fatigue** – Significantly fewer false positives, focusing analyst time on real threats.

---

## Future Enhancements

Planned improvements for the next evolution of this lab:

- Add **Elastic Security (ELK Stack)** as an additional SIEM for comparison and redundancy.
- Integrate with **MISP** for automated threat intelligence sharing.
- Implement **automated forensic collection** (PCAPs, memory images, key logs) on high-severity alerts.
- Explore **ML-based anomaly detection** on Zeek and Suricata data.
- Extend coverage to **cloud environments** (AWS, Azure) and hybrid architectures.
- Integrate with **ticketing systems** (ServiceNow/Jira) for incident tracking.
- Add **automated containment** options like VLAN isolation or EDR quarantine.

---

## Important Note: Lab Environment

This project was built and tested in a **controlled home lab**, not a live production SOC. The custom C2 server and
attack traffic were created **solely for educational and defensive testing purposes**.

In a real production rollout, I would:

- Harden PSRemoting and WinRM and apply strict RBAC.
- Use a secrets manager for all API keys and credentials.
- Enforce TLS everywhere and add HA/DR for monitoring components.
- Implement formal change management and incident response procedures.
- Perform extensive testing and legal/compliance review before enabling automated actions in live environments.

This case study is meant to highlight my **network detection engineering, threat hunting, SIEM/SOAR integration,
and automated incident response** skills in a realistic but safe lab setting.

