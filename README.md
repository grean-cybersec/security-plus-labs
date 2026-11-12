# Security+ SY0-701 — Hands-On Lab Portfolio

Practical cybersecurity labs built while preparing for the CompTIA Security+ (SY0-701)
certification and a career as a SOC analyst. Each lab includes the objective, tools used,
evidence (screenshots, PCAPs, logs), analysis, and the real-world security relevance.

## Labs

| # | Lab | Tools | Security+ Objectives |
|---|-----|-------|----------------------|
| 01 | [DNS Traffic Analysis](Lab-01-Wireshark-DNS/) | Wireshark, PowerShell | 4.9 |
| 02 | [HTTP Credential Sniffing](Lab-02-HTTP-Credential-Sniffing/) | Wireshark, Python | 2.2, 3.2, 4.5 |
| 03 | [Nmap Network Scanning](Lab-03-Nmap-Network-Scanning/) | Nmap, Wireshark | 4.3, 2.2 |
| 04 | [SIEM Basics: Brute Force Detection](Lab-04-Splunk-SIEM-Basics/) | Splunk, SPL | 2.4, 4.4, 4.9 |
| 05 | [Firewall Rules & Access Control](Lab-05-Firewall-Rules/) | Windows Defender Firewall, PowerShell | 3.2, 4.5 |
| 06 | [Incident Response: Web Server Compromise](Lab-06-Incident-Response/) | Splunk, SPL | 4.8, 4.9, 2.3 |
| 07 | [Purple Team: Detection & Automated Response](Lab-07-Purple-Team-Wazuh/) | Wazuh SIEM, Kali, Nmap, VirtualBox | 2.4, 4.4, 4.5, 4.8, 4.9 |
| 08 | [Writing & Tuning Custom SQLi Detection Rules](Lab-08-SQLi-Detection-Custom-Rules/) | Wazuh SIEM, Kali, DVWA, PCRE2 | 2.4, 4.4, 4.5 |

## Skills Demonstrated
- **Network analysis:** capturing and reading DNS and HTTP traffic at the packet level
- **Reconnaissance:** host discovery and port scanning, interpreting results
- **SIEM and detection:** ingesting logs, writing SPL queries, building alerts, deploying
  Wazuh agents and reading correlated alerts
- **Detection engineering:** writing custom Wazuh rules, measuring false positives, and
  tuning a rule to cut noise without losing coverage
- **Incident response:** reconstructing attack timelines across log sources and reporting
  them with the NIST IR lifecycle and MITRE ATT&CK
- **Automated response:** containing an SSH brute-force attack with Wazuh Active Response
- **Lab engineering:** building an isolated multi-VM SOC lab (attacker, victims, SIEM)
- **Hardening:** creating and verifying firewall rules

## Environment
Windows 10 host, VirtualBox, Kali Linux, Ubuntu Server, Wazuh, Wireshark, Nmap,
Splunk Enterprise, Python, PowerShell, Git.

## About
Aspiring SOC analyst based in Mexico. I document every lab, including what I confirmed
and what the evidence could not prove.

GitHub: [grean-cybersec](https://github.com/grean-cybersec)
