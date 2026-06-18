# Lab 01 — Wireshark DNS Traffic Analysis

## Objective
Capture and analyze live DNS (Domain Name System) traffic using Wireshark
to understand query/response structure and identify security implications
of unencrypted DNS.

## Tools Used
- Wireshark 4.x (Windows 10)
- PowerShell — nslookup, ipconfig /flushdns

## Steps Performed
1. Flushed local DNS cache with `ipconfig /flushdns`
2. Queried public domains using `nslookup` (google.com, github.com, amazon.com)
3. Captured live DNS traffic in Wireshark over Wi-Fi interface
4. Applied `dns` display filter to isolate DNS packets
5. Analyzed query and response packet structure (Transaction ID, flags, answers)
6. Identified load balancing — amazon.com resolved to 3 different IPs
7. Saved capture as `dns-capture.pcap`

## Key Observations
- DNS queries use UDP port 53
- Each query/response pair shares the same Transaction ID (0x0002)
- amazon.com returned 3 IPs — evidence of load balancing:
  - 98.82.161.185
  - 98.87.170.74
  - 98.87.170.71
- DNS response time: 7.846700 ms (normal range: under 100ms)
- Background DNS traffic observed from OS (safebrowsing.googleapis.com)
- Traffic captured over IPv6 (2806:2f0::/32 — Latin American range)
- DNS traffic is unencrypted — fully visible to any network observer

## Screenshots
![DNS Query and PowerShell](screenshots/01-dns-query-analysis.png)
![DNS Response Detail](screenshots/02-dns-response-detail.png)
![DNS Traffic Overview](screenshots/03-dns-traffic-overview.png)

## Security Relevance
In a SOC analyst role, DNS logs are a primary detection source for:
- **C2 (Command and Control) beaconing** — malware calling home repeatedly
- **DNS tunneling** — data exfiltration hidden inside DNS queries
- **DGA (Domain Generation Algorithms)** — malware generating random domains

Unencrypted DNS is why secure alternatives exist:
- **DoH (DNS over HTTPS)** — encrypts DNS inside HTTPS traffic
- **DoT (DNS over TLS)** — encrypts DNS using TLS on port 853

## Lessons Learned
- DNS is foundational — nearly every network attack touches DNS
- Wireshark display filters isolate specific protocols instantly
- Transaction IDs link queries to responses — key for timeline reconstruction
- Saving PCAP files preserves network evidence for incident response