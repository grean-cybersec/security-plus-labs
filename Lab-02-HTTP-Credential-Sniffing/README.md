# Lab 02 — HTTP Traffic Analysis & Credential Sniffing

## Objective
Demonstrate how unencrypted HTTP traffic exposes credentials in plaintext
by capturing a login form submission with Wireshark. Understand why HTTPS
is mandatory for any authentication system.

## Tools Used
- Wireshark 4.6.6 (Windows 10)
- Python 3.14 — built-in HTTP server
- PyCharm — code editor
- Firefox — HTTP client

## Steps Performed
1. Built a simulated corporate login portal using Python HTTP server
2. Served login form over HTTP (port 8080) — no encryption
3. Started Wireshark capture on loopback interface
4. Applied `http` display filter to isolate HTTP traffic
5. Submitted credentials through the login form
6. Located POST request in Wireshark
7. Expanded HTML Form URL Encoded section — credentials visible in plaintext

## Credentials Captured
- Form item: "username" = "realgads"
- Form item: "password" = "realgads123"

Transmitted in plaintext over HTTP — no encryption applied.

## Key Observations
- HTTP POST requests expose form data in plaintext
- Wireshark can extract credentials with zero decryption needed
- Username and password visible under: HTML Form URL Encoded section
- Any attacker on the same network can capture these credentials
- This is the foundation of an on-path attack (formerly Man-in-the-Middle)

## Screenshots
![Credentials Exposed](screenshots/01-http-credentials-exposed.png)
![Login Portal](screenshots/02-http-login-portal.png)
![HTTP Traffic Overview](screenshots/03-http-traffic-overview.png)

## HTTP vs HTTPS Comparison

| | HTTP | HTTPS |
|---|---|---|
| Port | 8080 / 80 | 443 |
| Encryption | None | TLS (Transport Layer Security) |
| Credentials in Wireshark | Visible in plaintext | Encrypted — unreadable |
| Certificate required | No | Yes |
| Safe for login forms | Never | Yes |

## Security Relevance
In a SOC analyst role, detecting unencrypted authentication is critical:
- On-path attacks — attacker intercepts HTTP traffic on the same network
- Credential harvesting — capturing plaintext passwords at scale
- WiFi sniffing — public networks are especially vulnerable

Any login form over HTTP is an automatic Critical finding in a
security assessment or penetration test.

## Mitigation
- Enforce HTTPS on all web applications (TLS 1.2 minimum, TLS 1.3 preferred)
- Implement HSTS (HTTP Strict Transport Security) — forces HTTPS always
- Use MFA (Multi-Factor Authentication) — limits damage if credentials leak
- Deploy network monitoring to detect plaintext authentication attempts

## Lessons Learned
- HTTP is never safe for authentication — credentials travel in plaintext
- Wireshark makes credential sniffing trivial on unencrypted networks
- HTTPS encrypts the entire session — Wireshark only sees TLS handshake
- This attack requires no special tools — only network access and Wireshark