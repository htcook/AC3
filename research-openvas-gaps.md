# OpenVAS/Greenbone vs ScanForge — Complete Gap Analysis

## OpenVAS NASL Protocol Handlers (from nasl/ directory)

### Network Protocol Handlers
1. **nasl_http.c / nasl_http2.c** — HTTP/1.1 and HTTP/2 request engine
2. **nasl_ssh.c** — SSH protocol handler with netconf subsystem support
3. **nasl_smb.c** — SMB/CIFS protocol handler for Windows shares
4. **nasl_snmp.c** — SNMP v1/v2c/v3 protocol handler
5. **nasl_socket.c** — Raw TCP/UDP socket operations
6. **nasl_wmi.c** — WMI (Windows Management Instrumentation) queries
7. **nasl_krb5.c** — Kerberos 5 authentication
8. **nasl_packet_forgery.c / _v6.c** — Raw packet crafting (IPv4 + IPv6)
9. **nasl_frame_forgery.c** — Ethernet frame-level packet crafting
10. **capture_packet.c** — Packet capture (pcap-based)

### Crypto & Authentication
11. **nasl_crypto.c / nasl_crypto2.c** — Cryptographic functions
12. **nasl_signature.c** — Digital signature verification
13. **hmacmd5.c** — HMAC-MD5 for NTLM/SMB auth
14. **smb_crypt.c** — SMB-specific crypto (NTLM, NTLMv2)
15. **ntlmssp.c** — NTLM Security Support Provider

### Scanner Infrastructure
16. **nasl_builtin_find_service.c** — Service detection (banner grabbing)
17. **nasl_builtin_openvas_tcp_scanner.c** — Built-in TCP port scanner
18. **nasl_builtin_synscan.c** — SYN stealth scanner
19. **nasl_scanner_glue.c** — Scanner-to-NASL bridge (KB access)
20. **nasl_host.c** — Host resolution, alive detection
21. **nasl_cert.c** — X.509 certificate parsing and validation
22. **nasl_cmd_exec.c** — External command execution
23. **nasl_text_utils.c** — String matching, regex, parsing

### Greenbone Architecture
- **gvmd** — Central orchestrator
- **openvas-scanner** — NASL interpreter scan engine
- **ospd-openvas** — OSP daemon bridge
- **notus-scanner** — Local Security Check scanner (bulk package comparison)
- **greenbone-feed-sync** — 100,000+ NVT feed sync

## CRITICAL GAPS IN SCANFORGE

### 1. Knowledge Base (KB) System — HIGH PRIORITY
OpenVAS uses Redis-backed KB for cross-test state sharing.
ScanForge has template-level state only.

### 2. Service Detection Engine — HIGH PRIORITY
OpenVAS has nasl_builtin_find_service.c for banner grabbing + protocol fingerprinting.
ScanForge relies on nmap, no native service fingerprinting.

### 3. SMB/CIFS Protocol Handler — HIGH PRIORITY
OpenVAS has deep SMB support (share enum, registry, WMI, NTLM).
ScanForge has NONE.

### 4. SNMP Protocol Handler — HIGH PRIORITY
OpenVAS scans SNMP devices (community string brute, MIB walking).
ScanForge has NONE.

### 5. CVSS Scoring Engine — MEDIUM
OpenVAS has built-in CVSS v2/v3 scoring.
ScanForge has severity levels but no CVSS calculator.

### 6. Local Security Checks / Notus — MEDIUM
OpenVAS compares installed packages against known vulnerable versions.
ScanForge has NONE (only remote checks).

### 7. Certificate Validation — LOW-MEDIUM
OpenVAS has X.509 cert chain validation.
ScanForge has basic TLS template only.

### 8. Raw Packet Crafting — LOW
OpenVAS forges raw IP/TCP/UDP/Ethernet packets.
ScanForge has NONE.

## WHAT SCANFORGE DOES BETTER
1. LLM-powered analysis (OpenVAS has no AI)
2. Proof-based verification (re-exploit to confirm)
3. OOB detection (callback server for blind vulns)
4. Authenticated DAST (session-aware web scanning)
5. Ember agent bridge (internal network scanning)
6. Self-improving loop (reassessment + auto-template gen)
7. 30+ TI feed integration (OpenVAS only uses Greenbone feed)
8. Bug bounty intelligence (HackerOne hacktivity)
9. Real-time engagement pipeline with SSE/WS events
