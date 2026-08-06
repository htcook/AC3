# NIST SP 800-81r3 DNS Security Research — Key Findings for ScanForge

**Source:** NIST SP 800-81r3 (March 2026) — Secure Domain Name System (DNS) Deployment Guide
**Authors:** Scott Rose (NIST), Cricket Liu & Ross Gibson (Infoblox)
**Supersedes:** NIST SP 800-81-2 (Sept 2013) — first update in 13 years

## Three Core Pillars
1. **Secure the DNS infrastructure** — dedicated servers, geographic distribution, hidden primaries
2. **Ensure integrity of DNS system and configuration** — DNSSEC, zone management, record hygiene
3. **Implement Protective DNS as a cybersecurity control** — block malicious queries, threat intel integration

## DNS Attack Vectors for Scanning/Testing (from SP 800-81r3 + analysis articles)

### 1. Dangling CNAME Records (Subdomain Takeover)
- CNAME points to canonical name whose parent domain has lapsed in registration
- Attacker registers expired domain → takes over resolution → serves malicious content under trusted name
- **Test:** Enumerate all CNAME records, check if canonical targets are still registered/controlled

### 2. Lame Delegations (Subdomain Hijacking)
- Subdomain delegated to DNS hosting provider, contract lapses, delegation record not removed
- Attacker contracts with same provider → hijacks resolution for subdomain
- **Test:** Validate all NS delegations are still authoritative, check for lame delegations

### 3. Lookalike/Typosquat Domains
- Subtle character substitutions, international homoglyphs, re-registered retired domains
- Used for phishing, malware distribution, brand impersonation
- **Test:** Generate permutations of target domain, check registration status

### 4. DNS Zone Transfer Exposure
- Misconfigured authoritative servers allowing AXFR/IXFR to unauthorized clients
- Reveals complete zone contents (all subdomains, IPs, MX records, etc.)
- **Test:** Attempt zone transfer against all NS records

### 5. DNSSEC Misconfiguration
- Missing DNSSEC signing on authoritative zones
- Expired or invalid RRSIG signatures
- Incorrect NSEC/NSEC3 configuration
- Weak algorithms (RSA < 2048, deprecated algorithms)
- **Recommended algorithms:** ECDSA P-256/P-384, Ed25519, Ed448 (prefer over RSA)
- **RRSIG validity:** 5-7 days recommended (limits compromise window)
- **NSEC vs NSEC3:** NSEC preferred (NSEC3 overhead not justified for zone walking protection)
- **Test:** Validate DNSSEC chain, check algorithm strength, check RRSIG validity periods

### 6. Encrypted DNS Gaps
- DNS over TLS (DoT) — TCP port 853
- DNS over HTTPS (DoH) — TCP/UDP port 443
- DNS over QUIC (DoQ) — UDP port 853
- U.S. Government requires FCEB agencies to use encrypted DNS
- **Test:** Check if organization supports encrypted DNS, detect rogue DoT/DoH/DoQ bypassing controls

### 7. DNS Information Leakage
- Excessive information in DNS responses
- Missing split-horizon DNS configuration
- Public-facing records exposing internal infrastructure
- HINFO, TXT, LOC records revealing sensitive info
- **Test:** Query for information-leaking record types, check for split-horizon

### 8. Recursive/Authoritative Separation
- Internet-facing server configured for both recursive AND authoritative = security risk
- Should be separated on different servers/network segments
- **Test:** Check if authoritative servers also respond to recursive queries

### 9. DNS Cache Poisoning Vulnerability
- Forged DNS responses accepted by resolvers without DNSSEC validation
- **Test:** Check if resolvers validate DNSSEC, check source port randomization

### 10. DNS Tunneling / Data Exfiltration
- Encoding data in DNS queries/responses to bypass security controls
- C2 communication over DNS
- **Test:** Analyze DNS query patterns for anomalous lengths, entropy, frequency

### 11. TTL Misconfiguration
- TTL of zero explicitly prohibited
- Values below 30 seconds discouraged for DNSSEC-signed records
- Recommended range: 1800 seconds (30 min) to 86400 seconds (1 day)
- **Test:** Check TTL values across all record types

### 12. Protective DNS Deployment Gaps
- No DNS firewall / Response Policy Zones (RPZs)
- DNS query logs not integrated with SIEM
- No correlation of DNS data with DHCP lease histories
- **Test:** Check for protective DNS indicators, RPZ deployment

### 13. Infrastructure Architecture Weaknesses
- Single authoritative server (no redundancy)
- Servers not on separate network segments
- No geographic distribution
- DNS co-hosted with unrelated services
- No hidden primary authoritative server
- **Test:** Enumerate NS records, check geographic distribution, check for hidden primary

## Key NIST Recommendations for Test Plans
- DNS should be treated as a **policy enforcement point (PEP)** in zero trust architecture
- DNS query data should be correlated with DHCP lease histories for incident response
- Organizations should maintain retired domain delegations in a **parked state** to prevent re-registration
- Post-quantum cryptographic algorithms not yet specified for DNSSEC — plan for migration
- Hybrid protective DNS approach recommended (cloud + on-premises)

## Compliance Control Mappings
- **NIST SP 800-53:** SC-20 (Secure Name/Address Resolution Service), SC-21 (Secure Name/Address Resolution Service - Recursive or Caching Resolver), SC-22 (Architecture and Provisioning for Name/Address Resolution Service)
- **NIST SP 800-81r3:** Full DNS security deployment guide
- **NIST SP 800-115:** Technical Guide to Information Security Testing and Assessment
- **CIS Controls:** Control 9 (Email and Web Browser Protections), Control 12 (Network Infrastructure Management)

## Additional Threat Details from NIST SP 800-81r3 PDF

### Section 3.1 — Zone Transfer Threats
- Zone transfer DoS: Frequent/malicious AXFR/IXFR requests overload primary/secondary servers
- Unauthorized zone modification: Zone transfer response could be tampered with
- Mitigation: ACLs on zone transfers, restrict to known secondaries, use TSIG authentication
- ZONEMD RRtype: Hashed digest of zone contents for integrity verification
- SIG(0): Public-key authentication for DNS transactions (alternative to TSIG)
- TLS for zone transfer confidentiality (RFC 9103)

### Section 3.2 — Zone Content Threats
- **Lame Delegations (3.2.1):** NS RRset entries pointing to non-existing servers → child zone unreachable or intermittently accessible. Check delegation from parent zone AND child delegations within zone.
- **Zone Drift (3.2.2):** Mismatch between primary/secondary when SOA Refresh/Retry too high + frequent changes. Refresh range: 1200s (20min) to 432000s (12hr). Retry should be fraction of Refresh.
- **Zone Thrash (3.2.2):** SOA Refresh/Retry too low → excessive zone transfers → DoS on both servers.

### Section 3.3 — Dynamic Update Threats
- Unauthorized updates: Add illegitimate resources, delete legitimate resources, alter NS RRsets
- Update tampering: Modify data in dynamic update requests
- Replay attacks: Capture and resubmit update messages
- Volume attacks: Large volume of dynamic updates → DoS
- Mitigation: TSIG authentication, hidden primary servers for dynamic updates, IPSec

### Section 3.4 — DNS NOTIFY Threats
- Spoofed NOTIFY messages trigger unnecessary zone transfers → DoS
- Mitigation: Restrict NOTIFY to known primary servers, use TSIG

### Section 3.5 — Information Leakage
- Resource records (HINFO, TXT, LOC, RP) can expose sensitive info
- Split-horizon DNS recommended to separate internal/external views
- Minimize public-facing record content

### Section 3.6 — External Authoritative Domain Integrity
- **Dangling CNAME (3.6.1):** CNAME → expired domain → attacker registers → subdomain takeover
- **Lame Delegation Exploitation (3.6.2):** Subdomain delegated to provider, contract lapses, delegation not removed → attacker contracts with same provider → hijack
- **Look-Alike Domain Exploitation (3.6.3):** Typosquat, homoglyph, retired domain re-registration

### Section 3.7 — Operational Recommendations
- **TTL Values (3.7.1):** Range 1800s (30min) to 86400s (1 day). TTL=0 prohibited. Below 30s discouraged for DNSSEC.

### Section 3.8 — DNSSEC for Authoritative Service
- **Key Considerations (3.8.1):** ECDSA P-256/P-384 and Ed25519/Ed448 preferred over RSA. Table 1 in PDF has full algorithm parameters.
- **RRSIG Validity (3.8.2):** 5-7 days recommended to limit compromise window
- **NSEC vs NSEC3 (3.8.3):** NSEC preferred; NSEC3 overhead not justified. If NSEC3 required by policy, follow RFC 9276.
- **Algorithm Migration (3.8.5):** Plan for post-quantum migration when specs available
- **Internal Zones (3.8.6):** DNSSEC signing recommended for internal zones too

### Section 4 — Recursive/Forwarding Service Threats
- **Encrypted DNS (4.2.1):** DoT (TCP 853), DoH (TCP/UDP 443), DoQ (UDP 853)
- Block unauthorized DoT on TCP 853 via firewall
- Block rogue DoH using RPZ + firewall rules (harder due to port 443)
- **Public DNS Restriction (4.2.2):** Block direct queries to public resolvers (8.8.8.8, 1.1.1.1)
- **QNAME Minimization (4.2.3):** Reduce information sent to authoritative servers
- **DNS Tunneling Detection (4.2.4):** Detect data exfiltration via DNS query/response encoding
- **DNSSEC Validation (4.2.5):** Enable on all recursive resolvers

### Section 5 — Stub Resolver Threats
- Securing individual device DNS resolvers
- MDM enforcement of approved DNS configurations
- DNS cache poisoning prevention
