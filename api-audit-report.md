# Platform API Audit & Recommendations

**Prepared for:** Caldera Dashboard Platform Owner
**Date:** February 24, 2026

---

## Part 1: Currently Integrated Paid APIs

The following table lists every external API currently wired into the platform, categorized by whether it requires a paid subscription for the level of access the platform uses. Internal/self-hosted services (C2 server, exploit server, ZAP, GoPhish) are excluded since they run on your own infrastructure rather than consuming a third-party SaaS API.

### Paid APIs You Are Currently Paying For

| API | Env Variable | What It Does on the Platform | Pricing Model | Est. Annual Cost |
|:----|:-------------|:-----------------------------|:--------------|:-----------------|
| **Shodan** | `SHODAN_API_KEY` | Internet-wide host discovery, open port enumeration, CVE correlation, ICS/OT device scanning, banner grabbing. Used in Domain Intel passive recon, ICS exploit catalog, and corroboration engine. | Freelancer $69/mo, Small Business $359/mo, Corporate $1,099/mo; or $49 lifetime membership (limited) | $828 – $13,188/yr |
| **Censys** | `CENSYS_API_ID`, `CENSYS_API_SECRET` | Certificate transparency monitoring, host enumeration, service fingerprinting. Used in Domain Intel passive recon, ICS/OT security scanning, and corroboration engine. | Free tier (250 queries/mo), Solo $50/mo, credit packages from $100, Enterprise custom | $600 – $5,000+/yr |
| **SecurityTrails** | `SECURITYTRAILS_API_KEY` | Historical DNS records, subdomain enumeration, WHOIS history, domain intelligence. Used in Domain Intel passive recon and corroboration engine. | Free tier (50 queries/mo), API plans from ~$50/mo, Enterprise $11K–$70K/yr | $600 – $70,000/yr |
| **DeHashed** | `DEHASHED_API_KEY`, `DEHASHED_EMAIL` | Breach/credential leak database searches. Used in Domain Intel passive recon, corroboration engine, and dedicated credential exposure module. | Free (limited), Domain Monitoring $29.99/domain/mo, Enterprise $99.99/mo | $360 – $1,200/yr |
| **DigitalOcean** | `DIGITALOCEAN_ACCESS_TOKEN` | Cloud infrastructure provisioning for exploit servers (droplet management), SSH tunnel management, and typosquatting infrastructure. | Pay-as-you-go: Droplets from $4/mo, bandwidth included | $200 – $2,000+/yr (usage-dependent) |
| **GreyNoise** | `GREYNOISE_API_KEY` | Internet background noise classification — distinguishes targeted attacks from mass scanning. Used in Domain Intel passive recon. | Community (free, limited), Paid plans from ~$500/yr, Enterprise custom | $500 – $5,000+/yr |
| **BinaryEdge** | `BINARYEDGE_API_KEY` | Internet-wide scanning, data breach detection, attack surface analysis. Used in Domain Intel passive recon. | Free (250 queries/mo), Starter $10/mo, Business $50/mo, Enterprise custom | $120 – $600+/yr |
| **URLScan** | `URLSCAN_API_KEY` | URL scanning, website screenshot capture, DOM analysis, phishing detection. Used in Domain Intel passive recon and corroboration engine. | Free (limited public scans), Paid plans from ~$60/mo for private scans | $0 – $720+/yr |
| **NVD (NIST)** | `NVD_API_KEY` | CVE vulnerability database lookups, CPE matching, CVSS scoring. Used in corroboration engine, dynamic CPE matcher, and ICS exploit catalog. | Free (rate-limited without key), API key is free but increases rate limits | **Free** |

### Free APIs Currently Integrated

These APIs are integrated and do not require payment, though some offer paid tiers for higher limits.

| API | What It Does | Pricing |
|:----|:-------------|:--------|
| **abuse.ch** (ThreatFox, URLhaus, Feodo Tracker, MalwareBazaar, SSL Blacklist) | Malware IOC feeds, botnet C2 tracking, malicious URL database, SSL certificate blacklist. Used across dark web OSINT, IOC sync, and corroboration engine. | **Free** (community project) |
| **AlienVault OTX** | Community threat intelligence pulses, IOC sharing, MITRE ATT&CK mapping. Used in dark web feed scheduler and IOC enrichment. | **Free** (community tier) |
| **Have I Been Pwned** | Breach catalog lookups (public breaches endpoint). Used in dark web OSINT service. | **Free** (public breaches endpoint; paid for domain search/stealer logs) |
| **crt.sh** | Certificate Transparency log searches for subdomain discovery. Used in Domain Intel passive recon. | **Free** |
| **RIPE Stat** | IP prefix lookups, ASN information, BGP routing data. Used in Domain Intel passive recon. | **Free** |
| **CIRCL (MISP)** | MISP OSINT feed for structured threat intelligence events. Used in threat intel ingest. | **Free** |
| **Spamhaus DROP** | IP blocklist of hijacked/malicious network ranges. Used in dark web OSINT service. | **Free** (basic feeds) |
| **OpenPhish** | Phishing URL feed. Used in dark web OSINT service. | **Free** (community feed) |
| **ransomware.live** | Ransomware victim and group tracking. Used in dark web feed scheduler. | **Free** |
| **MITRE ATT&CK** | Technique/tactic framework data (STIX format). Used across attack coverage, TTP knowledge, and threat actor catalog. | **Free** |
| **Exploit-DB** | Public exploit database references. Used in exploit catalog and ingestion. | **Free** |
| **DNS Google** | DNS-over-HTTPS resolution. Used in domain verification. | **Free** |

---

## Part 2: Recommended Paid APIs to Add

The following APIs would fill specific capability gaps in the platform across reconnaissance, vulnerability intelligence, breach monitoring, and active testing. They are organized by the attack lifecycle phase they would enhance most.

### Tier 1 — High Impact, Should Add

| API | What It Would Add | Phase Enhanced | Pricing | Why It Matters |
|:----|:------------------|:---------------|:--------|:---------------|
| **VirusTotal / Google Threat Intelligence** | Multi-AV file scanning (70+ engines), YARA-based threat hunting (LiveHunt/Retrohunt), behavioral analysis sandboxing, file reputation scoring. Would let operators submit suspicious files, payloads, and malware samples for deep analysis directly from the platform. | Recon, Validation | Free (~500 lookups/day), Paid from ~$5,000/yr, Enterprise ~$10K–$150K/yr | Industry standard for malware analysis. Currently the platform has no file-based threat analysis capability. Every serious offensive platform needs this. |
| **Have I Been Pwned (Paid Tier)** | Domain-wide breach search, stealer log access, real-time breach notifications. The free tier only gives public breach catalog; the paid tier enables searching by domain to find all compromised employee credentials. | Recon, Discovery | From $4.50/mo (10 domains) to $1,304/mo (unlimited + stealer logs) | Critical for pre-engagement credential exposure assessment. Stealer log data is increasingly the #1 initial access vector. |
| **AbuseIPDB** | IP abuse reputation scoring with community reports, CIDR range checking. Already referenced in the corroboration engine code but currently skipped due to missing API key. | Recon, Validation | Free (1,000/day), Paid $5–$150/mo | Already partially coded — just needs an API key to activate. Very affordable and fills the IP reputation gap in corroboration. |
| **Intezer Analyze** | Automated malware analysis with code-level genetic analysis, automated reverse engineering, YARA rule generation from samples. | Validation, Reporting | Custom pricing, typically $5K–$20K/yr | Goes beyond VirusTotal by providing code-level similarity analysis — identifies malware families and code reuse across samples. |

### Tier 2 — Strong Enhancement, Recommended

| API | What It Would Add | Phase Enhanced | Pricing | Why It Matters |
|:----|:------------------|:---------------|:--------|:---------------|
| **Recorded Future** | Premium threat intelligence with real-time risk scoring, dark web monitoring, threat actor tracking, vulnerability prioritization with exploit likelihood scoring (EPSS-like). | All Phases | Custom pricing, typically $10K–$100K+/yr | The gold standard for threat intelligence. Would dramatically enhance the AI Attack Planner and threat actor catalog with predictive intelligence. |
| **Snyk** | Software composition analysis (SCA), container vulnerability scanning, IaC security scanning. Would scan target application dependencies for known vulnerabilities. | Discovery, Validation | Free (limited), Team $25/dev/mo, Enterprise custom | Adds supply chain vulnerability intelligence — identifies vulnerable libraries in target applications during web app scanning. |
| **Flare.io** | Dark web and illicit community monitoring, credential leak monitoring, threat actor tracking across Telegram/Discord/forums. | Recon, Discovery | Custom pricing, typically $15K–$50K/yr | Purpose-built dark web monitoring that goes far beyond what abuse.ch feeds provide. Would enhance the dark web OSINT module significantly. |
| **SpiderFoot HX** | Automated OSINT collection across 200+ data sources, attack surface mapping, data correlation. | Recon, Discovery | From $500/yr (personal) to $5K+/yr (enterprise) | Would automate and expand passive reconnaissance beyond the current 7-source corroboration engine. |

### Tier 3 — Specialized Enhancement, Nice to Have

| API | What It Would Add | Phase Enhanced | Pricing | Why It Matters |
|:----|:------------------|:---------------|:--------|:---------------|
| **Cloudflare Radar** | Internet traffic analytics, DDoS attack trends, BGP hijack detection, domain popularity ranking. | Recon | Free (basic), Enterprise for full access | Adds network-level intelligence for target profiling and infrastructure analysis. |
| **WhoisXML API** | Comprehensive WHOIS, DNS, and IP intelligence with historical data, reverse WHOIS, brand monitoring. | Recon, Discovery | From $19/mo (500 queries) to $99/mo (5,000 queries), Enterprise custom | More reliable and comprehensive than free WHOIS services. Historical WHOIS data is valuable for attribution. |
| **PassiveTotal (RiskIQ/Microsoft)** | Passive DNS, SSL certificate history, host pair analysis, web component tracking. | Recon, Discovery | Community (free, limited), Enterprise via Microsoft Defender TI | Deep passive DNS intelligence that complements SecurityTrails with different data sources and analysis capabilities. |
| **LeakIX** | Real-time leak and misconfiguration detection across the internet, exposed database discovery, cloud misconfiguration alerts. | Recon, Discovery | Free (limited), Paid from ~$30/mo | Finds exposed databases, misconfigured cloud storage, and leaked credentials in real-time. Complements Shodan with a security-focused lens. |
| **Netlas.io** | Internet-wide scanning similar to Shodan/Censys but with additional DNS and certificate intelligence, response body search. | Recon, Discovery | Free (limited), Paid from $50/mo | Alternative/supplementary internet scanning data source. Response body search is unique and valuable for finding specific technologies. |
| **FullHunt** | Attack surface discovery and monitoring, exposed API detection, subdomain takeover detection. | Recon, Discovery | Free (limited), Paid from $200/mo | Purpose-built for attack surface management with features like subdomain takeover detection that the platform currently lacks. |

---

## Part 3: Priority Integration Roadmap

Based on the platform's current capabilities and gaps, the recommended integration order is:

**Immediate (activate what's already coded):**
1. **AbuseIPDB** — Already referenced in corroboration engine code, just needs an API key ($5/mo)

**Short-term (highest ROI):**
2. **VirusTotal** — File/malware analysis is a fundamental gap (~$5K/yr minimum)
3. **Have I Been Pwned (Paid)** — Domain-wide credential exposure for pre-engagement recon (~$54/yr for 10 domains)

**Medium-term (significant capability expansion):**
4. **Intezer Analyze** — Deep malware analysis with code genetics (~$10K/yr)
5. **Flare.io** — Dark web monitoring beyond abuse.ch feeds (~$15K/yr)
6. **WhoisXML API** — Reliable WHOIS/DNS intelligence (~$240/yr)

**Long-term (enterprise-grade):**
7. **Recorded Future** — Premium threat intelligence (~$25K+/yr)
8. **Snyk** — Supply chain vulnerability scanning (~$300/yr per developer)

---

## Summary

The platform currently integrates **9 paid APIs** and **12+ free APIs/feeds**. The estimated total annual spend on paid APIs ranges from approximately **$3,200 to $97,000** depending on the tier selected for each service. The three highest-impact additions would be **AbuseIPDB** (nearly free, already partially coded), **VirusTotal** (industry-standard malware analysis), and **HIBP Paid** (credential exposure at the domain level). Together these three would cost as little as **$5,100/year** and close the platform's most significant intelligence gaps.
