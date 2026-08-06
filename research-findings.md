# IAB Research Findings: US Gov & ICS/SCADA Credential Sales

## Key Findings from Rapid7 (Mar 2026 - H2 2025 data)

### Government is #1 IAB Target
- **Government sector is the most frequently targeted at 14.2%** of all IAB offerings
- Retail follows at 13.1%, IT at 10.8%
- This is a NEW trend — last year gov was NOT in the top sectors (Financial Services and IT dominated)
- DarkForums is the principal platform for gov access sales
- "Admin panel" access is the most commonly offered type for gov sector

### US is #1 Target Country
- **155 unique US listings** = 30.9% of all global IAB listings
- US dominance due to: network size, high value of gov/enterprise networks, wealthy buyers
- Top 10 countries similar to last year: US, UK, India, Brazil

### Access Types & Pricing
- Top access vectors: RDP (21.2%), VPN (12.8%), RDWeb (11.2%)
- Privilege levels: Domain User (42.9%), Domain Admin (32.1%), Local Admin (12.5%)
- Average base price: $113,275 (up 4055% from $2,726 last year)
- Average victim revenue: $3.242 billion

### Forums
- DarkForums (221 threads) and RAMP (208 threads) = 81% of all IAB activity
- Exploit (53), BreachForums (30), XSS (18)

## CloudSEK Report (Feb 2026) - ICS/OT Targeting in Iran-US Conflict
- URL: https://www.cloudsek.com/blog/a-threat-actor-landscape-assessment-of-ics-ot-targeting-in-the-2026-iran-us-conflict-and-the-scale-of-the-risk
- Feb 2026 strikes accelerated existing cyber threat to US critical infrastructure

## CISA Advisory (Apr 7, 2026) - Iranian APT Targeting PLCs
- URL: https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-097a
- Iranian-affiliated APT actors targeting internet-exposed PLCs
- Intent to cause disruptions

## DarkReading (Aug 2025) - Gov Email Access for Sale
- URL: https://www.darkreading.com/threat-intelligence/government-email-sale-dark-web
- Cybercriminals auctioning live email credentials for gov systems
- Access to sensitive systems, confidential intelligence

## DarkOwl (Sep 2022) - ICS/OT Threats on Darknet
- URL: https://www.darkowl.com/blog-content/an-intro-to-industrial-control-systems-and-operational-technology-threats-on-the-darknet/
- Monitoring darknet for ICS/OT threats

## Google Cloud (Feb 2026) - Threats to Defense Industrial Base
- URL: https://cloud.google.com/blog/topics/threat-intelligence/threats-to-defense-industrial-base
- Defense sector faces relentless operations from state-sponsored actors and criminal groups

## Keywords for Gov IAB Detection
- government, federal, .gov, .mil, military, defense, DoD, DoE, DHS, FBI, CIA, NSA
- state government, county, municipal, city government
- admin panel, RDP, VPN, domain admin
- classified, clearance, FOUO, CUI

## Keywords for ICS/SCADA IAB Detection
- ICS, SCADA, PLC, HMI, DCS, RTU, OT, operational technology
- industrial control, programmable logic controller
- water treatment, power grid, power plant, electric utility
- oil and gas, pipeline, refinery, chemical plant
- manufacturing, smart grid, energy sector
- Siemens, Rockwell, Allen-Bradley, Schneider Electric, ABB, Honeywell
- Modbus, DNP3, OPC, BACnet, EtherNet/IP
- critical infrastructure, CI/CD (in OT context)

## Keywords for Defense Contractor IAB Detection
- defense contractor, DIB, defense industrial base
- cleared contractor, security clearance, TS/SCI, Secret
- ITAR, EAR, export controlled, CUI, CMMC
- Lockheed Martin, Raytheon, Northrop Grumman, Boeing Defense
- General Dynamics, BAE Systems, L3Harris, Leidos, SAIC
- Booz Allen Hamilton, ManTech, CACI, Parsons, KBR
- DISA, DCSA, DARPA, NSA contractor, DoD contractor
- weapons system, missile, satellite, radar, sonar
- military communications, tactical network

---

## API Test Results (April 21, 2026)

### Working APIs We Have Keys For
| Source | Data Volume | Gov/Defense/ICS Relevance |
|--------|-------------|---------------------------|
| CISA KEV | 1,577 vulns | High - IABs exploit these |
| RansomLook | 563 groups, 144 markets | High - darkweb ecosystem |
| ransomware.live | 333 groups, 100 victims/batch | High - victim attribution |
| Shodan | 200+ gov RDP, 76 defense RDP, 79K+ ICS Modbus | **Critical** |
| URLScan | 734 malicious .gov results | High |
| NVD | 682 initial-access vulns | High |
| AbuseIPDB | Blacklist data | Low |

### Shodan ICS/SCADA Exposure (US Only)
| Protocol | Exposed Devices |
|----------|----------------|
| Modbus (port 502) | 79,793 |
| Siemens S7 (port 102) | 52,185 |
| BACnet (port 47808) | 31,104 |
| DNP3 (port 20000) | 218,239 |
| Gov RDP (port 3389) | 13 |
| Defense RDP (port 3389) | 76 |
| Military w/ vulns | 16 |

### APIs Needing Auth Fixes
- DeHashed: returns documentation page instead of data
- Censys: 401 auth error
- ThreatFox/MalwareBazaar: empty results
- Spicy TIP: returns HTML not JSON

---

## Tor Node Assessment

**Recommendation: Not yet. Maximize clearnet APIs first.**

### Why Not Now
1. Legal risk accessing criminal forums
2. OPSEC complexity and attribution risk
3. RansomLook + ransomware.live already scrape most leak sites (563 groups, 144 markets)
4. Maintenance burden (forums change URLs, add CAPTCHAs)
5. Raw forum data is noisy, mostly Russian/Chinese

### Phased Approach
1. **Now**: Integrate Shodan ICS/gov monitoring, fix DeHashed/Censys, add NVD cross-referencing
2. **3-6 months**: Deploy read-only Tor proxy with keyword monitoring (TorBot/CRATOR)
3. **6-12 months**: Full Tor crawler with forum-specific parsers

### Commercial Alternatives
- DarkOwl Vision API — indexed darkweb content search
- Sixgill DarkFeed — real-time IOC feed
- Flare.io — managed darkweb monitoring with IAB coverage
- SpyCloud — recovered infostealer credentials
