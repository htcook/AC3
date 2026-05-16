# AC3 Threat Actor Catalog Enrichment Strategy

**Document Version:** 1.0  
**Date:** May 15, 2026  
**Classification:** Internal — AceOfCloud Security Operations  
**Objective:** Transform the AC3 threat actor catalog into the premiere global threat intelligence database, surpassing commercial platforms in depth, accuracy, and operational utility.

---

## Executive Summary

The AC3 threat actor catalog currently holds **1,600 unique actors** across APT, ransomware, cybercrime, hacktivist, and access broker categories. While this provides solid breadth, the database has critical depth gaps: 35% of actors have unknown origin, 55% lack technique mappings, 60% lack tool associations, 70% lack activity timelines, and zero actors have tracked individual members, organizational structure, or infrastructure mapping.

This document outlines a phased enrichment strategy that leverages 20+ free and existing data sources, schema expansions for military-grade tactical intelligence, and automated continuous enrichment pipelines to achieve comprehensive coverage of every known threat group's personnel, capabilities, infrastructure, and operational patterns.

---

## 1. Current State Assessment

### 1.1 Database Composition

| Actor Type | Count | % of Total |
|-----------|-------|-----------|
| APT (Nation-State) | 696 | 43.5% |
| Ransomware | 459 | 28.7% |
| Cybercrime | 313 | 19.6% |
| Hacktivist | 69 | 4.3% |
| Access Broker | 33 | 2.1% |
| Influence Operations | 20 | 1.3% |
| Unknown | 10 | 0.6% |

### 1.2 Current Data Sources

The catalog aggregates from the following sources, with varying levels of completeness:

| Source | Actor Count | Primary Contribution |
|--------|-------------|---------------------|
| Malpedia (Fraunhofer FKIE) | 659 | Malware families, actor-to-family mapping, YARA rules |
| ransomware.live | 275 | Ransomware group profiles, victim lists, leak site monitoring |
| LLM-enriched Malpedia | 136 | AI-generated descriptions and technique mappings |
| General OSINT | 89 | Mixed community intelligence |
| Web crawler enrichment | 85 | Automated blog/report parsing |
| MITRE + Caldera + Malpedia | 42–83 | Cross-referenced multi-source entries |
| Curated OSINT | 22 | Manually verified intelligence |

### 1.3 Field Coverage Analysis

The following table shows what percentage of the 1,600 actors have meaningful data in each field:

| Field | Coverage | Gap | Priority |
|-------|----------|-----|----------|
| name | 100% | — | — |
| actorType | 100% | — | — |
| description | ~85% | 240 actors lack descriptions | HIGH |
| origin (country) | 65% | 557 actors marked "Unknown" | CRITICAL |
| motivation | ~60% | 640 actors missing | HIGH |
| targetSectors | ~50% | 800 actors missing | HIGH |
| techniques (ATT&CK) | ~45% | 880 actors missing | CRITICAL |
| targetRegions | ~45% | 880 actors missing | MEDIUM |
| tools | ~40% | 960 actors missing | CRITICAL |
| malware | ~35% | 1,040 actors missing | HIGH |
| activityTimeline | ~30% | 1,120 actors missing | HIGH |
| IOCs (linked table) | 21% | 1,267 actors have zero IOCs | CRITICAL |
| Events (linked table) | 27% | 1,176 actors have zero events | HIGH |
| Abilities (linked table) | 12% | 1,410 actors have zero abilities | MEDIUM |
| calderaProfile | ~12% | 1,408 actors missing | LOW (auto-gen) |
| enrichment_sources | ~5% | 1,520 actors have no enrichment tracking | MEDIUM |

### 1.4 Critical Missing Dimensions

The current schema entirely lacks the following intelligence categories that are standard in military/government threat intelligence products:

1. **Individual Members** — Named operators, their roles, nationalities, skills, legal status
2. **Organizational Hierarchy** — Command structure, sub-teams, specializations
3. **Group Relationships** — Affiliations, shared infrastructure, tool sharing, succession
4. **C2 Infrastructure** — Active/historical command-and-control servers, hosting providers
5. **Financial Operations** — Cryptocurrency wallets, ransom payments, money laundering
6. **Communication Channels** — Forum handles, Telegram groups, dark web presence
7. **Operational Patterns** — Working hours, timezone, language, attack cadence
8. **Law Enforcement Actions** — Indictments, sanctions, arrests, extraditions, rewards
9. **Campaign Tracking** — Named operations with full kill-chain mapping

---

## 2. Schema Expansion

To support military-grade tactical intelligence, the following new tables are required:

### 2.1 threat_actor_members

Tracks individual operators associated with threat groups.

```sql
CREATE TABLE threat_actor_members (
  id INT AUTO_INCREMENT PRIMARY KEY,
  actor_id VARCHAR(255) NOT NULL,          -- FK to threat_actors.actorId
  name VARCHAR(255),                        -- Real name (if known)
  aliases JSON,                             -- Online handles, forum names
  nationality VARCHAR(100),
  role ENUM('leader', 'developer', 'operator', 'recruiter', 'financier', 'unknown'),
  specialization VARCHAR(255),              -- e.g., "exploit development", "social engineering"
  skills JSON,                              -- ["reverse engineering", "C++ malware", "phishing"]
  status ENUM('active', 'arrested', 'indicted', 'sanctioned', 'deceased', 'unknown'),
  photo_url TEXT,
  indictment_ref TEXT,                      -- DOJ case number or link
  sanction_ref TEXT,                        -- OFAC designation
  reward_amount DECIMAL(12,2),              -- FBI reward if applicable
  first_seen DATE,
  last_seen DATE,
  confidence ENUM('high', 'medium', 'low'),
  source TEXT,                              -- Attribution source
  notes TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_actor (actor_id),
  INDEX idx_status (status)
);
```

### 2.2 threat_actor_relationships

Maps group-to-group connections for affiliation analysis.

```sql
CREATE TABLE threat_actor_relationships (
  id INT AUTO_INCREMENT PRIMARY KEY,
  source_actor_id VARCHAR(255) NOT NULL,
  target_actor_id VARCHAR(255) NOT NULL,
  relationship_type ENUM(
    'parent_of', 'subsidiary_of', 'affiliate', 'successor_to',
    'predecessor_of', 'shares_infrastructure', 'shares_tools',
    'shares_members', 'rival', 'customer_of', 'supplier_to',
    'rebranded_as', 'splinter_of'
  ),
  confidence ENUM('high', 'medium', 'low'),
  evidence TEXT,
  first_observed DATE,
  last_observed DATE,
  source TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_source (source_actor_id),
  INDEX idx_target (target_actor_id),
  INDEX idx_type (relationship_type)
);
```

### 2.3 threat_actor_infrastructure

Tracks C2 servers, hosting, and operational infrastructure.

```sql
CREATE TABLE threat_actor_infrastructure (
  id INT AUTO_INCREMENT PRIMARY KEY,
  actor_id VARCHAR(255) NOT NULL,
  infra_type ENUM('c2_server', 'staging_server', 'exfil_endpoint', 'phishing_domain',
                   'watering_hole', 'proxy', 'vpn_exit', 'bulletproof_hosting', 'other'),
  indicator_type ENUM('ip', 'domain', 'url', 'certificate_fingerprint'),
  indicator_value TEXT NOT NULL,
  asn VARCHAR(50),
  hosting_provider VARCHAR(255),
  country VARCHAR(100),
  first_seen TIMESTAMP,
  last_seen TIMESTAMP,
  status ENUM('active', 'inactive', 'sinkholed', 'seized', 'unknown'),
  associated_malware VARCHAR(255),
  confidence ENUM('high', 'medium', 'low'),
  source TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_actor (actor_id),
  INDEX idx_indicator (indicator_value(255)),
  INDEX idx_status (status)
);
```

### 2.4 threat_actor_financial

Tracks cryptocurrency wallets, ransom demands, and financial operations.

```sql
CREATE TABLE threat_actor_financial (
  id INT AUTO_INCREMENT PRIMARY KEY,
  actor_id VARCHAR(255) NOT NULL,
  wallet_type ENUM('bitcoin', 'monero', 'ethereum', 'tether', 'other'),
  wallet_address VARCHAR(255),
  total_received DECIMAL(20,8),
  total_sent DECIMAL(20,8),
  avg_ransom_demand DECIMAL(12,2),          -- USD equivalent
  max_ransom_demand DECIMAL(12,2),
  known_payments INT DEFAULT 0,
  sanctions_listed BOOLEAN DEFAULT FALSE,
  chainalysis_cluster VARCHAR(255),
  first_seen DATE,
  last_seen DATE,
  source TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_actor (actor_id),
  INDEX idx_wallet (wallet_address)
);
```

### 2.5 threat_actor_indictments

Tracks law enforcement actions, sanctions, and legal proceedings.

```sql
CREATE TABLE threat_actor_indictments (
  id INT AUTO_INCREMENT PRIMARY KEY,
  actor_id VARCHAR(255) NOT NULL,
  member_id INT,                            -- FK to threat_actor_members.id (optional)
  action_type ENUM('indictment', 'sanction', 'arrest', 'extradition', 'seizure',
                    'reward_offered', 'takedown', 'disruption'),
  agency VARCHAR(255),                      -- "DOJ", "FBI", "OFAC", "Europol", etc.
  case_number VARCHAR(255),
  description TEXT,
  action_date DATE,
  country VARCHAR(100),                     -- Jurisdiction
  reward_amount DECIMAL(12,2),
  document_url TEXT,
  outcome TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_actor (actor_id),
  INDEX idx_type (action_type),
  INDEX idx_date (action_date)
);
```

### 2.6 threat_actor_campaigns

Tracks named operations with full kill-chain detail.

```sql
CREATE TABLE threat_actor_campaigns (
  id INT AUTO_INCREMENT PRIMARY KEY,
  actor_id VARCHAR(255) NOT NULL,
  campaign_name VARCHAR(255) NOT NULL,
  aliases JSON,
  description TEXT,
  start_date DATE,
  end_date DATE,
  status ENUM('active', 'concluded', 'disrupted', 'unknown'),
  target_sectors JSON,
  target_regions JSON,
  target_organizations JSON,
  initial_access_vector VARCHAR(255),       -- ATT&CK technique ID
  techniques_used JSON,                     -- Full kill-chain technique list
  tools_used JSON,
  malware_deployed JSON,
  infrastructure_used JSON,                 -- IPs/domains used in this campaign
  impact TEXT,
  iocs JSON,
  mitre_campaign_id VARCHAR(50),            -- C0001, etc.
  source TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_actor (actor_id),
  INDEX idx_name (campaign_name),
  INDEX idx_status (status)
);
```

### 2.7 threat_actor_operational_patterns

Tracks behavioral signatures for attribution and prediction.

```sql
CREATE TABLE threat_actor_operational_patterns (
  id INT AUTO_INCREMENT PRIMARY KEY,
  actor_id VARCHAR(255) NOT NULL,
  working_hours_utc VARCHAR(50),            -- e.g., "06:00-18:00 UTC"
  working_days VARCHAR(50),                 -- e.g., "Sun-Thu" (Iranian groups)
  timezone_estimate VARCHAR(50),            -- e.g., "UTC+3:30", "UTC+8"
  primary_language VARCHAR(50),
  secondary_languages JSON,
  avg_dwell_time_days INT,                  -- Average time in network before detection
  preferred_initial_access JSON,            -- Top 3 initial access techniques
  preferred_persistence JSON,               -- Top persistence mechanisms
  preferred_exfil_method VARCHAR(255),
  attack_frequency VARCHAR(100),            -- "weekly", "monthly", "campaign-based"
  target_selection_pattern TEXT,            -- How they choose targets
  opsec_level ENUM('excellent', 'good', 'moderate', 'poor'),
  known_mistakes JSON,                      -- OpSec failures that led to attribution
  source TEXT,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE INDEX idx_actor (actor_id)
);
```

---

## 3. Data Source Integration Plan

### 3.1 Phase 1 — Immediate Enrichment (Week 1-2)

These sources are free, have APIs, and can be automated immediately using existing AC3 infrastructure:

#### MITRE ATT&CK STIX Bundle (v18.1)
- **URL:** `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json`
- **Data:** 143 groups, 800+ techniques, 700+ software, 40+ campaigns with full relationship mapping
- **Integration:** Download STIX JSON, parse `intrusion-set` objects, map `uses` relationships to techniques/software
- **Fills:** techniques (critical), tools, malware, campaigns, aliases, descriptions
- **Frequency:** Monthly pull (ATT&CK updates quarterly)

#### MISP Galaxy Threat Actor Clusters
- **URL:** `https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json`
- **Data:** 500+ actors with rich metadata: country, motivation, synonyms, references, CFR attribution
- **Integration:** Parse JSON, cross-reference by name/alias, merge unique fields
- **Fills:** origin (critical — reduces "Unknown" from 35% to ~15%), motivation, aliases, references
- **Frequency:** Weekly pull

#### Malpedia Full Actor Refresh
- **URL:** `https://malpedia.caad.fkie.fraunhofer.de/api/get/actors`
- **Data:** 659+ actors with malware family associations, references, alt names
- **Integration:** API call, merge actor-to-family mappings, update references
- **Fills:** malware, tools, aliases, references, descriptions
- **Frequency:** Weekly pull

#### ransomware.live PRO API
- **URL:** `https://api.ransomware.live/v2/groups` (free API key required)
- **Data:** 200+ ransomware groups with TTPs, YARA rules, IOCs, victim counts, negotiation data
- **Integration:** API key registration, pull group profiles + TTPs + IOCs
- **Fills:** techniques, tools, IOCs, victim data, operational patterns, financial data
- **Frequency:** Daily pull

#### FBI Most Wanted — Cyber
- **URL:** `https://api.fbi.gov/wanted/v1/list?title=cyber`
- **Data:** Named individuals with photos, charges, aliases, reward amounts, group affiliations
- **Integration:** REST API (no auth), parse subject records, link to actor groups
- **Fills:** threat_actor_members (names, photos, rewards), threat_actor_indictments
- **Frequency:** Weekly pull

#### OFAC Specially Designated Nationals (SDN) List
- **URL:** `https://www.treasury.gov/ofac/downloads/sdn.xml`
- **Data:** Sanctioned entities including cyber actors, crypto wallets, aliases
- **Integration:** XML download, filter for "CYBER" program, extract wallet addresses
- **Fills:** threat_actor_financial (wallets), threat_actor_indictments (sanctions), aliases
- **Frequency:** Daily pull (OFAC updates frequently)

#### VulnCheck Threat Actors Index
- **URL:** `https://api.vulncheck.com/v3/index/threat-actors` (free tier available)
- **Data:** Threat actor to CVE mappings, vulnerability exploitation attribution
- **Integration:** API call with existing VULNCHECK key, map actors to exploited CVEs
- **Fills:** techniques (specific CVE exploitation), tools, campaigns
- **Frequency:** Weekly pull

### 3.2 Phase 2 — OSINT Enrichment (Week 3-4)

#### ETDA ThaiCERT Threat Group Cards
- **Coverage:** 504 groups, 2,997 operations, 2,194 tools, 1,789 aliases, 9,569 references
- **Method:** Structured web scraping of individual group pages
- **Fills:** operations → campaigns, tools, target sectors/regions, aliases, references
- **Value:** Most comprehensive free encyclopedia — fills campaigns table significantly

#### DOJ Press Releases (Cyber Division)
- **URL:** `https://www.justice.gov/criminal/criminal-fraud/news` + cyber indictment RSS
- **Method:** RSS monitoring + PDF parsing of indictment documents
- **Fills:** threat_actor_members (real names, nationalities), threat_actor_indictments, group structure
- **Value:** Primary source for named APT operators (e.g., GRU Unit 74455 members)

#### CISA Advisories
- **URL:** `https://www.cisa.gov/news-events/cybersecurity-advisories`
- **Method:** RSS + structured advisory parsing (AA-series reports)
- **Fills:** techniques, IOCs, mitigations, campaigns, target sectors
- **Frequency:** Daily monitoring

#### CrowdStrike Adversary Universe
- **Method:** Web scraping of public adversary profiles
- **Fills:** Naming cross-reference (BEAR/PANDA/KITTEN → our actorId), descriptions, campaigns
- **Value:** Industry-standard naming convention mapping

#### Unit 42 (Palo Alto Networks)
- **Method:** Blog/report parsing for threat actor profiles
- **Fills:** Campaigns, techniques, IOCs, infrastructure
- **Value:** Deep technical analysis of APT operations

#### Microsoft Threat Intelligence
- **Method:** Blog parsing for STORM/BLIZZARD/TYPHOON actor profiles
- **Fills:** Naming cross-reference, campaigns, techniques, infrastructure
- **Value:** Unique visibility into cloud-targeting actors

### 3.3 Phase 3 — Infrastructure Intelligence (Week 5-6)

Using existing API keys already configured in AC3:

#### Shodan (existing key: SHODAN_API_KEY)
- **Method:** Search for known C2 fingerprints (JARM hashes, HTTP headers, TLS certs)
- **Fills:** threat_actor_infrastructure (active C2 servers, hosting providers, ASNs)
- **Automation:** Scheduled searches for known actor infrastructure signatures

#### Censys (existing keys: CENSYS_API_ID, CENSYS_API_SECRET)
- **Method:** Certificate transparency + host search for actor-associated infrastructure
- **Fills:** threat_actor_infrastructure (domains, certificates, hosting)
- **Automation:** Certificate monitoring for known actor patterns

#### SecurityTrails (existing key: SECURITYTRAILS_API_KEY)
- **Method:** Historical DNS for known actor domains, subdomain enumeration
- **Fills:** threat_actor_infrastructure (DNS history, domain registration patterns)
- **Automation:** Domain monitoring for known registrant patterns

#### URLScan (existing key: URLSCAN_API_KEY)
- **Method:** Search for phishing kits, C2 panels, watering holes
- **Fills:** threat_actor_infrastructure (phishing domains, C2 panel screenshots)
- **Automation:** Tag-based monitoring for known actor phishing patterns

### 3.4 Phase 4 — Deep Enrichment (Ongoing)

#### LLM-Assisted Academic Paper Analysis
- **Method:** Feed academic papers (APT reports from Kaspersky GReAT, ESET, etc.) to LLM for structured extraction
- **Fills:** Group structure, member roles, operational patterns, campaign details
- **Automation:** Scheduled ingestion of new publications from security vendor blogs

#### Dark Web Forum Attribution
- **Method:** Cross-reference underground_intel_events (140,825 existing records) with actor handles
- **Fills:** threat_actor_communications, operational patterns, recruitment activity
- **Automation:** NLP-based handle attribution from existing dark web corpus

#### Court Document Analysis
- **Method:** Parse DOJ indictments, extradition requests, and sanctions documents
- **Fills:** Complete member dossiers, organizational charts, financial flows
- **Value:** Highest-confidence attribution data (government-verified)

#### Operational Pattern Extraction
- **Method:** Analyze threat_group_events (4,877 events) for temporal patterns
- **Fills:** threat_actor_operational_patterns (working hours, timezone, frequency)
- **Automation:** Statistical analysis of event timestamps

---

## 4. Enrichment Pipeline Architecture

### 4.1 Automated Collection Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    AC3 Enrichment Pipeline                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│  │  MITRE   │    │ Malpedia │    │   MISP   │    │ ransomware│  │
│  │  ATT&CK  │    │   API    │    │  Galaxy  │    │   .live   │  │
│  └────┬─────┘    └────┬─────┘    └────┬─────┘    └────┬─────┘  │
│       │               │               │               │         │
│       ▼               ▼               ▼               ▼         │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              Ingestion & Normalization Layer               │   │
│  │  - STIX/TAXII parser                                      │   │
│  │  - JSON schema mapper                                     │   │
│  │  - Deduplication engine (name + alias matching)           │   │
│  │  - Confidence scoring                                     │   │
│  └────────────────────────┬─────────────────────────────────┘   │
│                           │                                      │
│                           ▼                                      │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              LLM Enrichment Layer                          │   │
│  │  - Gap identification (missing fields per actor)          │   │
│  │  - Cross-source correlation                               │   │
│  │  - Structured extraction from unstructured reports        │   │
│  │  - Confidence assessment                                  │   │
│  └────────────────────────┬─────────────────────────────────┘   │
│                           │                                      │
│                           ▼                                      │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              AC3 Threat Actor Database                     │   │
│  │  - threat_actors (core profiles)                          │   │
│  │  - threat_actor_members (personnel)                       │   │
│  │  - threat_actor_relationships (affiliations)              │   │
│  │  - threat_actor_infrastructure (C2/hosting)               │   │
│  │  - threat_actor_campaigns (operations)                    │   │
│  │  - threat_actor_financial (crypto/payments)               │   │
│  │  - threat_actor_indictments (legal actions)               │   │
│  │  - threat_actor_operational_patterns (behavioral)         │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 Deduplication & Merge Strategy

When ingesting from multiple sources, the pipeline must:

1. **Match by name/alias** — Fuzzy matching with Levenshtein distance < 3, plus exact alias overlap
2. **Match by STIX ID** — Canonical identifier when available
3. **Match by MITRE G-code** — Cross-reference ATT&CK group IDs
4. **Merge strategy** — Union of all unique data, keep highest confidence for conflicting fields
5. **Provenance tracking** — Every field update records source + timestamp in enrichment_sources

### 4.3 Confidence Scoring Model

| Confidence Level | Source Type | Example |
|-----------------|-------------|---------|
| **High** (0.9-1.0) | Government attribution, court documents | DOJ indictment, OFAC sanction |
| **High** (0.8-0.9) | MITRE ATT&CK, vendor with primary research | Mandiant APT report, CrowdStrike IR |
| **Medium** (0.6-0.8) | Multi-vendor consensus, OSINT correlation | 3+ vendors agree on attribution |
| **Medium** (0.5-0.6) | Single vendor, community consensus | One vendor report, MISP community |
| **Low** (0.3-0.5) | LLM inference, weak correlation | AI-generated enrichment, forum posts |
| **Low** (0.1-0.3) | Unverified, single source, rumor | Dark web claim, unconfirmed leak |

---

## 5. Competitive Positioning

### 5.1 Comparison with Commercial Platforms

| Capability | AC3 (Target) | Recorded Future | Mandiant | CrowdStrike |
|-----------|-------------|-----------------|----------|-------------|
| Total actors tracked | 1,600+ (growing) | ~4,000 | ~3,000 | ~200 (named) |
| Named individuals | Yes (DOJ/FBI/OFAC) | Limited | Yes | No |
| Infrastructure tracking | Real-time (Shodan/Censys) | Yes | Yes | Limited |
| Financial intelligence | Blockchain + OFAC | Yes ($$$) | Limited | No |
| Operational patterns | Automated extraction | Yes | Yes | Yes |
| Relationship mapping | Graph-based | Yes | Yes | Limited |
| Dark web monitoring | Existing corpus (140K+) | Yes ($$$) | Limited | Limited |
| Campaign tracking | MITRE + ETDA + custom | Yes | Yes | Yes |
| Free/included | Yes (platform feature) | $100K+/yr | $50K+/yr | $50K+/yr |

### 5.2 Unique Differentiators

1. **Caldera Integration** — Direct mapping from threat actor TTPs to executable adversary emulation plans. No other platform does this.
2. **Combined OSINT + Dark Web** — 140K+ underground intel events cross-referenced with actor profiles.
3. **Automated Enrichment** — LLM-driven gap filling with confidence scoring and source tracking.
4. **Customer-Relevant Scoring** — Threat actors ranked by relevance to each customer's sector/region.
5. **Predictive Indicators** — Operational pattern analysis enables prediction of next likely targets.

---

## 6. Implementation Roadmap

### Week 1-2: Foundation
- [ ] Create new database tables (Section 2)
- [ ] Build MITRE ATT&CK STIX importer (143 groups, full technique mapping)
- [ ] Build MISP Galaxy importer (500+ actors, origin/motivation fill)
- [ ] Refresh Malpedia data (659 actors, malware family links)
- [ ] Register for ransomware.live PRO API key
- [ ] Build FBI Wanted API importer (named individuals)
- [ ] Build OFAC SDN parser (sanctions, crypto wallets)

### Week 3-4: Depth
- [ ] Build ETDA ThaiCERT scraper (504 groups, 2,997 operations)
- [ ] Build DOJ indictment parser (named members, legal actions)
- [ ] Integrate VulnCheck threat-actor-to-CVE mapping
- [ ] Build CrowdStrike/Unit42/Microsoft naming cross-reference table
- [ ] Implement CISA advisory ingestion
- [ ] Build relationship graph from shared infrastructure/tools

### Week 5-6: Infrastructure
- [ ] Build Shodan C2 hunting automation (known fingerprints)
- [ ] Build Censys certificate monitoring for actor patterns
- [ ] Integrate SecurityTrails DNS history for actor domains
- [ ] Build URLScan phishing attribution pipeline
- [ ] Cross-reference underground_intel_events with actor handles

### Week 7-8: Intelligence
- [ ] Build LLM-powered academic paper extraction pipeline
- [ ] Implement operational pattern analysis (timestamps → working hours)
- [ ] Build automated campaign detection from event clustering
- [ ] Implement relationship inference from shared IOCs/infrastructure
- [ ] Build confidence scoring and provenance tracking

### Ongoing: Continuous Enrichment
- [ ] Daily: OFAC, CISA, ransomware.live, abuse.ch
- [ ] Weekly: MITRE, Malpedia, MISP, FBI, VulnCheck
- [ ] Monthly: ETDA, DOJ, academic papers, vendor reports
- [ ] Real-time: Shodan/Censys infrastructure monitoring, dark web feeds

---

## 7. Expected Outcomes

After full implementation:

| Metric | Current | Target | Improvement |
|--------|---------|--------|-------------|
| Total actors | 1,600 | 2,500+ | +56% |
| Origin coverage | 65% | 90%+ | +25pp |
| Technique mapping | 45% | 95%+ | +50pp |
| Tool associations | 40% | 90%+ | +50pp |
| Named individuals | 0 | 500+ | New capability |
| Tracked infrastructure | 0 | 10,000+ IPs/domains | New capability |
| Relationship edges | 0 | 3,000+ | New capability |
| Campaign records | 0 | 3,000+ (from ETDA alone) | New capability |
| Financial records | 0 | 200+ wallets | New capability |
| Legal actions tracked | 0 | 300+ | New capability |

---

## 8. API Keys & Credentials Required

### Already Available in AC3:
- SHODAN_API_KEY
- CENSYS_API_ID / CENSYS_API_SECRET
- SECURITYTRAILS_API_KEY
- URLSCAN_API_KEY
- NVD_API_KEY
- ABUSECH_API_KEY
- ABUSEIPDB_API_KEY
- OPENAI_API_KEY (for LLM enrichment)

### Need to Register (Free):
- ransomware.live PRO API key (free forever)
- VulnCheck community API key (free tier)
- AlienVault OTX API key (free)
- Malpedia API token (free registration)

### No Auth Required:
- MITRE ATT&CK STIX (GitHub raw download)
- MISP Galaxy (GitHub raw download)
- FBI Wanted API (public)
- OFAC SDN List (public download)
- CISA Advisories (public RSS)
- ETDA ThaiCERT (public web)

---

## 9. Risk Considerations

| Risk | Mitigation |
|------|-----------|
| Data quality from automated ingestion | Confidence scoring + human review for high-impact changes |
| Rate limiting on free APIs | Implement backoff, cache aggressively, respect ToS |
| False attribution propagation | Require multi-source corroboration for origin/member claims |
| Schema migration complexity | Phased rollout, new tables don't break existing functionality |
| Storage growth | Infrastructure and IOC tables will grow fastest — implement TTL for low-confidence entries |
| Legal risk of tracking individuals | Only use publicly available government sources (DOJ, FBI, OFAC) |

---

## 10. Conclusion

The AC3 threat actor catalog is positioned to become the most comprehensive open-architecture threat intelligence database available. By leveraging 20+ free data sources, existing API keys, automated LLM enrichment, and the unique Caldera adversary emulation integration, the platform can deliver military-grade tactical intelligence that surpasses commercial offerings costing $50K-$100K+ annually.

The key differentiator is not just data volume — it is the operational utility of connecting threat actor intelligence directly to defensive action through Caldera emulation plans, automated IOC deployment, and predictive targeting analysis.

**Recommended immediate action:** Begin with Phase 1 (MITRE + MISP + Malpedia refresh) to achieve the fastest coverage improvement, then build the new schema tables to support the deeper intelligence dimensions.
