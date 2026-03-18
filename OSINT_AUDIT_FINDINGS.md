# OSINT Pipeline Audit Findings

## Current Manual Supplement Capabilities

### What Operators CAN Do Now:
1. **Add Targets** — EngagementOps has `addTargets` mutation (domains/IPs via text input)
2. **Import Scan Results** — `engagement-scan-imports` supports Nessus, Qualys, Burp, ZAP XML/JSON import
3. **Import BloodHound Data** — `bloodhound-import` for AD graph data
4. **CSV Target Import** — CampaignWizard supports CSV import for phishing targets
5. **Bug Bounty Findings** — Manual finding entry in BugBountyHub
6. **Operator Notes** — Auth assessment and training lab support operator notes
7. **Cloud Credentials** — `cloud-credentials` router has `addCredential` for AWS/Azure/GCP keys
8. **Notes Field** — Engagement create/update has a notes text field

### What Operators CANNOT Do (Gaps):
1. **No manual credential/password list management** — BUILTIN_PASSWORD_LISTS is hardcoded, no custom upload or breach credential import
2. **No manual IOC entry** — Cannot add custom indicators (IPs, domains, hashes) to an engagement
3. **No manual finding entry** — Cannot manually add pentest findings to an engagement
4. **No breach credential → engagement credential list pipeline** — DeHashed finds breaches but doesn't populate attack lists
5. **No manual company intel override** — Cannot manually correct/supplement LLM-inferred org profile
6. **No manual regulatory framework selection** — Cannot override auto-detected compliance frameworks
7. **No custom darkweb intel input** — Cannot paste in darkweb findings from external sources
8. **No engagement-scoped notes/evidence system** — No structured evidence collection per engagement

## Current Credential Attack Engine State:
- Has built-in password lists (top_100, top_500, common_admin, etc.)
- Has built-in username lists (common_admins, common_users)
- Has `generateTargetedPasswordList()` that creates org-specific passwords
- Has DEFAULT_CREDENTIALS for OEM devices (100+ entries)
- **Missing**: Custom list upload, breach credential import, per-engagement credential store
- **Missing**: DeHashed → credential attack list pipeline

## Current Darkweb Intel State:
- 13 built-in feeds (abuse.ch, ransomware.live, AlienVault OTX, OpenPhish, etc.)
- Domain correlation via `correlateEventsWithDomain()`
- **Missing**: IntelX (paste/darkweb search), Hudson Rock (stealer logs), LeakCheck
- **Missing**: Domain-specific darkweb searches (current feeds are generic IOC ingestion)

## Current Company Intel State:
- `org-enrichment.ts` has OrgProfile with industry, sector, products, services, technologies, employees, locations, financials, regulatoryContext
- LLM prompt scrapes website and infers org profile
- **Missing**: Structured data from business data brokers (LinkedIn, Yahoo Finance, SEC EDGAR)
- **Missing**: Systematic regulatory framework detection engine
- **Missing**: Firmographic data (SIC/NAICS codes, revenue, employee count from authoritative sources)

## Current BIA/Scoring Integration:
- `buildLLMPromptForBIA()` includes org profile + Shodan + DNS data
- `domainIntel.ts` pipeline extracts breach data from DeHashed passive recon
- **Missing**: Darkweb intel context in BIA prompt
- **Missing**: Company intel context in BIA prompt  
- **Missing**: Regulatory framework context in BIA prompt
- **Missing**: Breach credential count/severity in scoring multipliers
