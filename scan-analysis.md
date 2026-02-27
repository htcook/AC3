# Scan Result Population Analysis

## Key Findings

### 1. Vianova.ai (scan 1380022 / assets in 1290209)
- **Status**: completed
- **Total Assets**: 10 (analyzed) 
- **Subdomains in pipelineOutput**: 106
- **Ports in pipelineOutput**: 17
- **Passive Recon**: 726 observations, 147 risk signals, 27 connectors
- **Issue**: Only 10 assets in discovered_assets table, but 106 subdomains found
  - Assets have techCount=0 or 1, findingCount=0 or 5-7
  - Port data exists but product/version fields are EMPTY strings
  - Ports only from shodan/shodan_internetdb, no Nmap/Naabu enrichment

### 2. AceofCloud.com (scan 1380013)
- **Subdomains**: stored in pipelineOutput
- **Ports**: stored but product/version EMPTY
- **Same pattern**: port data from passive recon only, no active scan enrichment

### 3. Issues Identified

#### A. Port/Service Data Quality
- Ports are discovered via Shodan InternetDB (passive) but product/version/vulns are empty
- No active Nmap scan data feeding into the pipeline output
- The discoveredPorts extraction only pulls from passive recon observations

#### B. Risk Signals Undefined Fields
- In the e2e test output: `[medium] undefined (undefined)` 
- Risk signals have severity but title/source are undefined
- Need to check the risk signal structure in passive connectors

#### C. Subdomain-to-Asset Gap
- 106 subdomains discovered but only 10 analyzed as assets
- The LLM analysis step only processes a subset (top 30 by default)
- Remaining subdomains stored in pipelineOutput.discoveredSubdomains but NOT in discovered_assets

#### D. Missing Active Scan Integration
- Amass, Subfinder, HTTPX, Naabu are NOT automatically run during domain intel pipeline
- The pipeline relies entirely on passive connectors for discovery
- Active tools (Nmap, Service Fingerprinter) are separate and not auto-triggered

### 4. Root Causes
1. **No active tool auto-trigger**: The domain intel pipeline runs passive recon only, then LLM analysis. It does NOT auto-trigger Amass/Nmap/Subfinder.
2. **Port data is passive-only**: discoveredPorts comes from Shodan observations which often lack product/version details.
3. **Risk signal fields**: The riskSignals array items may have different field names than what the test script expected (title vs name, etc.)
4. **Asset count limited**: LLM analysis processes ~30 assets max, so most subdomains are stored as metadata only.
