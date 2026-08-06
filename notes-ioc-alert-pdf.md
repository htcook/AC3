# Implementation Notes

## IOC Overlap Detection
- threat_actor_iocs: 3,790 IOCs (1092 domain, 999 hash, 882 url, 740 ip, 53 email, etc.)
- discovered_assets: hostname (domain), dnsRecords (JSON with A records = IPs), url
- Cross-reference: match asset hostnames against IOC domains, DNS A records against IOC IPs
- Also check domain_intel_scans.primaryDomain against IOC domains
- Add to executive-threat-briefing.ts as new step between Step 4 and Step 6

## Executive PDF Export
- Use server-side PDF generation (fpdf2 or html-to-pdf approach)
- Template: branded report with scan context, matched actors, CARVER profile, trends
- tRPC mutation that generates PDF, uploads to S3 via storagePut, returns URL
- Frontend: "Generate Briefing Report" button in ExecutiveThreatBriefing.tsx

## Alert Thresholds
- Need new DB table: threat_alert_thresholds (scanId, threshold, enabled, notifyMethod)
- Need new DB table: threat_alert_history (alertId, scanId, actorId, relevanceScore, notifiedAt)
- tRPC procedures: getAlertThresholds, setAlertThreshold, getAlertHistory
- Check thresholds during briefing computation, fire notifyOwner when exceeded
- Frontend: settings panel in ExecutiveThreatBriefing.tsx with threshold slider

## Data Model Summary
- discoveredAssets.hostname = domain (e.g., "rapidtalentgroup.com")
- discoveredAssets.dnsRecords = JSON {"A": ["23.20.98.48"], ...}
- threatActorIocs.iocType = "domain" | "ip" | "url" | "hash" | etc.
- threatActorIocs.value = the actual IOC value
- notifyOwner({ title, content }) = built-in notification helper
