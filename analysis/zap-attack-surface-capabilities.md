# ZAP Attack Surface Analysis Capabilities

## Built-in Attack Surface Features

### 1. Spider + Ajax Spider (Crawling)
- Traditional spider: follows links, parses HTML, forms, comments, robots.txt, sitemap.xml
- Ajax Spider: browser-based crawling for JavaScript-heavy apps (React, Angular, Vue)
- Both feed discovered URLs into the Sites Tree

### 2. Sites Tree (core/view/sites, core/view/urls)
- ZAP API: `/JSON/core/view/sites/` — lists all discovered sites
- ZAP API: `/JSON/core/view/urls/` — lists all discovered URLs
- Hierarchical representation of the application structure

### 3. Parameters View (params/view/params)
- ZAP API: `/JSON/params/view/params/` — lists all discovered parameters
- Shows parameter name, type (URL, POST, cookie, header), and which URLs use them
- Critical for understanding the attack surface

### 4. Technology Detection (Wappalyzer-based)
- ZAP API: `/JSON/wappalyzer/view/listAll/` — detected technologies
- Identifies frameworks, languages, servers, CMS, etc.
- Can be used to select targeted scan policies

### 5. Active Scan Input Vectors
- URL Query String & Data Driven Nodes
- POST Data
- Plain Body Data (text/plain)
- URL Path elements
- HTTP Headers (optionally all requests)
- Cookie Data
- Built-in handlers: Multipart Form Data, XML, JSON, GWT, OData

### 6. Passive Scanner
- Runs on all proxied/spidered traffic without sending additional requests
- Detects: missing security headers, information disclosure, cookie issues, CSP problems
- Technology fingerprinting via response patterns

## Attack Surface Detector Plugin (secdec/attack-surface-detector-zap)
- Static code analysis to find unlinked endpoints
- Discovers parameters not visible in client-side code
- Supports: ASP.NET MVC, Web Forms, Spring MVC, Struts, JSP, Django, Rails
- Last updated 7 years ago — may not work with current ZAP versions
- Requires source code access — not applicable for black-box testing

## Key ZAP APIs for Attack Surface Enumeration
- `/JSON/core/view/sites/` — all discovered sites
- `/JSON/core/view/urls/` — all discovered URLs (the site map)
- `/JSON/params/view/params/` — all discovered parameters per URL
- `/JSON/wappalyzer/view/listAll/` — detected technologies
- `/JSON/search/view/urlsByUrlRegex/` — search URLs by pattern
- `/JSON/pscan/view/scanOnlyInScope/` — passive scan scope
- `/JSON/spider/view/results/` — spider results
- `/JSON/ajaxSpider/view/results/` — ajax spider results

## Current Issues in Our Pipeline
1. **ALL 204 ZAP scans failed** — active scan never starts (400 Bad Request)
2. Spider completes (100%) but only finds 3-16 URLs per target
3. Zero completed scans = zero active vulnerability testing
4. All "found" vulns come from Nuclei and LLM analysis, not ZAP
