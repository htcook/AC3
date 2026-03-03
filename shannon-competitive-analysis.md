# Shannon Competitive Analysis: Lessons for the AceofCloud Platform

**Author:** Harrison Cook  
**Date:** March 3, 2026  
**Subject:** Feature and architecture analysis of Shannon (KeygraphHQ) with actionable improvement recommendations for the Ace C3 engagement orchestrator

---

## Executive Summary

Shannon, developed by KeygraphHQ, is an open-source autonomous AI pentester that has rapidly gained traction in the security community, achieving a 96.15% success rate on the XBOW Benchmark and accumulating thousands of GitHub stars within days of its public release [1]. Its core philosophy of "No Exploit, No Report" — meaning it only reports vulnerabilities it can prove with a working proof-of-concept — represents a fundamentally different approach from traditional vulnerability scanners. This analysis examines Shannon's architecture, compares it against our Ace C3 engagement orchestrator, and identifies seven high-impact improvements we can adopt to strengthen our platform.

---

## 1. Shannon Architecture Overview

Shannon operates as a five-phase pipeline orchestrated by Temporal, a durable execution engine that provides crash recovery, queryable progress, and intelligent retry semantics [2]. The pipeline is powered by Anthropic's Claude via the Claude Agent SDK, with each phase handled by specialized AI agents.

| Phase | Name | Description |
|-------|------|-------------|
| 1 | **Pre-Recon** | External scans (Nmap, Subfinder, WhatWeb) combined with static source code analysis |
| 2 | **Recon** | Attack surface mapping from initial findings — endpoints, API routes, auth mechanisms, input fields |
| 3 | **Vulnerability Analysis** | Five parallel agents (Injection, XSS, Auth, Authz, SSRF) trace data flows from user input to dangerous sinks |
| 4 | **Exploitation** | Five parallel agents attempt real-world attacks via browser automation (Playwright) and CLI tools |
| 5 | **Reporting** | Executive-level security report with copy-paste PoC exploits per finding |

The critical architectural insight is that Phases 3 and 4 each run **five specialized agents concurrently**, one per OWASP vulnerability category. Each agent operates independently with its own prompt template, tool access, and checkpoint state. This parallelism dramatically reduces total scan time while allowing each agent to develop deep domain expertise in its vulnerability class [3].

Shannon's agent system uses a modular design where each agent is defined in a central `AGENTS` record with its own prompt template supporting variable substitution (`{{TARGET_URL}}`, `{{CONFIG_CONTEXT}}`). Agents run with `maxTurns: 10_000` and `bypassPermissions` mode, giving them full autonomy to iterate on complex exploitation chains. Each agent gets three automatic retries, and progress is checkpointed via git commits so interrupted scans can resume without re-running completed agents [4].

---

## 2. Head-to-Head Comparison

The following table compares Shannon's capabilities against our current Ace C3 engagement orchestrator across key dimensions.

| Capability | Shannon | Ace C3 (Our Platform) | Gap |
|------------|---------|----------------------|-----|
| **Execution Model** | Temporal durable workflows with crash recovery | In-memory state (`Map<number, EngagementOpsState>`) | **Critical** — our state is lost on server restart |
| **Parallelism** | 5 concurrent agents per phase (vuln analysis + exploitation) | Sequential tool execution per asset | **High** — our scans take significantly longer |
| **Exploit Validation** | Browser-based (Playwright) real exploit execution with PoC generation | Simulated via exploitation-bridge-engine; no actual exploit execution | **High** — we report theoretical vulns, not proven ones |
| **Agent Architecture** | Specialized agents per vuln category with dedicated prompts | Single LLM call for scan planning; deterministic tool execution | **Medium** — our LLM usage is limited to planning, not execution |
| **Resume/Checkpoint** | Git-based per-agent checkpointing; workspace system for resume | No resume capability; restart means re-run everything | **High** — long engagements are fragile |
| **Source Code Analysis** | White-box: reads source code to guide attack strategy | Black-box only: external scanning without code access | **Intentional** — different use case, but we could add optional white-box |
| **Tool Integration** | Nmap, Subfinder, WhatWeb, Schemathesis, Playwright | Nmap, Nuclei, Nikto, Gobuster, httpx, ZAP, Hydra | **Advantage** — we have broader tool coverage |
| **Scan Planning** | AI generates attack strategy from code + recon data | LLM generates scan plan from passive recon data | **Comparable** — both use LLM for planning |
| **Operator Controls** | Fully autonomous (no approval gates) | Approval gates for orange/red risk actions | **Advantage** — our approach is safer for real engagements |
| **Report Quality** | Pentester-grade with reproducible PoC exploits | LLM-generated narrative report with findings summary | **Medium** — we lack reproducible PoC evidence |
| **Evasion Techniques** | Not mentioned (targets own apps) | Nmap evasion profiles (timing, fragmentation, decoys) | **Advantage** — critical for external pentesting |
| **WAF Awareness** | Not mentioned | WAF detection and adaptive scanning | **Advantage** — important for real-world targets |

---

## 3. Key Lessons and Actionable Improvements

### 3.1 Parallel Agent Execution (Priority: High)

Shannon's most impactful architectural decision is running specialized agents in parallel during vulnerability analysis and exploitation. While our orchestrator processes tools sequentially per asset, Shannon runs five independent agents concurrently — each focused on a single vulnerability class (injection, XSS, auth bypass, authz, SSRF).

**What to implement:** Restructure our Phase B (targeted enumeration) and vuln_detection phases to execute tool commands in parallel rather than sequentially. For each asset, nuclei, nikto, gobuster, and httpx can all run concurrently since they target different vulnerability surfaces. This could reduce Phase B execution time by 60-70%.

**Implementation approach:** Use `Promise.allSettled()` to run multiple `executeTool` calls concurrently per asset, with a configurable concurrency limit (e.g., 3 tools per asset simultaneously). Each tool's results would be collected independently and merged into the asset's `toolResults` array upon completion.

---

### 3.2 Durable State and Resume Capability (Priority: High)

Our engagement state currently lives in an in-memory `Map<number, EngagementOpsState>`. If the server restarts mid-engagement, all progress is lost. Shannon solves this with Temporal's durable execution engine, which provides automatic crash recovery and the ability to resume from the last successful checkpoint.

**What to implement:** Persist engagement state to the database at each phase transition and after each tool execution completes. Add a `resumeEngagement` function that loads the last persisted state and continues from where it left off. This does not require adopting Temporal — a simpler approach using database-backed state with phase markers would suffice.

**Implementation approach:** Create an `engagement_state_snapshots` table that stores serialized state after each significant operation. On resume, load the latest snapshot and skip completed tools/phases based on the `toolResults` and `log` entries already recorded.

---

### 3.3 Browser-Based Exploit Validation (Priority: High)

Shannon's defining feature is its ability to actually execute exploits through a real browser, proving vulnerabilities are exploitable rather than just theoretically present. Our platform currently uses a simulated exploitation bridge that generates exploit plans but does not execute them.

**What to implement:** Integrate a headless browser (Playwright or Puppeteer) on the scan server to validate web application vulnerabilities. After nuclei or ZAP identifies a potential XSS, SQLi, or auth bypass, a browser-based validation agent would attempt to reproduce the finding and capture evidence (screenshots, HTTP traces, DOM state).

**Implementation approach:** This is the most complex improvement but also the highest-value one. Start with a focused scope: validate XSS findings by injecting payloads through the browser and checking for DOM execution, and validate auth bypass by attempting to access protected resources without credentials. Each validated finding would include a screenshot and HTTP request/response as proof.

---

### 3.4 Specialized LLM Agents per Vulnerability Class (Priority: Medium)

Shannon uses dedicated AI agents with specialized prompts for each vulnerability category. Our platform uses a single LLM call to generate the entire scan plan, then executes tools deterministically. The specialized agent approach allows deeper analysis because each agent can iterate on its specific domain.

**What to implement:** Create specialized LLM prompt templates for each vulnerability class (web app vulns, network service vulns, credential weaknesses, misconfigurations). After initial scanning, invoke the appropriate specialist agent to analyze findings in its domain and suggest follow-up actions.

**Implementation approach:** Add a post-scan "deep analysis" phase where the LLM receives only the findings relevant to its specialty (e.g., all XSS-related nuclei and ZAP findings) and generates targeted follow-up commands or validation steps. This is lighter-weight than Shannon's full agent system but captures most of the value.

---

### 3.5 Reproducible Proof-of-Concept Generation (Priority: Medium)

Shannon's "No Exploit, No Report" philosophy means every finding comes with a copy-paste PoC that the development team can use to reproduce the issue. Our reports include findings with severity ratings and descriptions but lack reproducible evidence.

**What to implement:** For each confirmed vulnerability, generate a standalone PoC that includes the exact curl command, HTTP request, or browser steps needed to reproduce it. Store these as structured data alongside the finding.

**Implementation approach:** After tool parsing, use the LLM to transform raw tool output (nuclei JSONL, ZAP alerts, nikto findings) into structured PoC objects containing: (1) a curl command or HTTP request that triggers the vulnerability, (2) the expected response indicating success, and (3) remediation guidance. These PoCs would be included in the engagement report.

---

### 3.6 Configuration-Driven Scan Profiles (Priority: Medium)

Shannon supports YAML configuration files with JSON Schema validation for customizing scan behavior, authentication settings, MFA/TOTP handling, and per-application testing parameters. Our platform relies on the LLM to determine scan parameters dynamically.

**What to implement:** Add scan profile presets (Quick, Standard, Deep, Stealth) that operators can select before launching an engagement. Each profile would define tool selection, timeout values, concurrency limits, evasion settings, and scope constraints. Additionally, allow operators to save custom profiles for recurring engagements.

**Implementation approach:** Create a `scan_profiles` table and a YAML/JSON schema for profile definitions. The engagement orchestrator would load the selected profile at startup and use it to configure tool execution parameters, replacing hard-coded values.

---

### 3.7 Structured Deliverables System (Priority: Low)

Shannon saves deliverables (findings, reports, evidence) to a structured directory within the target repository using a dedicated `save_deliverable` MCP tool. Each agent produces typed deliverables that are collected and merged into the final report.

**What to implement:** Formalize our report generation to produce structured deliverables per phase: a recon summary, an enumeration report, a vulnerability assessment, and an exploitation evidence package. Each deliverable would be stored in S3 and linked to the engagement record.

**Implementation approach:** Define deliverable types in the schema and create a `saveDeliverable` helper that uploads structured JSON + rendered Markdown to S3. The final report generator would compose these deliverables into a comprehensive engagement report.

---

## 4. Implementation Roadmap

The following table prioritizes the improvements by impact and effort, suggesting an implementation order.

| Priority | Improvement | Estimated Effort | Impact | Dependencies |
|----------|------------|-----------------|--------|-------------|
| 1 | Parallel tool execution | 2-3 days | High — 60-70% faster scans | None |
| 2 | Durable state / resume | 3-4 days | High — eliminates lost progress | DB schema change |
| 3 | PoC generation from findings | 2-3 days | Medium — dramatically better reports | LLM integration |
| 4 | Scan profile presets | 2 days | Medium — better operator UX | DB schema change |
| 5 | Specialized vuln analysis agents | 3-4 days | Medium — deeper findings | LLM prompt engineering |
| 6 | Browser-based exploit validation | 1-2 weeks | Very High — proven exploits | Playwright on scan server |
| 7 | Structured deliverables system | 2-3 days | Low — cleaner report pipeline | S3 integration |

---

## 5. What We Already Do Better

It is worth noting several areas where our platform already exceeds Shannon's capabilities, and these should be preserved and strengthened.

**Operator approval gates** provide critical safety controls for real-world engagements where unauthorized exploitation could cause damage. Shannon runs fully autonomously with no human-in-the-loop controls, which is appropriate for testing your own applications but dangerous for client engagements.

**Broader tool coverage** with Nuclei, Nikto, Gobuster, httpx, ZAP, and Hydra gives us more comprehensive scanning than Shannon's Nmap + Subfinder + WhatWeb + Schemathesis stack. Our technology-aware nuclei tag targeting is particularly effective.

**Evasion and stealth capabilities** including Nmap timing profiles, packet fragmentation, decoy scanning, and WAF-aware ZAP configuration are essential for external pentesting against production systems. Shannon does not address evasion because it targets applications the user owns.

**Black-box external perspective** is what clients actually need for penetration testing. Shannon's white-box requirement (source code access) limits it to internal security teams. Our platform can test any externally accessible target.

**Real-time WebSocket event streaming** provides operators with live visibility into scan progress, which Shannon lacks (it relies on Temporal's query API and log files).

---

## 6. Conclusion

Shannon represents the cutting edge of AI-driven autonomous pentesting, and its architecture offers several patterns worth adopting. The highest-impact improvements for our platform are parallel tool execution, durable state management, and PoC generation — all of which can be implemented incrementally without disrupting our existing pipeline. Browser-based exploit validation is the most transformative capability but requires the most investment. By selectively adopting Shannon's strengths while preserving our advantages in operator safety, tool breadth, and black-box testing, we can build a platform that combines the best of both approaches.

---

## References

[1]: https://github.com/KeygraphHQ/shannon "KeygraphHQ/shannon — GitHub"
[2]: https://pinggy.io/blog/automate_penetration_testing_with_ai/ "Completely Automate Penetration Testing with AI — Pinggy"
[3]: https://betterstack.com/community/guides/ai/shannon-ai/ "AI Penetration Testing with Shannon — BetterStack"
[4]: https://github.com/KeygraphHQ/shannon/blob/main/CLAUDE.md "CLAUDE.md — Shannon Architecture Reference"
