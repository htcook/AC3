# Auth Testing Pack v1.2 — Cross-Module Carry-Over Analysis

## Patterns That Carry Across Modules

### 1. Pipeline Orchestration Engine → All Scanning Modules
The `AuthPipelineEngine` pattern (template → initialize → step-by-step advance with guardrails) is directly reusable for:
- **Discovery Chain**: Replace ad-hoc tool chaining with orchestrated recon pipelines
- **Vuln Scanning Hub**: Nuclei/ZAP scan workflows with rate limiting and evidence capture
- **Web App Scanner**: Multi-phase web app assessment with scope enforcement
- **Credential Attacks**: Hydra/Medusa workflows with lockout detection guardrails

### 2. Guardrail System → Scan Policy Engine (All Profiles)
The strict/standard dual-mode guardrail pattern applies to:
- **Cloud Attack Paths**: Rate-limited API enumeration for AWS/Azure/GCP
- **AD Attack Sim**: Kerberoasting/AS-REP roasting with lockout-aware throttling
- **API Security Testing**: Fuzzing with request-rate caps per endpoint

### 3. Evidence Store → Evidence Collection + Compliance Dashboard
SHA-256 hashed evidence chains apply to:
- **KSI Evidence Chain**: Same integrity model for all key security indicators
- **OSCAL Export**: Evidence artifacts can feed directly into OSCAL assessment results
- **Post-Engagement Reports**: Tamper-evident evidence attachments

### 4. CARVER+Shock Auth Overlay → CARVER Scoring (All Target Types)
The conditional scoring adjustment pattern (auth-specific multipliers) extends to:
- **Cloud infrastructure** targets (API key exposure = higher criticality)
- **OT/ICS** targets (default credential prevalence = higher accessibility)
- **Mobile app** targets (certificate pinning = lower exploitability)

### 5. LLM Reasoning Framework → All AI Personas
The auth reasoning chain (classify → assess → recommend) pattern applies to:
- **AI Attack Planner**: Same structured reasoning for non-auth attack planning
- **Campaign Advisor**: Evidence-backed campaign recommendations
- **Corroboration Engine**: Cross-source validation with confidence scoring
