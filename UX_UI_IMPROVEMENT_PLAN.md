# AC3 — UX/UI Improvement Plan

**Objective:** Transform AC3 from a feature-rich platform that risks feeling "massive and confusing" into one that feels **intuitive, creative, and beautiful** — where the depth of capability is discovered progressively rather than presented all at once. The brutalist design aesthetic is preserved and refined throughout.

**Source Document:** *Best Operator-Centric UX/UI for a Penetration Testing and Red Team Platform in 2026* (17-page research paper, 110 citations)

**Current State:** 243 page components, ~148 unique navigation items across 8 groups and 15 sub-sections, 7 defined user roles with role-based access control already implemented.

---

## 1. The Core Problem: Cognitive Overload

The platform currently exposes between 10 and 148 navigation items depending on role. Even the most restricted technical role (Analyst) sees 80 items. The research document identifies this as the primary UX failure mode for offensive security platforms:

> "Fragmented tooling, inconsistent logs/artifacts, heavy context switching, and disproportionate time on reporting/retesting/collaboration" represent the core UX tax operators pay. [p.1]

The solution is not to remove features but to restructure how they are discovered and accessed. The document recommends a **"two-pane + timeline spine"** layout with **progressive disclosure** — showing only what matters for the current task, with everything else one keystroke away.

---

## 2. Design Philosophy: Brutalist Clarity

The brutalist aesthetic already serves the platform well. The improvement plan refines it rather than replacing it, guided by three principles:

| Principle | Current State | Target State |
|---|---|---|
| **Progressive Disclosure** | All nav items visible simultaneously in sidebar | Role-aware landing pages surface 5-8 primary actions; full nav accessible via command palette |
| **Context-First Layout** | Every page wraps in AppShell with full nav | Pages show contextual breadcrumbs + inspector; nav collapses to icon rail |
| **Operational Tempo** | Dashboard of charts | Live cockpit showing "what's happening now" with timeline spine |

---

## 3. Role-Specific UX Design

Each role should experience the platform differently — not just in what they can access, but in how the interface presents itself. The following table maps each role to its primary workflow, landing experience, and navigation philosophy.

### 3.1 Role Experience Matrix

| Role | Users | Primary Workflow | Landing View | Nav Items Visible | Navigation Model |
|---|---|---|---|---|---|
| **Operator** | Red team operators | Plan → Execute → Capture Evidence → Report | Operator Cockpit (timeline + active tasks) | ~15 pinned + command palette | Mission-centric: grouped by current engagement phase |
| **Team Lead** | Engagement managers | Assign → Monitor → Review → Deliver | Engagement Pipeline (kanban + team status) | ~20 pinned + command palette | Pipeline-centric: engagements, team, approvals |
| **Analyst** | Threat/vuln analysts | Collect → Analyze → Correlate → Brief | Intel Dashboard (threat feeds + vuln triage) | ~12 pinned + command palette | Analysis-centric: intel sources, findings, coverage |
| **SOC Analyst** | Security operations | Monitor → Detect → Validate → Respond | SOC Cockpit (detection coverage + alerts) | ~15 pinned + command palette | Detection-centric: alerts, validation, coverage |
| **Executive** | CISO / leadership | Review → Decide → Communicate | Executive Scorecard (KSIs + risk trends) | ~8 pinned | Outcome-centric: risk posture, compliance, trends |
| **Client** | External stakeholders | Review → Comment → Accept | Client Portal (reports + findings status) | ~5 pinned | Read-only: reports, findings, remediation status |
| **Admin** | Platform administrators | Configure → Monitor → Troubleshoot | System Health (infra + errors + queues) | ~20 pinned + full nav | System-centric: all platform admin tools |

### 3.2 Detailed Role Designs

#### Operator — "The Warfighter"

The operator's interface should feel like a **mission cockpit**, not an admin panel. The research document's mockup concept (p.13) directly applies:

**Landing View: Operator Cockpit**
The cockpit is built around three columns that map to the operator's mental model during an engagement:

- **Left Column — Mission Context:** Current engagement name, scope status, ROE summary, active task queue with explicit states (queued, running, paused, complete, failed). This replaces the current 13-item "Mission Operations" sub-section with a contextual task list.

- **Center Column — Timeline Spine:** A chronological event stream showing what happened and what's happening now. Each event is a structured record (timestamp, actor, action, target, result) that links to evidence. This is the operator's primary working surface — not a dashboard of charts.

- **Right Column — Context Inspector:** A detail panel that shows the full context of whatever the operator selects in the timeline or task queue. For a finding, it shows severity, evidence, remediation notes, and retest status. For a host, it shows ports, services, vulnerabilities, and attack paths.

**Navigation:** The sidebar collapses to an icon rail showing 6 group icons. The operator's pinned items (configurable) appear as a "Favorites" section at the top. Everything else is accessible via `Ctrl/Cmd+K` command palette or `/` search.

**Key Interactions:**
- One-click evidence capture from any context (screenshot, terminal output, file)
- Drag-and-drop findings into report sections
- Keyboard-driven task creation and status updates
- Inline LLM copilot for attack planning suggestions (supervised, not autonomous)

#### Team Lead — "The Conductor"

The team lead needs to see across engagements and across team members simultaneously.

**Landing View: Engagement Pipeline**
A kanban-style view showing all active engagements in their current phase (Scoping → Discovery → Testing → Reporting → Delivered). Each card shows: engagement name, assigned operators, progress percentage, days remaining, and blockers.

**Key Panels:**
- **Team Activity Feed:** Who is doing what, across all engagements
- **Approval Queue:** Findings pending review, scope change requests, ROE modifications
- **Resource Allocation:** Which operators are assigned where, capacity planning
- **Client Communication Log:** Recent client interactions and pending deliverables

**Navigation:** Same icon rail as operator, plus "Platform" group for team management. The command palette includes team-specific actions (assign operator, create engagement, approve finding).

#### Analyst — "The Investigator"

The analyst's interface emphasizes **correlation and context** — connecting intelligence to findings to coverage gaps.

**Landing View: Analysis Dashboard**
A three-panel layout optimized for investigation:

- **Left — Source Feeds:** Threat intel feeds, vulnerability databases, OSINT monitors, IOC feeds. Each source shows unread count and last update time.
- **Center — Investigation Workspace:** A flexible canvas where the analyst can pin findings, threat actors, CVEs, and attack paths side-by-side for comparison.
- **Right — Coverage Matrix:** ATT&CK coverage heat map showing which techniques are tested, which have detections, and which are gaps.

**Key Interactions:**
- Drag intelligence items into investigation workspace
- One-click correlation between threat actor TTPs and detection coverage
- Inline enrichment (WHOIS, passive DNS, reputation) without leaving the workspace
- Export investigation as structured brief or STIX bundle

#### SOC Analyst — "The Defender"

The SOC analyst validates that defenses actually work. Their interface bridges offensive testing and defensive monitoring.

**Landing View: Defense Validation Cockpit**
- **Top Strip:** Detection coverage score, last validation run, active alerts, mean time to detect
- **Center — Validation Matrix:** A grid showing attack techniques vs. detection tools, with pass/fail/untested states. Color-coded but not relying on red/green alone (using shapes and patterns per WCAG 2.2).
- **Bottom — Validation Timeline:** Recent test runs with results, linked to specific detection rules and SIEM alerts

**Key Interactions:**
- Launch validation tests against specific detection rules
- Compare "before and after" detection coverage across validation runs
- Link failed detections to remediation tickets
- Export validation evidence for compliance reporting

#### Executive — "The Decision Maker"

The executive sees the platform through the lens of **business risk and compliance posture**. The interface should be clean, data-dense but not cluttered, and immediately actionable.

**Landing View: Executive Scorecard**
A single-page view with four quadrants:

| Quadrant | Content |
|---|---|
| **Risk Posture** | Overall risk score with trend line, top 5 critical findings, mean time to remediate |
| **Compliance Status** | Framework coverage percentages (FedRAMP, NIST, PCI), upcoming audit dates, evidence gaps |
| **Engagement Summary** | Active engagements with status, recent deliverables, client satisfaction |
| **KSI Trends** | Key Security Indicators over time, with drill-down to evidence chains |

**Navigation:** Minimal — only 3 groups visible (Command Center → Risk & Analysis, KSI, Reports). No technical tooling exposed. The command palette is available but surfaces only executive-relevant actions.

#### Client — "The Stakeholder"

The client portal is a **read-only, report-focused experience** that builds trust through transparency.

**Landing View: Assessment Portal**
- **Header:** Engagement name, status, timeline, assigned team
- **Findings Summary:** Severity distribution chart, remediation progress bar
- **Findings Table:** Sortable/filterable list with severity, status (open/remediated/accepted), and remediation guidance
- **Reports Section:** Downloadable reports in PDF/DOCX format
- **Communication:** Comment threads on individual findings for clarification

**Navigation:** Single group (Reports & Knowledge) with 5-10 items. No sidebar — top navigation bar with engagement switcher.

#### Admin — "The Architect"

The admin retains full access but with a **system health focus** on their landing page.

**Landing View: System Health Dashboard**
- **Infrastructure Status:** Server health, scan server status, queue depths, error rates
- **User Activity:** Active sessions, recent logins, role distribution
- **Platform Metrics:** LLM telemetry, API latency, storage usage
- **Quick Actions:** Common admin tasks (invite user, create tenant, review queue)

**Navigation:** Full sidebar with all groups, but organized with admin-specific items promoted to the top. The command palette includes system-level actions (restart service, clear queue, promote user).

---

## 4. Navigation Redesign: From Menu Wall to Progressive Discovery

### 4.1 The Three-Layer Navigation Model

The research document recommends replacing the current "everything in the sidebar" approach with three layers:

| Layer | Mechanism | Items Shown | Access Speed |
|---|---|---|---|
| **Layer 1: Icon Rail** | Always-visible collapsed sidebar | 8 group icons + favorites | Instant (always visible) |
| **Layer 2: Command Palette** | `Ctrl/Cmd+K` or `/` | All items, searchable | Fast (1 keystroke) |
| **Layer 3: Expanded Sidebar** | Hover/click on icon rail group | Items within one group | Medium (2 interactions) |

This approach reduces the visible nav items from 80-148 to **8-15** while keeping everything accessible within one keystroke. The command palette becomes the primary navigation tool for power users, while the icon rail provides spatial memory for frequent destinations.

### 4.2 Command Palette Design

The command palette (triggered by `Ctrl/Cmd+K`) should be the single most powerful UI element in the platform. It combines navigation, actions, and search into one interface:

**Sections within the palette:**
1. **Recent:** Last 5 visited pages (learning from usage patterns)
2. **Pinned:** User's favorited pages (persistent across sessions)
3. **Navigate:** All pages, searchable by name or keyword
4. **Actions:** Context-aware actions (e.g., "Create Engagement", "Start Scan", "Generate Report")
5. **Search:** Full-text search across findings, assets, engagements, and evidence

### 4.3 Favorites & Pinning System

Each user can pin up to 15 items to their "Favorites" section at the top of the icon rail. Defaults are set per role:

| Role | Default Pinned Items |
|---|---|
| Operator | Dashboard, Engagements, Engagement Ops, Nuclei Scanner, Exploit Arsenal, Evidence, Reports |
| Team Lead | Dashboard, Engagement Pipeline, Team, Campaigns, Reports, Audit Log |
| Analyst | Dashboard, Threat Intel Hub, Detection Coverage, ATT&CK Coverage, IOC Feed, Reports |
| SOC | Dashboard, Detection Coverage, Purple Team, Agentless BAS, Control Testing, Sigma Rules |
| Executive | KSI Dashboard, Risk Trending, Compliance, Reports |
| Client | Reports, Pentest Report |
| Admin | Dashboard, Error Dashboard, Team, Job Queue, LLM Telemetry, Infrastructure |

---

## 5. Visual Design Refinements (Brutalist + Beautiful)

The brutalist aesthetic works because it communicates **seriousness and precision**. The refinements below enhance beauty without compromising the brutalist identity.

### 5.1 Typography Hierarchy

The current font stack (Inter + JetBrains Mono) is strong. Refinements:

| Element | Current | Proposed |
|---|---|---|
| Page titles | `font-display tracking-wider` (Inter Bold) | Add subtle letter-spacing animation on page load |
| Section headers | Various sizes | Standardize to 3 sizes: `text-lg`, `text-base`, `text-sm` with consistent `tracking-wider` |
| Data labels | Inconsistent | All caps, `text-[10px]`, `tracking-widest`, `text-muted-foreground` |
| Monospace data | JetBrains Mono | Add tabular-nums for aligned numbers in tables |

### 5.2 Color System Enhancement

The current OKLCH color system is well-designed. Additions:

| Purpose | Current | Proposed Addition |
|---|---|---|
| Severity indicators | Red/amber/green | Add **shape indicators** (triangle=critical, diamond=high, circle=medium, square=low) for WCAG compliance |
| Status semantics | Inconsistent | Standardize: `primary` = active/running, `emerald` = success, `amber` = warning, `red` = critical, `muted` = inactive |
| Role accent colors | Badge colors defined | Extend to subtle page-level tinting (e.g., operator pages have faint red-500/5 background accent) |
| Interactive states | Basic hover | Add micro-transitions: 150ms ease-out for all interactive elements |

### 5.3 Spacing and Density

The research document emphasizes that security operators prefer **information-dense** layouts but with clear visual hierarchy:

- **Card spacing:** Standardize to `gap-3` (12px) between cards, `gap-6` (24px) between sections
- **Table density:** Compact mode (28px rows) as default for data tables, comfortable mode (40px) as option
- **Sidebar width:** 64px collapsed (icon rail), 256px expanded, with smooth 200ms transition
- **Inspector panel:** 320px default, resizable, with snap points at 280/320/400px

### 5.4 Micro-Interactions

Small animations that make the platform feel "crafted":

- **Page transitions:** Subtle fade-in (150ms) when navigating between pages
- **Card hover:** Slight elevation change (shadow-sm → shadow-md) with 150ms transition
- **Status changes:** Pulse animation on status badge when state changes (e.g., scan completes)
- **Loading states:** Skeleton screens that match the actual content layout (already partially implemented)
- **Toast notifications:** Slide in from top-right with progress bar for timed dismissal
- **Command palette:** Backdrop blur with 100ms fade, results animate in with stagger

---

## 6. Key UX Patterns from the Research Document

### 6.1 Unified Timeline Spine (Top Priority)

The document identifies this as the **single most impactful UX improvement** for offensive security platforms. Every action, finding, and event flows into a single chronological stream per engagement.

**Implementation approach:**
- Create an `EngagementTimeline` component that aggregates events from scans, findings, evidence captures, and manual notes
- Each event is a structured record with: timestamp, actor (human or tool), action, target, result, and linked evidence
- The timeline supports filtering by event type, actor, and severity
- Events are append-only with cryptographic integrity (hash chain)

### 6.2 Engagement Container (Top Priority)

All work happens within an engagement context. The engagement container provides:
- Scope boundaries (what targets are in-scope, what's excluded)
- ROE guardrails (what actions are permitted)
- Task status tracking (queued → running → paused → complete → failed)
- Evidence chain (all artifacts linked to the engagement)
- Report generation (pull from engagement data)

### 6.3 Findings Workbench (Top Priority)

A dedicated workspace for managing findings through their lifecycle:
- **States:** Draft → Validated → Reported → Remediated → Retested → Closed
- **Severity:** Critical / High / Medium / Low / Informational (with shape + color indicators)
- **Evidence:** Each finding links to one or more evidence items (screenshots, terminal output, request/response pairs)
- **Remediation:** Inline remediation guidance with retest workflow
- **Deduplication:** Automatic grouping of similar findings across scans

### 6.4 LLM Copilot (High Priority)

The document recommends a **"supervised copilot"** model — the LLM suggests, the operator approves:
- Plan preview panel showing proposed steps before execution
- Tool-call ledger (immutable log of all LLM-initiated actions)
- Guardrails: in-scope targets only, no autonomous chaining, output sanitization
- Citations linking LLM suggestions to evidence and knowledge base entries

The existing Platform Advisor chat already implements some of this. Enhancements:
- Move from floating chat bubble to docked side panel within the cockpit
- Add plan preview mode for multi-step suggestions
- Show confidence scores and source citations for recommendations

---

## 7. Keyboard Shortcuts (Power User UX)

The research document provides a recommended shortcut set. Mapped to AC3:

| Shortcut | Action | Rationale |
|---|---|---|
| `Ctrl/Cmd+K` | Command palette | Primary navigation + action hub |
| `/` | Global search | Quick access to any entity |
| `g` then `d` | Go to Dashboard | Spatial navigation |
| `g` then `e` | Go to Engagements | Spatial navigation |
| `g` then `f` | Go to Findings | Spatial navigation |
| `g` then `t` | Go to Timeline | Spatial navigation |
| `Shift+Space` | Pause current task | Safety control |
| `Ctrl/Cmd+Shift+E` | Capture evidence | One-keystroke evidence capture |
| `Ctrl/Cmd+R` | Replay last task | Rapid iteration |
| `?` | Show keyboard shortcuts | Discoverability |

All shortcuts should be user-remappable via Account Settings.

---

## 8. Implementation Roadmap

### Phase 1: Foundation (Weeks 1-3)
- [ ] Implement icon rail navigation (collapsed sidebar with 8 group icons)
- [ ] Build command palette component (`Ctrl/Cmd+K`)
- [ ] Add favorites/pinning system with role-specific defaults
- [ ] Standardize page-level description headers across all pages
- [ ] Add page transition animations (fade-in 150ms)

### Phase 2: Role Landing Pages (Weeks 4-6)
- [ ] Redesign Operator Home as Operator Cockpit (timeline + tasks + inspector)
- [ ] Redesign Team Lead Home as Engagement Pipeline (kanban + team feed)
- [ ] Redesign Analyst Home as Analysis Dashboard (feeds + workspace + coverage)
- [ ] Redesign SOC Home as Defense Validation Cockpit
- [ ] Refine Executive Home as Executive Scorecard (4-quadrant layout)
- [ ] Refine Client Home as Assessment Portal (findings + reports)
- [ ] Redesign Admin Home as System Health Dashboard

### Phase 3: Core UX Patterns (Weeks 7-10)
- [ ] Build Unified Timeline Spine component
- [ ] Enhance Engagement container with scope/ROE/task tracking
- [ ] Build Findings Workbench with state machine workflow
- [ ] Add evidence capture one-click from any context
- [ ] Implement keyboard shortcuts system with `?` help overlay

### Phase 4: Polish & Refinement (Weeks 11-12)
- [ ] Enhance LLM Copilot with plan preview and tool-call ledger
- [ ] Add micro-interactions (card hover, status pulse, loading skeletons)
- [ ] Implement density controls (compact/comfortable table modes)
- [ ] Add role-specific page tinting
- [ ] User testing and iteration

---

## 9. Success Metrics

| Metric | Current Baseline | Target |
|---|---|---|
| Time to first meaningful action after login | Unknown (likely 3-5 clicks) | < 1 click (role landing page) |
| Navigation items visible on landing | 80-148 | 8-15 (icon rail + favorites) |
| Keyboard shortcut coverage | Partial (search exists) | 10+ core shortcuts |
| Pages with purpose description header | ~30% | 100% |
| Consistent status color semantics | ~50% | 100% |
| WCAG 2.2 AA compliance (focus, contrast) | Partial | Full |

---

## 10. Design Principles Summary

1. **Show less, access everything.** The sidebar is not a table of contents — it's a launchpad. Use progressive disclosure to reveal depth on demand.

2. **Role = lens, not cage.** Each role sees a different default view, but the full platform is always one `Ctrl+K` away. Never make users feel locked out.

3. **Timeline over dashboard.** Operators think in sequences of events, not pie charts. The timeline spine is the primary working surface.

4. **Brutalist means honest.** Raw data, clear typography, no decorative chrome. But honest doesn't mean ugly — precision in spacing, alignment, and micro-interactions makes brutalism beautiful.

5. **Keyboard-first, mouse-friendly.** Every action should be reachable by keyboard. The mouse is for exploration; the keyboard is for execution.

6. **Context travels with the operator.** When an operator selects a host, finding, or engagement, that context persists across navigation. The inspector panel follows them.

---

*Document prepared by Manus AI based on analysis of "Best Operator-Centric UX/UI for a Penetration Testing and Red Team Platform in 2026" and the current AC3 codebase (243 pages, 7 roles, ~148 nav items).*
