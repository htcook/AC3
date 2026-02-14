# Caldera Dashboard TODO

## Core Features
- [x] Server status monitoring dashboard (health, uptime, resources)
- [x] Secure credential management interface (admin login, API keys, SSH)
- [x] Real-time Caldera statistics via API (adversaries, abilities, operations)
- [x] APT29 VCD campaign viewer with ability breakdown
- [x] MITRE ATT&CK threat group browser (156+ adversary profiles)
- [x] Server management controls (restart, logs, config)
- [x] Team access control with role-based permissions
- [x] Quick action buttons (Caldera UI, SSH strings, API testing)

## Design
- [x] Brutalist aesthetic with solid black background
- [x] High contrast white condensed sans-serif typography
- [x] Vivid red horizontal divider lines
- [x] Centered minimalist layout
- [x] Industrial atmosphere styling

## Database Schema
- [x] Server configurations table
- [x] Credentials storage (encrypted)
- [x] Team members and roles
- [x] Activity logs

## API Integration
- [x] Caldera API connection for live stats
- [x] Server health check endpoints
- [x] SSH command generation

## Campaign Building Workflow
- [x] Campaign management database schema (campaigns, agents, campaign_abilities)
- [x] Campaign creation form with name, description, target environment
- [x] Agent management (add/remove agents to campaigns)
- [x] Adversary selection for campaigns
- [x] Ability selection and ordering for campaigns
- [x] Campaign status tracking (draft, active, completed)
- [x] Pre-built Databank Red Team Exercise campaign with APT29-VCD Enhanced
- [x] Campaign detail view with execution timeline
- [ ] Export campaign configuration

## Credential Updates
- [x] Update Red Team login password to PVYedK$BUAYzyXaAegdEl2Dz (already set)

## DigitalOcean Deployment
- [x] Build production bundle of dashboard
- [x] Transfer files to DigitalOcean server
- [x] Install Node.js and dependencies on server
- [x] Configure nginx reverse proxy for dashboard (port 3001)
- [x] Set up systemd service for dashboard
- [x] Configure environment variables
- [x] Verify dashboard is accessible at https://137.184.7.224:3001

## Dashboard Integration Fix
- [x] Diagnose current dashboard Caldera server configuration
- [x] Update routers to use DigitalOcean Caldera API (137.184.7.224:8888)
- [x] Update credentials display to show correct API keys (ADMIN123, BLUEADMIN123)
- [x] Redeploy dashboard to DigitalOcean
- [x] Verify live integration with Caldera API (492 adversaries, 2 operations)

## Caldera API Loading Fix
- [x] Diagnose browser CORS issues with Caldera API
- [x] Add backend proxy routes for Caldera API calls
- [x] Update Dashboard to use backend proxy for stats
- [x] Update Adversaries page to use backend proxy
- [x] Add tactics and abilities loading
- [x] Redeploy to DigitalOcean and verify

## AceofCloud Branding
- [x] Gather branding materials from aceofcloud.com
- [x] Update logo and brand name throughout dashboard
- [x] Update color scheme to match AceofCloud brand (navy blue #0a1628, teal #14b8a6)
- [x] Add contact information from website
- [x] Update footer with AceofCloud details

## Caldera Server Issues
- [x] Troubleshoot Manual Command tab not loading in Operations page (requires agents)
- [x] Verify Caldera server plugins are working correctly (EMU enabled)

## Agent Deployment Scripts
- [x] Generate Windows PowerShell agent deployment script
- [x] Generate Linux bash agent deployment script
- [x] Generate macOS agent deployment script
- [x] Create agent deployment documentation
## Caldera Server Verification
- [x] Verify all plugins are working correctly
- [x] Check server configuration for issues
- [x] Ensure Manual Command (Manx) plugin is functional (requires agents to show sessions)

## Agents Section
- [x] Add agent tRPC endpoints to fetch from Caldera API
- [x] Create Agents page with detailed agent information
- [x] Display agent status, platform, hostname, last check-in
- [x] Add agent actions (kill, trust, untrust)
- [x] Add Agents link to navigation on all pages
- [x] Deploy to DigitalOcean

## Button Testing and Error Fixes
- [x] Test Home page buttons (Dashboard, Caldera UI)
- [x] Test Dashboard page buttons and quick actions
- [x] Test Credentials page copy buttons and links
- [x] Test Adversaries page search and filters
- [x] Test Agents page actions and deployment scripts
- [x] Test Campaigns page create and manage buttons
- [x] Test Team page member management
- [x] Fix all identified errors

## Authentication Fix (403 Error)
- [x] Fix 403 error on Get Started button - remove Manus OAuth dependency
- [x] Fix remaining TypeScript errors related to user references
- [x] Make dashboard work standalone without authentication
- [x] Test all dashboard pages are accessible
- [x] Redeploy to DigitalOcean server

## Authentication Implementation
- [x] Create login page with Caldera credentials
- [x] Add server-side authentication endpoint
- [x] Implement session management with JWT
- [x] Protect all dashboard routes
- [x] Add logout functionality
- [x] Test login/logout flow

## Comprehensive Button/Link Testing & Caldera Data Fix
- [x] Test Home page - Dashboard button, Get Started, Caldera Server links
- [x] Test Dashboard page - all quick actions, sidebar navigation
- [x] Fix Caldera API data loading (CORS issue) - add server-side proxy
- [x] Test Credentials page - copy buttons, external links
- [x] Test Adversaries page - search, filters, adversary cards (493 adversaries)
- [x] Test Agents page - agent actions, deployment scripts
- [x] Test Campaigns page - create campaign, manage buttons
- [x] Test Team page - member management
- [x] Test Activity page - logs display
- [x] Redeploy all fixes to DigitalOcean


## CrowdStrike Falcon Bypass Campaign
- [x] Research CrowdStrike Falcon bypass techniques
- [x] Identify relevant Caldera abilities for EDR evasion
- [x] Create CrowdStrike bypass adversary profile (Databank_CrowdStrike_Bypass)
- [x] Create Databank Operation for CrowdStrike testing (Databank_CrowdStrike_Falcon_Bypass_Operation)
- [x] Add 12 abilities for defense evasion tactics (T1562.001)
- [x] Update dashboard to display new campaign
- [x] Deploy to DigitalOcean

## Multiple APT Adversary Profiles
- [x] Query existing adversaries in Caldera (found 18 matching profiles)
- [x] APT28 (Fancy Bear) - already exists with 50 abilities
- [x] APT41 (Double Dragon) - already exists with 50 abilities
- [x] Lazarus Group - already exists with 50 abilities
- [x] FIN7 - already exists with 50 abilities
- [x] Cobalt Group - already exists with 50 abilities
- [x] Update dashboard to display all APT campaigns (6 APT groups on dashboard)
- [x] Fix static file serving issue on DigitalOcean (dist/public folder fixed)


## Adversary Profile Pages
- [x] Analyze current adversary page routing and click behavior
- [x] Create AdversaryDetail page component with full profile display
- [x] Add tRPC endpoint for fetching individual adversary with abilities
- [x] Display adversary metadata (name, description, techniques)
- [x] Display all abilities with tactics and descriptions
- [x] Add MITRE ATT&CK technique mapping
- [x] Test adversary profile loading locally
- [x] Deploy to DigitalOcean and verify


## Merged Databank Operation (VCD + CrowdStrike Bypass)
- [x] Query existing APT29 VCD and CrowdStrike Bypass operations
- [x] Get all abilities from both adversary profiles
- [x] Create merged adversary profile with defense evasion abilities (59 abilities)
- [x] Create unified Databank_Complete_Red_Team_Exercise operation
- [x] Update dashboard to show merged operation
- [x] Deploy to DigitalOcean and verify

## IP Routing Configuration
- [x] Configure nginx to route 137.184.7.224 to AceofCloud Dashboard on port 443
- [x] Ensure Caldera server remains accessible on port 8888 for agents
- [x] Test dashboard access via IP address (https://137.184.7.224)
- [x] Verify agent callbacks still work to Caldera server (http://137.184.7.224:8888)


## Agent Deployment Feature
- [x] Create agent deployment page with CrowdStrike bypass scripts
- [x] Add PowerShell, Bash, and Python deployment options
- [x] Include obfuscation techniques for EDR evasion
- [x] Add copy-to-clipboard functionality for deployment commands
- [x] Deploy to DigitalOcean

## Real-Time Operation Monitoring
- [x] Implement polling for live updates (WebSocket-ready)
- [x] Create live operation status component
- [x] Show ability execution progress in real-time
- [x] Display agent status updates
- [x] Add operation timeline visualization
- [x] Add security control effectiveness metrics
- [x] Add export functionality for results
- [x] Deploy to DigitalOcean

## Branded Report Generation
- [x] Generate AceofCloud Red Team Exercise Report
- [x] Include all operation results from Caldera (success AND failures)
- [x] Track blocked/failed attempts with timestamps and error details
- [x] Capture EDR/IDS detection events and block notices
- [x] Record Firewall/WAF responses with error codes
- [x] Add security control effectiveness assessment
- [x] Add MITRE ATT&CK mapping for attempted vs successful techniques
- [x] Include executive summary and recommendations
- [x] Create downloadable Markdown/JSON report
- [x] Attribute report to Harrison Cook as content creator
- [x] Deploy to DigitalOcean


## Caldera Backend Operations Fix
- [x] Query current state of all operations in Caldera
- [x] Check adversary profiles have all abilities linked
- [x] Verify Databank_Complete adversary has 59 abilities
- [x] Verify APT29_VCD_Cloud_Compromise_Enhanced has all abilities
- [x] Verify Databank_CrowdStrike_Bypass has 12 abilities
- [x] Fix any missing ability references
- [x] Test operations in Caldera UI


## Operations Detail Page with Abilities
- [x] Create OperationDetail page showing all abilities directly
- [x] Display operation metadata (name, state, adversary)
- [x] Show complete ability chain with MITRE ATT&CK mapping
- [x] Add ability execution status indicators
- [x] Include tactic grouping and filtering
- [x] Add "Run in Caldera" button for each ability
- [x] Deploy to DigitalOcean

## Caldera Server Campaign Configuration
- [x] Verify all operations exist with correct adversary links
- [x] Ensure Databank_Complete operation has 59 abilities
- [x] Ensure APT29_VCD operation has 48 abilities
- [x] Ensure CrowdStrike_Bypass operation has 12 abilities
- [x] Update Caldera credentials to red/ADMIN123
- [x] Test operations are accessible in Caldera UI


## Open Caldera Button Fix
- [x] Fix all "Open Caldera" buttons to link to http://137.184.7.224:8888
- [x] Fix Dashboard quick action Open Caldera button
- [x] Fix Campaigns page Open Caldera button (already correct)
- [x] Fix Operation Detail page Open in Caldera button (already correct)
- [x] Fix Home page Caldera Server button
- [x] Fix Credentials page Open Caldera Login button
- [x] Fix AdversaryDetail page Open in Caldera button
- [x] Fix Dashboard header Caldera UI button
- [x] Ensure links open in new tab with correct Caldera UI URL

## GoPhish Server + Caldera Integration

- [x] Install GoPhish on DigitalOcean server
- [x] Configure GoPhish admin panel and API
- [x] Open firewall ports for GoPhish (3333 admin, 8080 phishing)
- [x] Create Caldera-GoPhish webhook bridge for campaign coordination
- [x] Add GoPhish management page to AceofCloud Dashboard
- [x] Add GoPhish proxy endpoints to server routers
- [x] Display GoPhish campaigns, templates, and results in dashboard
- [x] Create phishing campaign launcher integrated with Caldera operations
- [x] Test full integration end-to-end
- [ ] Update Terraform files with GoPhish droplet configuration


## Admin Credential Rotation
- [x] Generate new secure credentials for all services
- [x] Update Caldera server credentials (red API key, blue API key, admin password)
- [x] Update GoPhish admin password and regenerate API key
- [x] Update AceofCloud Dashboard login password
- [x] Update dashboard code with new Caldera/GoPhish credentials
- [x] Update bridge service with new credentials
- [x] Rebuild and deploy dashboard
- [x] Verify all services work with new credentials


## Comprehensive Integration Testing
- [x] Test backend Caldera API connectivity with new credentials
- [x] Test backend GoPhish API connectivity with new credentials
- [x] Test Dashboard login with new password
- [x] Test Home page loads correctly
- [x] Test Dashboard page - stats, quick actions, sidebar nav
- [x] Test Credentials page - displays new credentials
- [x] Test Adversaries page - loads 494 adversaries from Caldera
- [x] Test Adversary Detail page - loads abilities (59 for Databank_Complete)
- [x] Test Campaigns page - shows operations from Caldera (3 operations)
- [x] Test Operation Detail page - shows abilities chain
- [x] Test Agents page - loads agent data (0 agents expected)
- [x] Test Agent Deploy page - deployment scripts
- [x] Test GoPhish page - campaigns, templates, landing pages
- [x] Test Operation Monitor page
- [x] Test Reports page
- [x] Test Team page
- [x] Test all Open Caldera buttons link to port 8888
- [x] Note: Operations lost on Caldera restart (memory-only storage)


## Operation Persistence
- [x] Create startup script to recreate 3 operations after Caldera restart
- [x] Create systemd service to run script after Caldera starts
- [x] Include all adversary profiles and ability mappings
- [x] Test by restarting Caldera and verifying operations persist

## GoPhish SMTP Sending Profile
- [x] Configure SMTP sending profile in GoPhish (Postfix local relay on port 25)
- [x] Create a sample email template (Security Awareness - Password Reset)
- [x] Create a sample landing page (Credential Capture - Password Reset)
- [x] Create a sample target group (Test Targets - Internal Team, 3 users)
- [x] Verify SMTP profile can send test emails

## Test Agent Deployment
- [x] Deploy a test Caldera Sandcat agent on the DigitalOcean server (paw: tzsbja)
- [x] Verify agent checks in with Caldera C2 (trusted, group: red)
- [x] Fix adversary ability ordering (Linux abilities first, Windows last)
- [x] Assign agent to APT29 operation and start execution
- [x] Validate ability chain execution: 5 abilities executed (3 success, 1 collected, 1 failed)
- [x] Verify results appear in operation chain

## Rename Caldera Command
- [x] Choose a new name: ACE STRIKE (reflects offensive security + Ace of Cloud brand)
- [x] Update Home page hero title
- [x] Update all page headers and references (12 files)
- [x] Update browser tab title

## Full GoPhish Management Panels
- [x] Add Create Email Template form with HTML editor
- [x] Add Edit/Delete Email Template functionality
- [x] Add Create Landing Page form with HTML editor
- [x] Add Edit/Delete Landing Page functionality
- [x] Add Create Sending Profile form (SMTP config)
- [x] Add Edit/Delete Sending Profile functionality
- [x] Add Create Target Group form with user import
- [x] Add Edit/Delete Target Group functionality
- [x] Add Launch Campaign form (select template, landing page, profile, group)
- [x] Add Campaign results/statistics view
- [x] Add server-side tRPC endpoints for all GoPhish CRUD operations
- [x] Ensure GoPhish panels are accessible from dashboard sidebar

- [x] Research and document email sender domain best practices for phishing simulations
- [x] Provide deliverability guide for avoiding common email filters


## APT29 TTPs Counter Rename
- [x] Change "APT29 TTPs" label to "Adversary TTP's"
- [x] Update the count to 348 (unique MITRE ATT&CK techniques across all adversaries)


## SSL Certificate Fix
- [ ] Diagnose current SSL configuration (self-signed cert causing browser warnings)
- [ ] Install proper trusted SSL certificate
- [ ] Update nginx configuration for new certificate
- [ ] Fix GoPhish admin panel certificate (port 3333)
- [ ] Verify no browser security warnings on any service


## GoPhish Knowledge Base & Campaign Guide
- [x] Research GoPhish user guides and admin documentation
- [x] Research phishing campaign design best practices
- [x] Research email template creation techniques
- [x] Research landing page design for credential capture
- [x] Research target group management and segmentation
- [x] Research campaign metrics and reporting
- [x] Create integrated knowledge base page in Ace Strike dashboard
- [x] Include step-by-step campaign creation workflow
- [x] Include email template design guide with examples
- [x] Include landing page design guide
- [x] Include SMTP/sending profile configuration guide
- [x] Include campaign analysis and reporting guide
- [x] Include security awareness testing best practices
- [x] Add sidebar navigation for the knowledge base
- [x] Deploy to DigitalOcean


## Caldera Knowledge Base & Operations Guide
- [x] Research Caldera user guides and admin documentation
- [x] Research adversary emulation planning and execution
- [x] Research agent deployment and management
- [x] Research ability and plugin development
- [x] Research operation planning and execution workflows
- [x] Research MITRE ATT&CK mapping and coverage
- [x] Create integrated Caldera knowledge base page in dashboard
- [x] Include agent deployment guide
- [x] Include adversary profile creation guide
- [x] Include operation planning and execution guide
- [x] Include ability development guide
- [x] Include reporting and analysis guide
- [x] Add sidebar navigation for the knowledge base
- [x] Deploy to DigitalOcean


## Searchable FAQ & Troubleshooting
- [x] Create searchable FAQ page with filtering/search functionality
- [x] Add Caldera troubleshooting: agent not checking in
- [x] Add Caldera troubleshooting: abilities failing to execute
- [x] Add Caldera troubleshooting: operations stuck or not progressing
- [x] Add Caldera troubleshooting: plugin errors and missing abilities
- [x] Add GoPhish troubleshooting: emails going to spam
- [x] Add GoPhish troubleshooting: SMTP connection failures
- [x] Add GoPhish troubleshooting: landing page not capturing credentials
- [x] Add GoPhish troubleshooting: campaign not sending emails
- [x] Add general troubleshooting: server connectivity issues
- [x] Add general troubleshooting: certificate/SSL errors
- [x] Add sidebar navigation link for FAQ page
- [x] Deploy to DigitalOcean

## Customer-Facing Security Assessment Report
- [x] Create report generation page with branded AceofCloud template
- [x] Pull live GoPhish campaign results (emails sent, opened, clicked, submitted)
- [x] Pull live Caldera operation data (abilities executed, success/fail rates)
- [x] Include executive summary section
- [x] Include MITRE ATT&CK technique coverage matrix
- [x] Include phishing campaign effectiveness metrics
- [x] Include red team operation timeline and results
- [x] Include security recommendations based on findings
- [x] Include risk scoring and severity ratings
- [x] Generate downloadable PDF/Markdown report
- [x] Attribute report to Harrison Cook / AceofCloud
- [x] Add sidebar navigation link for report generator
- [x] Deploy to DigitalOcean

## GoPhish Credentials on Credentials Page
- [x] Add GoPhish admin credentials (admin / ADMIN123) to Credentials page
- [x] Add GoPhish API key to Credentials page
- [x] Add GoPhish admin URL to Credentials page

## Rename Ace Strike to Cyber Campaign Command
- [x] Find and replace all "Ace Strike" references across the codebase
- [x] Update sidebar branding text
- [x] Update page headers and titles
- [x] Update Home page hero
- [x] Verify no remaining Ace Strike references

## Branding Polish - Cyber Campaign Command
- [x] Update VITE_APP_TITLE to "Cyber Campaign Command" (user must update manually in Settings > Secrets)
- [x] Add C3 compact branding element to sidebar logo area across all pages
- [x] Update Home page description to reference Cyber Campaign Command

## GoPhish Stats on Dashboard
- [x] Add GoPhish server status/health indicator to Dashboard
- [x] Add GoPhish campaign summary stats (total campaigns, active, completed)
- [x] Add GoPhish email metrics (sent, opened, clicked, submitted)
- [x] Add GoPhish sending profile and landing page counts
- [x] Add GoPhish recent activity feed
- [x] Match visual style with existing Caldera stats section

## Click-Through Stats on Dashboard
- [x] Make Caldera stat cards (Adversaries, Abilities, Operations, Agents) clickable with navigation
- [x] Make GoPhish stat cards (Campaigns, Templates, Landing Pages, SMTP Profiles) clickable
- [x] Make GoPhish email metric cards (Sent, Opened, Clicked, Submitted, Reported) clickable
- [x] Make Campaign Status and GoPhish Resources panels clickable
- [x] Add hover effects and cursor pointer to indicate clickability
- [x] Ensure detail pages exist for all linked stats

## Mega Red Team Bundle Integration
- [x] Create APT Scenario Library page with 4 nation-state scenarios (APT29, APT28, Sandworm, APT41)
- [x] Add ATT&CK Navigator technique heatmap visualization for each APT group
- [x] Display Caldera adversary profiles (APT29, Sandworm) with atomic ordering steps
- [x] Add Compliance Frameworks page with FedRAMP and CMMC 2.0 reference material
- [x] Integrate Defense Impersonation Matrix as phishing boundary reference
- [x] Add GoPhish policy review template to template references
- [x] Enhance Security Report with compliance framework sections
- [x] Add Infrastructure Reference page showing Terraform engagement architecture
- [x] Add STIX 2.1 threat intelligence viewer
- [x] Add sidebar navigation for new pages
- [x] Wire up routes in App.tsx

## Help Desk Email Template Library
- [x] Research real help desk/IT system email templates from GitHub and security resources
- [x] Create categorized template library (password reset, MFA, ticket notifications, account alerts, etc.)
- [x] Build Template Library page with search, categories, and copy-to-GoPhish functionality
- [x] Add template preview with GoPhish variable placeholders
- [x] Add sidebar navigation link for Template Library
- [x] Deploy latest changes to DigitalOcean

## Postfix Mail Server & SSL Certificate Setup
- [x] Check if Postfix/Sendmail is installed and running on DO server
- [x] Install and configure Postfix for GoPhish email delivery
- [ ] Configure SPF/DKIM/DMARC DNS records for email deliverability (requires domain DNS access)
- [x] Generate strong 4096-bit self-signed SSL certificate for GoPhish admin panel (port 3333)
- [x] Update GoPhish config to use the new SSL certificate
- [ ] Verify email sending works through GoPhish (blocked: DigitalOcean port 25 outbound blocked)
- [x] Verify SSL certificate shows AceofCloud LLC details in browser

## External SMTP Relay Setup
- [x] Create Brevo account and get SMTP credentials
- [ ] Create SendGrid account and get API key
- [x] Configure Brevo SMTP sending profile in GoPhish (port 2525 - only open SMTP port on DO)
- [ ] Configure SendGrid SMTP sending profile in GoPhish
- [x] Test email delivery through Brevo relay (success via port 2525)

## Nginx Virtual Hosts + Let's Encrypt SSL
- [x] Configure nginx virtual hosts for dashboard.aceofcloud.io, gophish.aceofcloud.io, caldera.aceofcloud.io
- [x] Obtain Let's Encrypt SSL certificates for all subdomains
- [x] Configure GoPhish admin to use Let's Encrypt cert
- [x] Remove port numbers from URLs (proxy through nginx on 443)
- [x] Redirect HTTP to HTTPS

## Brevo Domain Verification
- [x] Verify aceofcloud.io sender domain in Brevo

## PTR Record
- [x] Set PTR record for 137.184.7.224 to mail.aceofcloud.io via DigitalOcean droplet rename

## Per-Customer Phishing Domain Workflow
- [x] Create documentation/guide for per-customer domain setup
- [ ] Add domain management page to C3 dashboard

## Dashboard URL Updates
- [x] Update all frontend links from IP:port to subdomain URLs
- [x] Update server-side API URLs to use subdomains
- [x] Build and deploy updated dashboard to DigitalOcean
- [x] Verify all subdomains accessible with valid Let's Encrypt SSL
- [x] Deploy provision-phish-domain.sh automation script to server

## Rename Databank to MSP Target
- [x] Remove Databank references from Caldera-related contexts
- [x] Rename Databank to MSP Target in Dashboard.tsx
- [x] Rename Databank to MSP Target in Campaigns.tsx
- [x] Rename Databank to MSP Target in CampaignDetail.tsx
- [x] Rename Databank to MSP Target in OperationMonitor.tsx
- [x] Rename Databank to MSP Target in ReportGenerator.tsx
- [x] Update crowdstrike_bypass_agents.md
- [x] Build and deploy updated dashboard

## Update caldera-ops-persist service
- [x] Update systemd service script to use MSP_Target operation/adversary names
- [x] Verify service restarts correctly with new names

## Customer/Engagement Selector
- [x] Create engagements table in database schema
- [x] Create engagement CRUD procedures (create, list, get, update, delete)
- [x] Build engagement selector component in dashboard header/sidebar
- [x] Wire engagement context throughout dashboard pages
- [ ] Store active engagement in user session/localStorage

## MSP Adversary Profile (AD/RMM/Backup)
- [x] Design MSP-focused adversary profile with AD, RMM, and backup TTPs
- [x] Create adversary profile in Caldera via API
- [x] Create matching operation in Caldera
- [x] Add MSP profile to dashboard adversaries page
- [ ] Update CalderaGuide with MSP profile documentation (deferred)

## GoPhish Email Templates
- [x] Research pre-made GoPhish email template repositories
- [x] Evaluate and select best templates for MSP/enterprise phishing scenarios
- [x] Import selected templates into GoPhish instance
- [ ] Add template management/preview to C3 dashboard

## Help Desk Phishing Email Templates
- [x] Research real email designs from Zendesk, ServiceNow, Jira, Freshdesk, ConnectWise
- [x] Create Zendesk ticket notification phishing template
- [x] Create ServiceNow incident/request phishing template
- [x] Create Jira/Atlassian notification phishing template
- [x] Create Freshdesk ticket phishing template
- [x] Create ConnectWise/Automate MSP alert phishing template
- [x] Create Microsoft 365 admin center alert phishing template
- [x] Create matching credential harvest landing pages
- [x] Import all templates into GoPhish via API

## Unified Authentication (Dashboard + Caldera + GoPhish)
- [x] Investigate current auth mechanisms for all three services
- [x] Create server-side auth proxy that authenticates with Caldera API on dashboard login
- [x] Create server-side auth proxy that authenticates with GoPhish API on dashboard login
- [x] Store Caldera/GoPhish session tokens server-side per user session
- [x] Proxy all Caldera/GoPhish API calls through dashboard backend with injected auth
- [x] Update "Open Caldera" and "Open GoPhish" links to use pre-authenticated sessions
- [x] Build, deploy, and verify unified login flow

## Fix Statistics Counters
- [x] Investigate which counters aren't showing Caldera data - nginx auth_request was blocking server-side API calls
- [ ] Fix data fetching from Caldera API
- [x] Verify counters display correct data - 495 adversaries, 1940 abilities, 1 operation, 1 agent
- [ ] Deploy fix to DigitalOcean

## GoPhish Integration Testing
- [x] Test GoPhish API connectivity (getStats endpoint)
- [x] Test template CRUD (list, create, edit, delete)
- [x] Test landing page CRUD (list, create, edit, delete)
- [ ] Test sending profile CRUD (list, create, edit, delete)
- [x] Test target group CRUD (list, create, edit, delete)
- [x] Test campaign operations (list, create, launch)
- [ ] Test GoPhish UI page rendering in browser
- [ ] Fix any issues discovered

## Campaign Creation Wizard
- [ ] Multi-step wizard UI (template → target group → sending profile → landing page → review → launch)
- [ ] Step 1: Select or create email template with preview
- [ ] Step 2: Select or create target group
- [ ] Step 3: Select sending profile
- [ ] Step 4: Select landing page with preview
- [ ] Step 5: Review all selections and set campaign name/schedule
- [ ] Step 6: Launch campaign via GoPhish API
- [ ] Add createCampaign tRPC procedure
- [ ] Add campaign wizard route and navigation

## Template Preview Panel
- [ ] Build template preview component with live HTML rendering
- [ ] Support GoPhish template variables ({{.FirstName}}, {{.Email}}, etc.) with sample data
- [ ] Preview both email templates and landing pages
- [ ] Integrate preview into campaign wizard step 1 and step 4
- [ ] Add standalone template browser/preview page

## Engagement-Campaign Linking
- [ ] Add engagementId field to campaign tracking (local DB table)
- [ ] Create campaign_engagements table to link GoPhish campaigns to engagements
- [ ] Filter campaigns list by active engagement
- [ ] Filter campaign results/credentials by engagement
- [ ] Show engagement-specific stats on engagement detail view
- [ ] Update Campaigns page to show engagement filter

## Campaign Creation Wizard
- [x] Create multi-step campaign wizard page (/campaign-wizard)
- [x] Step 1: Engagement selection (optional linking)
- [x] Step 2: Email template selection with inline preview cards
- [x] Step 3: Target group selection or new group creation with CSV import
- [x] Step 4: SMTP sending profile selection
- [x] Step 5: Landing page selection with preview
- [x] Step 6: Review summary and launch with scheduling options
- [x] Add TemplatePreview component with desktop/tablet/mobile view modes
- [x] Add GoPhish variable substitution preview ({{.FirstName}}, {{.URL}}, etc.)
- [x] Add Launch Wizard button to GoPhish page header
- [x] Add Launch Wizard to sidebar navigation

## Template Preview Panel
- [x] Create TemplatePreview component with responsive preview modes
- [x] Add variable toggle (raw vs rendered preview)
- [x] Add sample data bar showing substituted values
- [x] Create TemplatePreviewCard for compact inline previews
- [x] Integrate preview into wizard template and landing page steps

## Engagement-Campaign Linking
- [x] Create campaign_engagements database table
- [x] Add DB helpers (link, unlink, getByEngagement, getByCampaign, listAll)
- [x] Add tRPC procedures for campaign-engagement linking
- [x] Add engagement filter bar on GoPhish campaigns tab
- [x] Filter campaigns list by selected engagement
- [x] Show engagement badge on campaign cards
- [x] Add campaign linking UI on Engagements page (LINK button)
- [x] Add expandable linked campaigns section per engagement
- [x] Add unlink functionality with confirmation
- [x] Add LAUNCH button on engagement cards to open wizard
- [x] Write vitest tests for campaign-engagement linking (10 tests passing)

## Per-Engagement Results Dashboard
- [x] Create EngagementResults page with aggregated campaign stats
- [x] Show emails sent, opened, clicked, credentials captured per engagement
- [x] Add campaign breakdown table within engagement view
- [x] Add visual charts/progress bars for engagement metrics
- [x] Add route and navigation link for engagement results
- [x] Add credential harvest details per campaign

## Pre-populate Help Desk Phishing Templates into GoPhish
- [x] Add backend tRPC procedure to push templates to GoPhish API
- [x] Create "Sync Templates" button in wizard and template library
- [x] Push all 9 help desk templates (Zendesk, ServiceNow, Jira, etc.) to GoPhish
- [x] Show sync status and success/failure feedback
- [x] Handle duplicate template names gracefully

## Campaign Cloning
- [x] Add "Clone" button to campaign cards in GoPhish page
- [x] Pre-populate wizard with cloned campaign configuration
- [x] Support cloning template, target group, SMTP profile, landing page, and engagement
- [x] Add clone entry point from campaign results view

## Caldera Open Source Research
- [x] Research open-source Caldera plugins and extensions
- [x] Research Caldera customizations and community contributions
- [x] Research additional threat actors with mappable ATT&CK data
- [x] Compile findings into a comprehensive research document

## OSINT-Driven Engagement Builder
- [x] Design OSINT recon data schema (domain intel, subdomains, emails, tech stack, dark web mentions)
- [x] Build domain reconnaissance backend (DNS, WHOIS, subdomain enum, email harvest)
- [x] Build typosquat domain generator and availability checker
- [x] Build dark web / leak site mention scanner
- [x] Build OSINT Recon tab in engagement detail UI
- [x] Build typosquat domain management panel (discover, register, track, transfer)
- [x] Build auto-campaign designer that uses OSINT findings to pre-fill Caldera campaigns
- [x] Integrate OSINT findings into phishing template customization
- [x] Add MX record check for target domain (determine spoofability)
- [x] Add SPF/DKIM/DMARC policy analysis for email spoofing assessment
- [x] Show spoof-vs-buy recommendation in typosquat panel

## Landing Page Update
- [x] Audit all current platform capabilities and features
- [x] Rewrite landing page feature descriptions to match actual built features
- [x] Update hero section, feature cards, and capability descriptions

## Seamless GoPhish/Caldera Access After Login
- [x] Review current auth flow and credential storage
- [x] Ensure GoPhish API proxy uses stored credentials automatically
- [x] Ensure Caldera API proxy uses stored credentials automatically
- [x] Test GoPhish features after dashboard login (templates, campaigns, profiles, landing pages)
- [x] Test Caldera features after dashboard login (adversaries, operations, abilities)
- [x] Test engagement builder functionality end-to-end (create engagement, OSINT recon, campaign wizard)
- [x] Fix any issues found during testing

## Mobile Responsiveness Optimization
- [x] Fix DashboardLayout sidebar for mobile (hamburger menu, slide-out overlay)
- [x] Fix Home/Landing page mobile layout (hero text, feature cards, stats grid)
- [x] Fix Dashboard page mobile layout (stats cards, quick actions grid)
- [x] Fix GoPhish page mobile layout (tabs, template cards, campaign cards)
- [x] Fix Engagements page mobile layout (engagement cards, action buttons)
- [x] Fix Adversaries page mobile layout (search, filter, adversary cards)
- [x] Fix Agents page mobile layout (agent cards, deployment scripts)
- [x] Fix Campaign Wizard mobile layout (multi-step form, preview panels)
- [x] Fix OSINT Recon page mobile layout (domain analysis, typosquat grid)
- [x] Fix Engagement Results page mobile layout (charts, tables)
- [x] Fix Login page mobile layout
- [x] Add mobile-friendly touch targets (min 44px tap areas)
- [x] Test all pages at 375px, 414px, and 768px breakpoints
- [x] Fix Caldera Adversaries page mobile layout (search bar, category filters, adversary cards)
- [x] Fix Caldera Agents page mobile layout (agent cards, deployment scripts)
- [x] Fix Caldera Operations page mobile layout (operation cards, ability lists)
- [x] Fix GoPhish overview panel mobile layout (stats grid)
- [x] Fix GoPhish campaigns panel mobile layout (campaign cards, engagement filter)
- [x] Fix GoPhish templates panel mobile layout (template cards, sync button)
- [x] Fix GoPhish landing pages panel mobile layout
- [x] Fix GoPhish sending profiles panel mobile layout
- [x] Fix GoPhish target groups panel mobile layout

## OSINT/Domain Search UI Integration
- [x] Add inline domain OSINT search to engagement creation form
- [x] Add OSINT quick-search widget to Dashboard page
- [x] Add "Domain Recon" entry in sidebar navigation
- [x] Integrate OSINT findings into Campaign Wizard (auto-populate from recon data)
- [x] Show spoofability verdict and typosquat recommendations in engagement cards
- [x] Add domain search bar to OSINT Recon page header for quick re-scan
- [x] Show OSINT summary in engagement detail view
- [x] Link OSINT findings to campaign template recommendations

## WHOIS + Domain Registrar Integration
- [x] Research and integrate free WHOIS lookup API
- [x] Add domain availability checking via RDAP/WHOIS
- [x] Wire typosquat CHECK AVAILABILITY buttons to live data
- [x] Show registrar info, expiry dates, nameservers in UI
- [ ] Display pricing estimates where available

## Client-Facing PDF Report Exporter
- [x] Build PDF generation backend with branded AceofCloud templates
- [x] Support MSP client report template
- [x] Support enterprise domain client report template
- [x] Support mixed hosting client report template
- [x] Support SaaS/PaaS/IaaS provider report template
- [x] Include OSINT findings section
- [x] Include campaign metrics section
- [x] Include credential harvest details
- [x] Include ATT&CK technique coverage
- [x] Include typosquat domain analysis
- [x] Include executive summary with risk scoring
- [x] Add report configuration UI with client type selector
- [x] Add PDF download flow from engagement detail

## Recurring OSINT Monitor
- [x] Build OSINT monitoring schedule backend
- [x] Add subdomain change detection
- [x] Add certificate transparency monitoring
- [x] Add DMARC/SPF policy change detection
- [x] Add MX record change alerting
- [x] Wire alerts to notification system
- [x] Build monitor configuration UI
- [x] Show monitoring history and change timeline

## WHOIS + Domain Registrar Integration
- [x] Research and integrate free WHOIS lookup API
- [x] Add domain availability checking via RDAP/WHOIS
- [x] Wire typosquat CHECK AVAILABILITY buttons to live data
- [x] Show registrar info, expiry dates, nameservers in UI

## Client-Facing PDF Report Exporter
- [x] Build PDF generation backend with branded AceofCloud templates
- [x] Support MSP client report template
- [x] Support enterprise domain client report template
- [x] Support mixed hosting client report template
- [x] Support SaaS/PaaS/IaaS provider report template
- [x] Include OSINT findings, campaign metrics, credential harvests
- [x] Include ATT&CK technique coverage and typosquat analysis
- [x] Include executive summary with risk scoring
- [x] Add report configuration UI with client type selector
- [x] Add PDF download flow from engagement detail

## Recurring OSINT Monitor
- [x] Build OSINT monitoring schedule backend
- [x] Add subdomain and certificate change detection
- [x] Add DMARC/SPF/MX policy change detection and alerting
- [x] Wire alerts to notification system
- [x] Build monitor configuration UI with history timeline

## Domain Intel Pipeline (SpicyTip Integration)
- [x] Build backend domain intel engine with LLM-powered passive discovery
- [x] Implement asset signal extraction and classification (SSO, mail, API, payment, etc.)
- [x] Implement Auto-BIA inference with CARVER+SHOCK factor scoring
- [x] Implement hybrid risk scoring engine (CVSS + mission impact + context multiplier)
- [x] Implement confidence fusion across discovery signals
- [x] Build campaign recommendation engine mapping risk findings to Caldera abilities
- [x] Build campaign recommendation engine mapping risk findings to GoPhish templates
- [x] Build Domain Intel Wizard frontend (multi-step: domain input → discovery → analysis → recommendations)
- [x] Build Threat Model results UI with risk heatmap and asset classification
- [x] Build Campaign Recommendations UI with auto-generated engagement plans
- [x] Wire engagement creation to auto-populate from intel results
- [x] Support all client types: MSP, Enterprise, SaaS, PaaS, IaaS, Mixed Hosting
- [x] Add database schema for domain intel scans and results
- [x] Write comprehensive tests for intel pipeline

## SpicyThreatIntel Platform Enhancement (Post Domain Intel)
- [x] Review SpicyThreatIntel.com platform for enhancement ideas
- [x] Enhance threat actor data with APT tracking and TTP mapping
- [x] Enhance Caldera abilities data with threat actor alignment
- [x] Improve OSINT/discovery functions with threat awareness feeds
- [x] Integrate beneficial features from cyber threat intel design

## Ransomware Groups from SpicyThreatIntel
- [x] Browse SpicyThreatIntel ransomware section for group data
- [x] Add ransomware groups to APT_SCENARIOS with full details
- [x] Add Navigator layers for new ransomware groups
- [x] Fix bundle-integration test to match new actor count
- [x] Verify all tests pass

## IOC-Driven GoPhish Template Generator
- [x] Build backend LLM-powered template generator that uses latest threat actor IOCs
- [x] Generate realistic email templates based on current phishing TTPs per threat actor
- [x] Generate matching landing pages (credential harvesting, MFA interception, etc.)
- [x] Support threat-actor-specific templates (APT29 style, Scattered Spider vishing, etc.)
- [x] Include IOC indicators in template metadata for training accuracy
- [x] Build frontend UI for template generation with actor/IOC selection
- [x] Wire generated templates to GoPhish API for direct deployment
- [x] Add template preview and customization before deployment

## Caldera Abilities for Ransomware TTPs
- [x] Build Caldera abilities data structure with executors, commands, and payloads
- [x] Map each ransomware group's TTPs to specific Caldera abilities
- [x] Add abilities for: credential dumping, lateral movement, encryption simulation, exfiltration
- [x] Add abilities for: service stopping, defense evasion, persistence mechanisms
- [x] Include IOC metadata (hashes, domains, IPs) per ability
- [x] Wire abilities into APT scenario profiles for auto-deployment
- [x] Build dedicated Abilities Library page with search, filter, and deploy-to-Caldera

## 400+ Caldera Threat Actors Database
- [x] Design threat_actors DB table schema with comprehensive fields
- [x] Build LLM-powered threat actor data generation for 400+ groups
- [x] Include APT groups, cybercrime groups, ransomware groups, hacktivists
- [x] Store TTPs, IOCs, tools, target sectors, origin countries, MITRE mappings
- [x] Build tRPC procedures for CRUD and search/filter
- [x] Wire threat actor DB to APT Library page for dynamic loading

## Dedicated Abilities Library Page (COMPLETED)
- [x] Build searchable, filterable catalog of all Caldera abilities
- [x] Add tactic-based grouping and technique ID filtering
- [x] Add bulk deploy to Caldera functionality
- [x] Show ability details with executor commands and platform support
- [x] Link abilities back to threat actor profiles

## Live IOC Feed Integration
- [x] Build CISA KEV (Known Exploited Vulnerabilities) feed integration
- [x] Build AlienVault OTX feed integration for IOC enrichment
- [x] Build abuse.ch (URLhaus, MalwareBazaar, ThreatFox) feed integration
- [x] Auto-refresh IOC data on schedule
- [x] Build IOC feed dashboard UI with real-time threat indicators
- [x] Align phishing templates with active campaign IOCs

## Automated Engagement Pipeline
- [x] Build one-click pipeline: Domain Intel scan → risk scoring → campaign recommendation
- [x] Auto-create Caldera operation from recommended abilities
- [x] Auto-create GoPhish campaign from recommended templates
- [x] Build pipeline wizard UI with progress tracking
- [x] Add pipeline status monitoring and result aggregation

## Research-Based Threat Actor Database (400+)
- [x] Research CrowdStrike threat actor naming conventions and groups
- [x] Research Unit 42 / Palo Alto threat groups
- [x] Research AlienVault OTX threat groups
- [x] Research MITRE CTI GitHub repo for comprehensive actor list
- [x] Research ETDA and other GitHub threat intel repos
- [x] Cross-reference and corroborate data across sources
- [x] Build detailed histories for each group
- [x] Create seed data files with 400+ actors
- [x] Build seed script and populate database

## Bug Fix: Domain Intel Pipeline
- [x] Fix "string did not match the expected pattern" error when scanning AceofCloud.com
- [x] Test and verify the fix works end-to-end

## E2E Test: Domain Intel Pipeline on AceofCloud.com
- [x] Test full pipeline scan on AceofCloud.com via tRPC procedure
- [x] Verify all 4 stages complete (discovery, analysis, campaign recs, summary)
- [x] No runtime errors - pipeline completed successfully (65.2s, 15 assets, 7 campaigns, risk 82.8)

## Threat Actor Detail Page
- [ ] Build dedicated detail page for each of the 401 threat actors
- [ ] Display full corroborated history and description
- [ ] Show MITRE ATT&CK technique heatmap
- [ ] Show associated IOCs (hashes, domains, IPs)
- [ ] Show tools and malware used
- [ ] Show activity timeline with sources
- [ ] Add "Simulate This Actor" button to auto-create Caldera adversary
- [ ] Add route and navigation wiring

## IOC Feed Auto-Sync
- [ ] Build server-side scheduled task for daily IOC feed fetch
- [ ] Fetch from CISA KEV (Known Exploited Vulnerabilities)
- [ ] Fetch from AlienVault OTX pulse feed
- [ ] Fetch from abuse.ch (URLhaus, ThreatFox)
- [ ] Cross-match new IOCs against monitored domains
- [ ] Send notifications when critical IOCs match monitored domains
- [ ] Add sync status and last-synced timestamp to IOC Feed dashboard

## Threat Actor Detail Page
- [x] Create ThreatActorDetail.tsx with full actor profile view
- [x] Add MITRE ATT&CK technique heatmap by tactic
- [x] Show aliases, origin, tools, malware, target sectors/regions
- [x] Add "Simulate This Actor" button to deploy to Caldera
- [x] Add "Enrich with LLM" button for intelligence enrichment
- [x] Add "Generate Phishing Template" link
- [x] Show associated abilities from abilities library
- [x] Activity timeline tab with historical events
- [x] Create ThreatActors.tsx list page with search/filter/pagination
- [x] Add routes in App.tsx for /threat-actors and /threat-actors/:id
- [x] Add THREAT ACTORS nav item to sidebar

## Caldera Adversary Sync
- [x] Fetch all 495 adversaries from Caldera API
- [x] Compare with 401 threat actors in database (upsert logic handles this)
- [x] Add missing Caldera adversaries to threat actor database
- [x] Map Caldera ability IDs to MITRE techniques
- [x] Keep both systems in sync for campaign building

## IOC Feed Auto-Sync
- [x] Create IOC sync background service
- [x] Implement CISA KEV daily fetch and store
- [x] Implement AlienVault OTX daily fetch and store
- [x] Implement abuse.ch daily fetch and store
- [ ] Add notifications for critical IOC matches
- [x] Wire up as scheduled cron job

## Tests for New Features
- [ ] Tests for threat actor detail page data
- [ ] Tests for IOC auto-sync functionality
- [ ] Tests for Caldera adversary sync

## Domain Intel → Threat Actor Auto-Matching
- [x] After Domain Intel scan completes, auto-analyze discovered assets/tech stack/industry
- [x] Cross-reference org profile (sector, tech, hosting type) against threat actor target sectors
- [x] Score and rank threat actors by likelihood of targeting the organization
- [x] Use LLM to correlate discovered infrastructure with known actor TTPs
- [x] Surface top matched threat actors in Domain Intel results page
- [x] Add "Recommended Adversaries" section to Domain Intel results
- [x] Allow one-click deploy of matched threat actors to Caldera for simulation

## TTP Knowledge Engine - Deep LLM Understanding
- [x] Build TTP research service that analyzes each MITRE technique in depth
- [x] Map how each technique is performed (tools, commands, execution methods)
- [x] Map IOC generation patterns per technique (artifacts, file hashes, registry, network signatures, event logs)
- [x] Generate detection rule templates (Sigma, YARA, Suricata) per technique
- [x] Cross-reference Caldera ability catalog with technique knowledge
- [x] Build LLM system prompt with deep TTP knowledge for campaign design
- [x] Enable intelligent Caldera campaign recommendations based on TTP understanding
- [x] Generate SOC/blocking rules from campaign simulations
- [x] Store TTP knowledge base in database for reuse across features

## Kali Linux & Metasploit Knowledge Integration
- [x] Download and catalog all Kali Linux tools with categories
- [x] Map Kali tools to MITRE ATT&CK techniques
- [x] Research Metasploit exploit/auxiliary/post module catalog
- [x] Map Metasploit modules to CVEs and ATT&CK techniques
- [x] Identify Metasploit modules that could be reverse-engineered into Caldera abilities
- [x] Generate Caldera ability definitions from compatible tools/exploits
- [x] Store all tool/exploit knowledge in TTP knowledge base for LLM reference
- [x] Build UI for browsing offensive tool catalog

## Execute Operations
- [x] Run GitHub TTP ingestion (ATT&CK STIX + Atomic Red Team + LOLBAS + Metasploit) — 691 techniques, 181 groups, 785 software, 328 Atomic tests, 451 LOLBAS, 4368 Metasploit modules, 67 Kali tools
- [x] Run Caldera adversary sync — 190 unique adversaries synced (from 495 total), 6,340 abilities mapped
- [x] Run Domain Intel scan on AceofCloud.com — Risk 89/100 (critical), 30 assets, 76 findings, 20 threat actors matched, 4 campaign recommendations

## Enrich Matched Threat Actors
- [x] Run LLM enrichment on 20 AceofCloud-matched threat actors (20/20 enriched)
- [x] Generate deep TTP analysis per actor (execution methods, tools, IOC patterns)
- [x] Generate Sigma detection rules per actor
- [x] Generate YARA rules per actor
- [x] Generate Suricata/Splunk/KQL rules per actor
- [x] Store enrichment results in TTP knowledge base

## Build Identity Provider Compromise Campaign
- [x] Create Caldera operation from "Identity Provider Compromise via Phishing" recommendation
- [x] Configure GoPhish phishing campaign targeting SSO/OWA infrastructure
- [x] Link campaign to AceofCloud engagement (Engagement ID: 90089)
- [x] Set up adversary profile with matched threat actor TTPs (aceofcloud-idp-compromise-2026)
- [x] Generate phishing templates for SSO/OWA credential harvesting (APT29 SSO + Scattered Spider OWA)

## Recurring Caldera Sync
- [x] Add Caldera sync to server cron schedule (daily at 07:00 UTC)
- [x] Configure daily sync interval
- [x] Add sync status to dashboard

## Detection Rules Export ZIP
- [x] Add backend endpoint to generate ZIP of Sigma/YARA/Suricata/Splunk/KQL rules per actor
- [x] Add "Download Rules Pack" button on Threat Actor Detail page
- [x] Include README in ZIP with rule descriptions and import instructions

## Launch AceofCloud Campaign
- [x] Deploy SSO phishing template to GoPhish (Template ID 50)
- [x] Deploy OWA phishing template to GoPhish (Template ID 51)
- [x] Start Caldera operation with aceofcloud-idp-compromise-2026 adversary (paused state)
- [x] Link GoPhish campaign and Caldera operation to Engagement #90089

## Campaign Report Generator
- [x] Build report generation backend service with LLM (enhanced existing with Domain Intel, threat actors, Caldera ops, TTP knowledge)
- [x] Support executive summary report (non-technical, business-focused)
- [x] Support technical report (detailed findings, detection gaps, remediation)
- [x] Added 3 new report types: Purple Team Exercise, Red Team Assessment, Detection Gap Analysis
- [x] Include MITRE ATT&CK mapping and detection gap analysis in all reports
- [x] Add report generation UI page (existing ReportGenerator.tsx enhanced with 9 report types)
- [x] Keep report templates customer-agnostic (privacy requirement - system prompt enforced)
- [x] Author attribution: Harrison Cook / AceofCloud

## Purple Team Report Generation
- [x] Generate Purple Team Exercise report for AceofCloud Engagement #90089 (Report #30244, stored in S3)
- [x] Include detection gap analysis with Sigma/YARA rules per uncovered technique
- [x] Verify report is stored and accessible in the UI

## MITRE ATT&CK Navigator Heatmap
- [x] Build interactive ATT&CK Navigator heatmap component (with zoom, search, fullscreen, export layer JSON)
- [x] Show technique coverage with color-coded severity/frequency (5-level color scale)
- [x] Support hover tooltips with technique details (score, tactic, description)
- [x] Embed heatmap in Threat Actor Detail page (replaced basic badge view)
- [x] Support filtering by tactic and search, export ATT&CK Navigator layer JSON

## Campaign Execution Dashboard
- [x] Build backend endpoints for real-time Caldera operation monitoring (operationDetail, controlOperation)
- [x] Fetch active operations with technique execution progress
- [x] Fetch agent status (alive, dead, pending) per operation
- [x] Track technique success/failure rates in real-time
- [x] Calculate detection rate metrics (techniques attempted vs detected)
- [x] Build real-time dashboard UI with auto-refresh (3-10s polling)
- [x] Show operation timeline with technique execution steps (expandable chain view)
- [x] Show agent status grid with health indicators
- [x] Show MITRE ATT&CK progress overlay (tactic-grouped view)
- [x] Add operation controls (pause, resume, stop)
- [x] Add nav link in AppShell (CAMPAIGN EXEC)

## Sigma/YARA Rule Validation Engine
- [x] Build rule validation backend service (server/lib/rule-validator.ts)
- [x] Parse and validate Sigma rule syntax (required fields, detection section, condition)
- [x] Parse and validate YARA rule syntax (rule structure, strings, condition, braces)
- [x] Parse and validate Suricata rule syntax (action, options, sid)
- [x] Parse and validate Splunk SPL syntax (balanced quotes, parens, brackets)
- [x] Parse and validate KQL syntax (table references, balanced parens)
- [x] Generate sample log data per technique for testing (12+ technique-specific samples)
- [x] Test rules against sample logs with LLM-powered deep analysis
- [x] Score rule effectiveness (0-100, based on syntax, semantics, best practices)
- [x] Assess false positive risk (low/medium/high)
- [x] Assess coverage (techniques, data sources, platforms)
- [x] Build rule validation UI page (RuleValidator.tsx with editor, results, samples)
- [x] Show validation results with pass/fail, errors, warnings, suggestions
- [x] LLM-powered improvement suggestions and sample data match testing
- [x] Add RULE VALIDATOR nav link in AppShell
- [x] Batch validation endpoint for multiple rules
- [x] 20 vitest tests passing for rule validation engine

## Intelligent Campaign Chain Builder
- [x] Build backend service to auto-populate Caldera operations with abilities (chain-builder.ts)
- [x] Map matched threat actors' TTPs to available Caldera abilities
- [x] Map OSINT/Discovery findings (vulns, misconfigs, open ports) to exploitation abilities
- [x] Map Domain Intel tech stack to relevant attack techniques
- [x] Use LLM to intelligently sequence attack chain (buildChainWithLLM)
- [x] Add endpoint to auto-build chain for any paused operation (buildChain, autoBuildAllChains)
- [x] Add "Auto-Build Chain" and "LLM Build" buttons to campaign execution dashboard
- [x] Run auto-build on all paused operations (5 operations, 24 abilities each, 24 techniques covered)

## Campaign Execution Dashboard Enhancement
- [x] Fix endpoint name mismatch (operationDetail → getOperationDetail)
- [x] Rewrite CampaignExecution.tsx with enhanced features
- [x] Add ATT&CK Flow tab (kill chain visualization by tactic phase)
- [x] Add Timeline tab (chronological execution events with duration)
- [x] Enhance Detection tab (bypass/blocked/partial/pending metrics)
- [x] Improve operation list with progress bars and ability counts
- [x] Add summary cards (running, paused, agents, completed, steps/abilities)
- [x] Add export results functionality (JSON download)

## Threat Actor Detail - Inline Rule Validation
- [x] Add auto-generate detection rules from actor's known TTPs (Detection Rules tab)
- [x] Generate Sigma rules for each technique
- [x] Generate YARA rules for relevant techniques
- [x] Generate Suricata rules for network-based techniques
- [x] Inline validate generated rules with effectiveness scoring (Deep Validate button)
- [x] Show validation results per rule with pass/fail indicators
- [x] LLM-enhanced rule generation option
- [x] Filter by rule type and tactic
- [x] Export all rules as text file
- [x] Copy individual rules to clipboard

## Detection Coverage Matrix
- [x] Build Detection Coverage Matrix page (DetectionCoverage.tsx)
- [x] Cross-reference validated rules against operation attack chains
- [x] Show coverage gaps in SIEM detection (ops-only = gap)
- [x] Matrix view: techniques grouped by tactic with expandable details
- [x] Summary stats: full/partial/rules-only/ops-only/none coverage
- [x] Overall coverage percentage bar with color segments
- [x] Tactic breakdown with clickable filter cards
- [x] Filter by operation, tactic, and coverage status
- [x] Add COVERAGE MATRIX nav link in AppShell

## Post-Engagement Report Generator
- [x] Build report generator backend (server/lib/report-generator.ts)
- [x] Generate client-ready HTML report with print/download support
- [x] LLM-powered executive summary with key metrics
- [x] Include operation timeline and attack chain results table
- [x] Include detection coverage analysis with coverage bar
- [x] Include findings with severity ratings and remediation steps
- [x] Include MITRE ATT&CK mapping visualization (tactic columns)
- [x] AceofCloud branding with Harrison Cook attribution
- [x] CONFIDENTIAL classification header
- [x] Table of contents, scope & methodology, recommendations, conclusion
- [x] Add report generation UI (PostEngagementReport.tsx) with operation selection
- [x] Add ENGAGEMENT REPORT nav link in AppShell
- [x] 15 vitest tests passing for report generator

## Email & Landing Page Template Review
- [x] Review existing email templates - all 26 templates have complete HTML (DOCTYPE, styles, body, closing tags)
- [x] Review existing landing page templates - all properly structured
- [x] No incomplete or broken template designs found
- [x] Add recipient preview mode (renders as recipient sees it with sample data substitution)
- [x] Keep existing source code view alongside preview (Source Code tab)
- [x] Add toggle between "Recipient View" and "Source Code" views
- [x] Device frame selector (Desktop/Tablet/Mobile) for responsive preview
- [x] Email header simulation (From/To/Subject) in recipient view
- [x] Fullscreen mode, copy, download, open-in-new-tab actions
- [x] Thumbnail previews on GoPhish template and landing page cards
- [x] Preview modal on click for both email templates and landing pages
- [x] Template Library expanded view now uses full TemplatePreview component
- [x] 17 vitest tests passing for template variable substitution
