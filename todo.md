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
