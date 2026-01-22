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
