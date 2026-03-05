# Backend tRPC Public Procedure Audit

## CRITICAL — Should be protectedProcedure

### caldera-proxy.ts (ALL endpoints are public — exposes C2 server data)
- `getStats` — C2 server stats
- `getAdversaries` — All adversary profiles
- `getAdversary` — Single adversary detail
- `getAbilities` — All attack abilities
- `getAbilitiesByTactic` — Abilities by tactic
- `getTactics` — All tactics
- `getOperations` — All operations
- `getAgents` — All agents
- `getAgent` — Single agent detail
- `getDeployCommands` — Agent deploy commands (CRITICAL)
- `checkHealth` — C2 health check
- `getOperationDetail` — Detailed operation with chain analysis
- `getOperationsSummary` — All operations summary

### gophish-proxy.ts
- `getStatus` — GoPhish server status
- `getStats` — GoPhish aggregated stats

### ioc-feed.ts
- `list` — IOC feed entries
- `stats` — IOC feed stats
- `syncHistory` — Sync history
- `lastSync` — Last sync info
- `syncStatus` — Sync status

### engagements-core.ts
- `listTemplates` — Engagement templates
- `getTemplate` — Single template

## ACCEPTABLE — Intentionally public

### auth-core.ts
- `me` — Returns current user (null if not logged in)
- `logout` — Clears session cookie
- `login` — Login endpoint
- `session` — Check session
- `calderaLogout` — Caldera logout

### account-auth.ts
- `emailLogin` — Login flow
- `acceptInvite` — Accept invite (token-gated)
- `mfaLoginVerify` — MFA during login
- `changePassword` — Uses session cookie internally
- `mfaSetup/mfaVerifyAndEnable/mfaDisable/mfaStatus/mySessions/mfaRegenerateBackupCodes` — All use session cookie internally

### client-portal.ts
- `accessReport` — Token-gated public access
- `signRoe` — Token-gated public access

### error-log.ts
- `logClientError` — Client error logging (low risk)

### platform-stats.ts
- `getHomepageStats` — Public homepage stats (limited fields)
- `recentThreatActors` — Public feed (limited fields)
- `publicActorDetail` — Public detail (limited fields)

### agent-manager.ts
- `heartbeat` — Agent heartbeat (agents auth via registration token)

### domain-intel-core.ts
- `getConnectorCatalog` — Connector catalog (metadata only)
