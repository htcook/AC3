import type { FAQItem } from '@/components/FAQ';

export const calderaFAQItems: FAQItem[] = [
  // --- Agent Not Checking In ---
  {
    id: 'cal-agent-1',
    question: 'Agent deployed but not checking in to Caldera server',
    answer: `This is the most common Caldera issue. Work through these checks:

1. **Network connectivity**: Verify the target machine can reach the Caldera server:
   curl -k https://caldera.aceofcloud.io/api/v2/health
   If this fails, there's a network/firewall issue between the agent and server.

2. **Correct callback address**: The agent must be configured with the correct Caldera server IP and port. Check the deployment command:
   - Server: https://caldera.aceofcloud.io
   - The agent binary must have been compiled with this address

3. **Firewall rules**: Ensure port 8888 is open on the Caldera server:
   sudo ufw allow 8888/tcp
   Also check the target machine's outbound firewall rules.

4. **Agent process running**: On the target, verify the agent process is running:
   Windows: tasklist | findstr sandcat
   Linux: ps aux | grep sandcat

5. **Antivirus/EDR blocking**: The agent binary may be quarantined by security software. Check:
   - Windows Defender quarantine
   - CrowdStrike Falcon detections
   - Carbon Black alerts

6. **Agent type mismatch**: Ensure you deployed the correct agent for the target OS:
   - Windows: sandcat.go-windows (or .exe)
   - Linux: sandcat.go-linux
   - macOS: sandcat.go-darwin

7. **Check Caldera logs**: On the server, check for connection attempts:
   tail -f /opt/caldera/logs/caldera.log`,
    category: 'Agents',
    tags: ['agent', 'check-in', 'connectivity', 'deployment', 'sandcat'],
    severity: 'critical',
  },
  {
    id: 'cal-agent-2',
    question: 'Agent was checking in but suddenly stopped (went "dead")',
    answer: `An agent that stops checking in may have been killed or blocked:

1. **Check agent status in Caldera**: Go to Agents page. If the agent shows as "dead" (red), it hasn't checked in within the expected interval.

2. **Default check-in interval**: Agents check in every 60 seconds by default. If the agent misses 3 consecutive check-ins, it's marked as dead.

3. **Process killed**: The agent process may have been terminated:
   - By the user or admin
   - By antivirus/EDR software
   - By a system reboot

4. **Network change**: If the target machine changed networks (VPN, Wi-Fi switch), the agent may lose connectivity.

5. **Sleep/hibernate**: If the target machine went to sleep or hibernated, the agent will resume when the machine wakes up.

6. **Redeploy**: If the agent is truly dead, you'll need to redeploy. Use the Agent Deploy page in Cyber Campaign Command for deployment scripts.

7. **Trust level**: Check if the agent's trust level was changed to "untrusted" in Caldera. Untrusted agents are ignored.`,
    category: 'Agents',
    tags: ['dead agent', 'stopped', 'check-in', 'killed'],
    severity: 'high',
  },
  {
    id: 'cal-agent-3',
    question: 'How do I deploy an agent that bypasses CrowdStrike Falcon?',
    answer: `Deploying agents past EDR requires careful evasion techniques:

1. **Use the CrowdStrike Bypass scripts**: The Agent Deploy page in Cyber Campaign Command includes pre-built bypass scripts for PowerShell, Bash, and Python.

2. **AMSI bypass first**: Before downloading the agent, bypass AMSI (Antimalware Scan Interface):
   [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

3. **Obfuscate the download**: Use encoded commands and indirect downloads:
   - Base64 encode the download cradle
   - Use certutil, bitsadmin, or curl instead of Invoke-WebRequest
   - Download to a temp directory with a legitimate-looking filename

4. **In-memory execution**: Avoid writing the agent to disk. Use reflective loading or execute directly from memory.

5. **Process injection**: Inject the agent into a legitimate process (explorer.exe, svchost.exe) to avoid detection.

6. **Timing**: Deploy during business hours when there's more noise. Avoid deploying during quiet periods when anomalies are more visible.

7. **Test first**: Use the CrowdStrike_Bypass operation in Caldera to test which evasion techniques work in the target environment.`,
    category: 'Agents',
    tags: ['CrowdStrike', 'EDR', 'bypass', 'evasion', 'AMSI'],
    severity: 'high',
  },

  // --- Abilities Failing ---
  {
    id: 'cal-ability-1',
    question: 'Abilities are failing with "executor not found" error',
    answer: `The "executor not found" error means the agent doesn't support the required executor:

1. **Check executor type**: Each ability requires a specific executor (psh for PowerShell, sh for bash, cmd for Windows command prompt). The agent must support that executor.

2. **Sandcat executors**: The default Sandcat agent supports:
   - Windows: psh (PowerShell), cmd (Command Prompt)
   - Linux: sh (Bash)
   - macOS: sh (Bash)

3. **Platform mismatch**: If an ability requires "psh" (PowerShell) but the agent is on Linux, it will fail. Check the ability's platform requirements.

4. **Manx agent**: For more executor support, use the Manx agent which provides a reverse shell with broader command execution.

5. **Custom executors**: You can create custom executors in Caldera plugins. Check if the required plugin is enabled.

6. **Verify in operation**: When viewing an operation, abilities that can't run on the current agent platform will show as "skipped" or "failed".

7. **Filter by platform**: In the Cyber Campaign Command dashboard, use the tactic/platform filters to find abilities compatible with your target OS.`,
    category: 'Abilities',
    tags: ['executor', 'not found', 'PowerShell', 'bash', 'platform'],
    severity: 'critical',
  },
  {
    id: 'cal-ability-2',
    question: 'Abilities execute but return no output or "collected" status',
    answer: `Abilities that show "collected" status ran but may not have produced visible output:

1. **"Collected" is normal**: In Caldera, "collected" means the ability executed and the output was collected. This is a success state.

2. **Check output**: Click on the ability in the operation view to see the raw output. Some abilities produce output that's stored as facts rather than displayed.

3. **Fact collection**: Many abilities are designed to collect facts (e.g., hostnames, usernames, file paths) rather than produce visible output. Check the Facts tab in the operation.

4. **Timeout**: If an ability takes too long, it may timeout. The default timeout is 60 seconds. Check if the ability needs more time.

5. **Permission issues**: The ability may have run but failed due to insufficient permissions. Check if the agent is running as Administrator/root.

6. **Cleanup abilities**: Some abilities are cleanup commands that don't produce output by design.

7. **Raw command test**: To verify, try running the ability's command manually on the target:
   - Find the ability's command in the Cyber Campaign Command dashboard
   - Execute it directly on the target machine
   - Compare the output`,
    category: 'Abilities',
    tags: ['collected', 'no output', 'status', 'facts'],
    severity: 'medium',
  },
  {
    id: 'cal-ability-3',
    question: 'Abilities are stuck in "queued" status and never execute',
    answer: `Abilities stuck in "queued" status haven't been sent to an agent yet:

1. **No matching agent**: The ability requires a specific platform/executor that no active agent supports. Check the ability's requirements.

2. **Agent is dead**: If the assigned agent is no longer checking in, abilities will remain queued. Check agent status.

3. **Operation paused**: The operation may be paused. Check the operation state:
   - Running: abilities are being executed
   - Paused: no new abilities are sent
   - Finished: operation is complete

4. **Fact dependencies**: Some abilities require facts from previous abilities. If a prerequisite ability failed, dependent abilities stay queued.

5. **Planner logic**: The operation's planner determines ability execution order. The "atomic" planner runs abilities sequentially. The "batch" planner runs all at once.

6. **Rate limiting**: Caldera may throttle ability execution. Check the operation's "jitter" settings (min/max sleep between abilities).

7. **Resume operation**: If the operation is stuck, try:
   - Pause and resume the operation
   - Or create a new operation with the same adversary profile`,
    category: 'Abilities',
    tags: ['queued', 'stuck', 'not executing', 'planner'],
    severity: 'high',
  },
  {
    id: 'cal-ability-4',
    question: 'Ability failed with "access denied" or "permission denied"',
    answer: `Permission errors indicate the agent lacks required privileges:

1. **Privilege level**: Many abilities require elevated privileges:
   - Windows: Run as Administrator
   - Linux: Run as root or with sudo

2. **Check agent privilege**: In the Agents page, check the agent's privilege level. If it shows "User", you need to escalate.

3. **Privilege escalation**: Use Caldera's privilege escalation abilities first:
   - T1548.002: Abuse Elevation Control Mechanism (UAC Bypass)
   - T1134: Access Token Manipulation
   - T1068: Exploitation for Privilege Escalation

4. **UAC on Windows**: If UAC is enabled, the agent may be running in a medium-integrity context. Use a UAC bypass ability first.

5. **SELinux/AppArmor**: On Linux, security modules may block operations even for root. Check:
   getenforce (SELinux)
   aa-status (AppArmor)

6. **Protected processes**: Some abilities target protected processes (LSASS, etc.) that require special privileges even for administrators.

7. **Credential Guard**: On Windows with Credential Guard, LSASS memory dumping is blocked at the hypervisor level. Use alternative credential access techniques.`,
    category: 'Abilities',
    tags: ['access denied', 'permission', 'privilege', 'escalation', 'UAC'],
    severity: 'high',
  },

  // --- Operations ---
  {
    id: 'cal-ops-1',
    question: 'Operation is not progressing - abilities are not being sent to agents',
    answer: `If an operation starts but doesn't progress:

1. **Check operation state**: Verify the operation is in "running" state, not "paused" or "finished".

2. **Agent availability**: At least one active agent must be available. Check the Agents page for live agents.

3. **Adversary profile**: Verify the operation's adversary profile has abilities assigned. An empty adversary profile will complete immediately.

4. **Planner issues**: The operation planner may be stuck. Try changing the planner:
   - Atomic: Executes abilities one at a time
   - Batch: Executes all abilities at once
   - Buckets: Groups by tactic phase

5. **Caldera logs**: Check server logs for errors:
   tail -100 /opt/caldera/logs/caldera.log

6. **Restart operation**: Sometimes restarting helps:
   - In Caldera UI: Stop the operation, then start a new one
   - Via API: DELETE /api/v2/operations/{id}, then POST /api/v2/operations

7. **Operation persistence**: If Caldera was restarted, operations may need to be recreated. The Cyber Campaign Command platform has a persistence service that handles this automatically.`,
    category: 'Operations',
    tags: ['operation', 'not progressing', 'stuck', 'planner'],
    severity: 'critical',
  },
  {
    id: 'cal-ops-2',
    question: 'Operations disappear after Caldera server restart',
    answer: `Caldera operations are stored in memory by default and may not survive restarts:

1. **Operation persistence service**: The Cyber Campaign Command platform includes a systemd service (caldera-ops-persist.service) that automatically recreates operations on restart.

2. **Check the service**:
   sudo systemctl status caldera-ops-persist
   This service recreates the three default operations:
   - Databank_Complete (59 abilities)
   - APT29_VCD (48 abilities)
   - CrowdStrike_Bypass (12 abilities)

3. **Manual recreation**: If the service isn't running, you can recreate operations via the Caldera API:
   curl -X POST https://caldera.aceofcloud.io/api/v2/operations \\
     -H "KEY: YOUR_API_KEY" \\
     -H "Content-Type: application/json" \\
     -d '{"name":"Operation Name","adversary":{"adversary_id":"ID"}}'

4. **Caldera data directory**: Operation data is stored in /opt/caldera/data/. Ensure this directory is preserved during updates.

5. **Backup**: Regularly backup /opt/caldera/data/ and /opt/caldera/conf/ to preserve configurations.`,
    category: 'Operations',
    tags: ['restart', 'persistence', 'disappear', 'operations'],
    severity: 'high',
  },
  {
    id: 'cal-ops-3',
    question: 'How do I run a specific subset of abilities from an adversary profile?',
    answer: `To run only specific abilities instead of the full adversary profile:

1. **Create a custom adversary**: In Caldera, create a new adversary profile with only the abilities you want:
   - Go to Adversaries in Caldera UI
   - Click "Create Adversary"
   - Add only the desired abilities

2. **Manual command execution**: Use the Manual Command feature in Caldera to run individual commands on an agent without creating an operation.

3. **Operation with filters**: Start an operation and immediately pause it. Then manually queue specific abilities.

4. **Atomic planner**: Use the "atomic" planner which runs abilities one at a time. You can pause the operation between abilities.

5. **API approach**: Use the Caldera API to create a custom operation:
   POST /api/v2/operations with a custom adversary containing only your selected abilities.

6. **Cyber Campaign Command dashboard**: Use the Operation Detail page to view all abilities in an adversary profile and identify which ones you want to run.`,
    category: 'Operations',
    tags: ['subset', 'custom', 'specific abilities', 'adversary'],
    severity: 'low',
  },

  // --- Server Issues ---
  {
    id: 'cal-server-1',
    question: 'Caldera server is not starting or crashes on startup',
    answer: `If the Caldera server won't start:

1. **Check the service**:
   sudo systemctl status caldera
   sudo journalctl -u caldera -f

2. **Port conflict**: Caldera uses port 8888 by default. Check if another process is using it:
   sudo lsof -i :8888
   Kill the conflicting process or change Caldera's port in conf/local.yml.

3. **Python dependencies**: Caldera requires Python 3.8+. Verify:
   python3 --version
   pip3 list | grep -i caldera

4. **Configuration errors**: Check /opt/caldera/conf/local.yml for syntax errors. YAML is sensitive to indentation.

5. **Memory issues**: Caldera needs at least 2GB RAM. Check available memory:
   free -h
   If low on memory, stop unnecessary services.

6. **Plugin errors**: A broken plugin can prevent startup. Try disabling plugins in conf/local.yml and re-enabling them one by one.

7. **Clean start**: As a last resort:
   cd /opt/caldera
   python3 server.py --fresh
   WARNING: This resets all data.`,
    category: 'Server',
    tags: ['startup', 'crash', 'service', 'port conflict'],
    severity: 'critical',
  },
  {
    id: 'cal-server-2',
    question: 'Caldera API returns 401 Unauthorized for all requests',
    answer: `API authentication failures usually mean incorrect API keys:

1. **Check API keys**: Caldera has two API keys:
   - Red team key: For offensive operations
   - Blue team key: For defensive monitoring
   
   Find them in /opt/caldera/conf/local.yml under "api_key_red" and "api_key_blue".

2. **Header format**: The API key must be sent in the "KEY" header (not "Authorization"):
   curl -H "KEY: your-api-key" https://caldera.aceofcloud.io/api/v2/health

3. **Key rotation**: If keys were recently rotated, update all references:
   - Cyber Campaign Command dashboard configuration
   - Bridge service configuration
   - Any scripts or automation tools

4. **Current keys for this deployment**:
   Check the Credentials page in the Cyber Campaign Command dashboard for the current API keys.

5. **Test connectivity**:
   curl -v -H "KEY: YOUR_KEY" https://caldera.aceofcloud.io/api/v2/agents
   Look for the response code and any error messages.`,
    category: 'Server',
    tags: ['401', 'unauthorized', 'API key', 'authentication'],
    severity: 'high',
  },
  {
    id: 'cal-server-3',
    question: 'Caldera plugins are not loading or showing errors',
    answer: `Plugin issues can affect Caldera functionality:

1. **Check enabled plugins**: View /opt/caldera/conf/local.yml for the plugins list:
   plugins:
     - sandcat
     - stockpile
     - manx
     - compass
     - emu
     - response

2. **Plugin dependencies**: Some plugins require additional Python packages. Install them:
   cd /opt/caldera
   pip3 install -r plugins/PLUGIN_NAME/requirements.txt

3. **Plugin conflicts**: Disable all plugins, then enable them one at a time to identify the problematic one.

4. **Stockpile plugin**: This is the main ability repository. If it's not loading, most abilities will be missing:
   cd /opt/caldera/plugins/stockpile
   git pull origin master

5. **EMU plugin**: The MITRE EMU plugin provides APT emulation profiles. Ensure it's installed:
   cd /opt/caldera/plugins
   git clone https://github.com/mitre/emu.git

6. **Restart after changes**: Always restart Caldera after modifying plugins:
   sudo systemctl restart caldera

7. **Check logs**: Plugin errors are logged during startup:
   sudo journalctl -u caldera | grep -i plugin`,
    category: 'Server',
    tags: ['plugins', 'loading', 'errors', 'stockpile', 'EMU'],
    severity: 'medium',
  },

  // --- MITRE ATT&CK ---
  {
    id: 'cal-mitre-1',
    question: 'How do I map my operation results to the MITRE ATT&CK framework?',
    answer: `Caldera natively supports MITRE ATT&CK mapping:

1. **Built-in mapping**: Every ability in Caldera is tagged with its MITRE ATT&CK technique ID (e.g., T1059.001). This mapping is automatic.

2. **Compass plugin**: Enable the Compass plugin to generate ATT&CK Navigator layers:
   - Shows which techniques were tested
   - Color-codes by success/failure
   - Exportable as JSON for ATT&CK Navigator

3. **Cyber Campaign Command dashboard**: The Operation Detail page shows all abilities grouped by MITRE ATT&CK tactic with technique IDs.

4. **ATT&CK Navigator**: Import the Compass output into https://mitre-attack.github.io/attack-navigator/ for a visual heatmap.

5. **Report generation**: The Cyber Campaign Command Report Generator includes a MITRE ATT&CK coverage section that maps all attempted techniques.

6. **Coverage analysis**: Compare your operation's technique coverage against known threat actor TTPs to identify gaps in your testing.`,
    category: 'MITRE ATT&CK',
    tags: ['MITRE', 'ATT&CK', 'mapping', 'Navigator', 'techniques'],
    severity: 'low',
  },

  // --- Integration ---
  {
    id: 'cal-integration-1',
    question: 'How does the Caldera-GoPhish bridge work?',
    answer: `The Cyber Campaign Command platform includes a bridge service that connects GoPhish and Caldera:

1. **How it works**: When a target submits credentials on a GoPhish landing page, the bridge service automatically triggers a Caldera operation against that target.

2. **Flow**:
   a. GoPhish sends phishing email to target
   b. Target clicks link and enters credentials
   c. GoPhish webhook notifies the bridge service
   d. Bridge service triggers a Caldera operation
   e. Caldera deploys an agent to the target (if accessible)

3. **Configuration**: The bridge service runs at /opt/caldera-gophish-bridge/ and is managed by systemd:
   sudo systemctl status caldera-gophish-bridge

4. **Customization**: Edit the bridge configuration to:
   - Choose which Caldera operation to trigger
   - Set delay between credential capture and operation start
   - Filter by target group or campaign

5. **Monitoring**: Check bridge logs:
   sudo journalctl -u caldera-gophish-bridge -f

6. **Manual trigger**: You can also manually trigger operations from the Cyber Campaign Command dashboard after reviewing captured credentials.`,
    category: 'Integration',
    tags: ['bridge', 'GoPhish', 'webhook', 'automation'],
    severity: 'medium',
  },
  {
    id: 'cal-integration-2',
    question: 'SSL certificate warnings when accessing the Cyber Campaign Command dashboard',
    answer: `The current deployment uses self-signed SSL certificates:

1. **Why warnings appear**: Self-signed certificates are not trusted by browsers. This is expected behavior and does not affect security of the encrypted connection.

2. **Bypass the warning**:
   - Chrome: Click "Advanced" → "Proceed to site"
   - Firefox: Click "Advanced" → "Accept the Risk and Continue"
   - Edge: Click "Continue to this website"

3. **Let's Encrypt fix**: Once the domain strike.spicythreatintel.com is configured with DNS pointing to 137.184.7.224, Let's Encrypt certificates will be installed:
   sudo certbot --nginx -d strike.spicythreatintel.com

4. **Current access URLs**:
   - Dashboard: https://dashboard.aceofcloud.io (SSL warning)
   - Caldera UI: https://caldera.aceofcloud.io (no SSL)
   - GoPhish Admin: https://gophish.aceofcloud.io (SSL warning)

5. **For API access**: When using curl with self-signed certs, add the -k flag:
   curl -k https://dashboard.aceofcloud.io/api/...`,
    category: 'Integration',
    tags: ['SSL', 'certificate', 'warning', 'HTTPS', 'Let\'s Encrypt'],
    severity: 'low',
  },
];
