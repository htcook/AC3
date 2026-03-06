# Nmap Evasion & NSE Script Research Notes

## Evasion Techniques (from Red Team article + official docs)

### 1. Scan Type Selection for Firewall Bypass
- **SYN Scan (-sS)**: Default stealth scan, half-open. Blocked by stateful firewalls.
- **ACK Scan (-sA)**: Bypasses stateful firewalls. Can't determine open/closed but maps firewall rules. Firewalls can't tell if connection was initiated internally.
- **FIN Scan (-sF)**: Sneaks through non-stateful firewalls. Closed ports respond RST, open ports silent.
- **NULL Scan (-sN)**: No flags set. Same bypass as FIN for non-stateful firewalls.
- **XMAS Scan (-sX)**: FIN+PSH+URG flags. Same bypass capability.
- **Window Scan (-sW)**: Like ACK but examines RST window field to differentiate open/closed.
- **Maimon Scan (-sM)**: FIN/ACK probe. Some systems don't drop per RFC.
- **Idle/Zombie Scan (-sI)**: Ultimate stealth - uses zombie host. No packets from real IP.

### 2. Timing Templates (IDS Evasion)
- **-T0 (Paranoid)**: 5min between probes. Serial. Avoids all IDS.
- **-T1 (Sneaky)**: 15sec between probes. Still very stealthy.
- **-T2 (Polite)**: 0.4sec between probes. Reduces load.
- **-T3 (Normal)**: Default. Balanced.
- **-T4 (Aggressive)**: Fast. For trusted networks.
- **-T5 (Insane)**: Fastest. Drops accuracy.

### 3. Fragmentation
- **-f**: Fragment packets into 8-byte chunks. Evades signature-based IDS.
- **-f -f (or --mtu 16)**: 16-byte fragments.
- **--mtu <size>**: Custom MTU (must be multiple of 8).

### 4. Decoy Scanning
- **-D RND:5**: 5 random decoy IPs mixed with real IP.
- **-D decoy1,decoy2,ME,decoy3**: Specific decoys with ME as real position.
- Works with SYN, ACK, ICMP, OS detection scans.
- Decoys should be live IPs to avoid SYN flood detection.

### 5. Source Port Spoofing
- **--source-port 53**: Spoof DNS source port. Many firewalls trust port 53 traffic.
- **--source-port 80**: Spoof HTTP source port.
- **--source-port 88**: Spoof Kerberos source port.
- **-g <port>**: Alias for --source-port.

### 6. DNS Manipulation
- **--dns-servers 8.8.8.8,1.1.1.1**: External DNS to avoid internal logging.
- **-n**: Disable DNS resolution entirely.
- **--system-dns**: Use OS resolver instead of nmap's.

### 7. MAC/IP Spoofing
- **--spoof-mac <mac>**: Spoof MAC address. 0 = random.
- **--spoof-mac Apple**: Random Apple MAC prefix.
- **-S <ip>**: Spoof source IP (need -e for interface).
- **--data-length <num>**: Append random data to change packet signature.

### 8. Advanced Evasion Combinations
- **ACK + Decoy + DNS Proxy**: Layered evasion for maximum stealth.
- **SYN from DNS port**: `nmap -sS --source-port 53` bypasses many firewalls.
- **Fragment + Timing**: `-f -T1` for slow fragmented scans.
- **Idle scan + Decoys**: `-sI zombie -D RND:3` ultimate attribution masking.

### 9. Cloud-Specific Considerations
- AWS Security Groups: Stateful, so ACK scans less effective. Use SYN with timing.
- Azure NSGs: Similar to AWS. Source port spoofing may help.
- Cloud WAFs (CloudFlare, AWS WAF): Need very slow timing + source rotation.
- Rate limiting: -T1 or -T2 with --max-rate 10.

## NSE Script Categories (14 total, 600+ scripts)

| Category | Risk | Purpose |
|----------|------|---------|
| default | Safe | Runs with -sC. Banner grab, basic info |
| safe | Safe | Non-intrusive checks |
| vuln | Low-Med | Known CVE checks |
| discovery | Low | Advanced network discovery |
| auth | Medium | Auth bypass, default creds |
| brute | Med-High | Password brute force |
| intrusive | High | May crash services |
| exploit | Critical | Active exploitation |
| malware | Safe | Detect backdoors/malware |
| dos | Critical | Denial of service |
| version | Safe | Enhanced version detection |
| broadcast | Low | Local network discovery |
| external | Varies | Query external services |
| fuzzer | High | Send unexpected data |

## Key NSE Scripts by Service

### HTTP/Web (Port 80, 443, 8080, 8443)
- http-title: Grab page titles
- http-headers: Get HTTP headers
- http-methods: Check allowed methods (PUT, DELETE, TRACE)
- http-enum: Directory/file enumeration (like dirb/gobuster)
- http-sql-injection: Basic SQLi detection
- http-shellshock: CVE-2014-6271 Shellshock
- http-vuln-cve2017-5638: Apache Struts RCE
- http-wordpress-enum: WordPress plugin/theme enumeration
- http-wordpress-brute: WordPress login brute force
- http-php-version: PHP version detection
- http-robots.txt: Parse robots.txt
- http-security-headers: Check HSTS, CSP, X-Frame-Options
- http-cors: Check CORS configuration
- http-cookie-flags: Check cookie security flags
- http-slowloris-check: Slowloris DoS vulnerability
- http-git: Check for exposed .git directories
- http-config-backup: Check for backup config files
- http-default-accounts: Check default credentials
- http-webdav-scan: WebDAV enumeration

### SSL/TLS (Port 443)
- ssl-heartbleed: CVE-2014-0160 Heartbleed
- ssl-poodle: CVE-2014-3566 POODLE
- ssl-cert: Certificate details (issuer, expiry, SANs)
- ssl-enum-ciphers: List all supported ciphers with grades
- ssl-dh-params: Check Diffie-Hellman parameters (Logjam)
- ssl-known-key: Check for known compromised keys
- ssl-ccs-injection: CVE-2014-0224

### SMB (Port 445, 139)
- smb-vuln-ms17-010: EternalBlue
- smb-vuln-ms08-067: Conficker
- smb-vuln-ms10-054: SMB memory corruption
- smb-vuln-ms10-061: Print spooler
- smb-enum-shares: List shared folders
- smb-enum-users: List user accounts
- smb-os-discovery: OS version via SMB
- smb-protocols: Supported SMB versions
- smb-security-mode: Check signing requirements
- smb2-security-mode: SMBv2 signing
- smb-brute: SMB password brute force

### SSH (Port 22)
- ssh-auth-methods: List auth methods
- ssh-hostkey: Get host key fingerprints
- ssh2-enum-algos: List supported algorithms
- ssh-brute: SSH password brute force
- sshv1: Check for SSHv1 (insecure)

### DNS (Port 53)
- dns-zone-transfer: Attempt AXFR zone transfer
- dns-brute: Subdomain brute force
- dns-cache-snoop: DNS cache snooping
- dns-recursion: Check open recursion
- dns-nsid: Get DNS server ID
- dns-srv-enum: SRV record enumeration

### FTP (Port 21)
- ftp-anon: Check anonymous login
- ftp-bounce: FTP bounce attack
- ftp-brute: FTP password brute force
- ftp-vuln-cve2010-4221: ProFTPD RCE
- ftp-vsftpd-backdoor: vsftpd 2.3.4 backdoor
- ftp-proftpd-backdoor: ProFTPD 1.3.3c backdoor
- ftp-syst: Get system info

### MySQL (Port 3306)
- mysql-info: Server info and capabilities
- mysql-enum: User enumeration
- mysql-brute: Password brute force
- mysql-databases: List databases
- mysql-vuln-cve2012-2122: Auth bypass
- mysql-empty-password: Check empty root password
- mysql-dump-hashes: Dump password hashes

### SMTP (Port 25, 587)
- smtp-enum-users: VRFY/EXPN user enumeration
- smtp-commands: List supported commands
- smtp-open-relay: Check open relay
- smtp-brute: Password brute force
- smtp-vuln-cve2010-4344: Exim heap overflow

### RDP (Port 3389)
- rdp-enum-encryption: Encryption level check
- rdp-vuln-ms12-020: BlueKeep predecessor
- rdp-ntlm-info: NTLM info extraction

### SNMP (Port 161)
- snmp-info: System info via SNMP
- snmp-brute: Community string brute force
- snmp-sysdescr: System description
- snmp-processes: Running processes
- snmp-interfaces: Network interfaces
- snmp-netstat: Network connections

### LDAP (Port 389, 636)
- ldap-rootdse: Root DSE info
- ldap-search: LDAP search
- ldap-brute: Password brute force

### VNC (Port 5900)
- vnc-info: VNC server info
- vnc-brute: Password brute force
- realvnc-auth-bypass: CVE-2006-2369

## Evasion + NSE Script Compatibility Notes
- Most NSE scripts work with -sS (SYN scan) - best combo
- vuln scripts generally safe with -f fragmentation
- brute scripts ignore timing templates (have own rate limiting)
- --script-timeout controls per-script timeout
- --script-args can pass custom args to scripts
- vulners.nse (external) queries vulners.com API for CVE matching
- vulscan.nse (external) uses local CSV databases for offline CVE matching

## Recommended Scan Profiles

### Stealth Recon (IDS Evasion)
```
nmap -sS -T1 -f --source-port 53 -D RND:3 --data-length 24 -n -Pn --max-rate 10 <target>
```

### Web Application Assessment
```
nmap -sV --script "http-* and safe" -p 80,443,8080,8443 <target>
```

### Full Vuln Scan (Authorized)
```
nmap -sV --script vuln -p- <target>
```

### Cloud Infrastructure Scan
```
nmap -sS -sV -T2 --script "ssl-* or http-security-headers or http-cors" -p 80,443,8080,8443,22 --max-rate 50 <target>
```

### SMB/Windows Assessment
```
nmap -sV --script "smb-vuln-* or smb-enum-*" -p 445,139 <target>
```

### Database Assessment
```
nmap -sV --script "mysql-* or pgsql-* or ms-sql-*" -p 3306,5432,1433 <target>
```

### Quick Recon (Default Scripts)
```
nmap -sC -sV -O <target>
```


## Complete Vuln Category NSE Scripts (from nmap.org)

### FTP Vulnerabilities
- ftp-libopie: CVE-2010-1938 OPIE off-by-one stack overflow
- ftp-proftpd-backdoor: ProFTPD 1.3.3c backdoor (BID 45150)
- ftp-vsftpd-backdoor: vsFTPd 2.3.4 backdoor (CVE-2011-2523)
- ftp-vuln-cve2010-4221: ProFTPD stack buffer overflow

### HTTP/Web Vulnerabilities
- http-adobe-coldfusion-apsa1301: ColdFusion auth bypass
- http-aspnet-debug: ASP.NET debug mode detection
- http-awstatstotals-exec: Awstats RCE (CVE-2008-3922)
- http-axis2-dir-traversal: Apache Axis2 directory traversal
- http-cookie-flags: Missing httponly/secure flags
- http-cross-domain-policy: Overly permissive crossdomain.xml
- http-csrf: CSRF vulnerability detection
- http-dlink-backdoor: D-Link firmware backdoor
- http-dombased-xss: DOM-based XSS detection
- http-enum: Directory/app enumeration
- http-fileupload-exploiter: Insecure file upload
- http-frontpage-login: Anonymous Frontpage login
- http-git: Exposed .git repository
- http-iis-webdav-vuln: IIS 5.1/6.0 WebDAV bypass (MS09-020)
- http-internal-ip-disclosure: Internal IP leak
- http-jsonp-detection: JSONP endpoint discovery
- http-method-tamper: HTTP verb tampering auth bypass
- http-passwd: Directory traversal for /etc/passwd
- http-phpmyadmin-dir-traversal: phpMyAdmin traversal
- http-phpself-xss: PHP_SELF reflected XSS
- http-shellshock: CVE-2014-6271 Shellshock
- http-slowloris-check: Slowloris DoS vulnerability
- http-sql-injection: SQL injection spider
- http-stored-xss: Stored XSS detection
- http-trace: HTTP TRACE method enabled
- http-vuln-cve2006-3392: Webmin file disclosure
- http-vuln-cve2009-3960: Adobe XML injection
- http-vuln-cve2010-0738: JBoss auth bypass
- http-vuln-cve2010-2861: ColdFusion directory traversal
- http-vuln-cve2011-3192: Apache Range header DoS
- http-vuln-cve2011-3368: Apache reverse proxy bypass
- http-vuln-cve2012-1823: PHP-CGI query string RCE
- http-vuln-cve2013-0156: Ruby on Rails XML parsing
- http-vuln-cve2014-3704: Drupal SQLi (Drupalgeddon)
- http-vuln-cve2014-8877: WordPress CM Download Manager RCE
- http-vuln-cve2015-1427: Elasticsearch Groovy RCE
- http-vuln-cve2015-1635: IIS HTTP.sys RCE (MS15-034)
- http-vuln-cve2017-1001000: WordPress REST API content injection
- http-vuln-cve2017-5638: Apache Struts RCE
- http-vuln-cve2017-5689: Intel AMT auth bypass
- http-vuln-cve2017-8917: Joomla SQLi
- http-vuln-misfortune-cookie: Allegro RomPager cookie RCE

### SSL/TLS Vulnerabilities
- ssl-ccs-injection: CVE-2014-0224 CCS injection
- ssl-cert-intaddr: Internal addresses in SSL certs
- ssl-dh-params: Weak DH parameters (Logjam)
- ssl-heartbleed: CVE-2014-0160 Heartbleed
- ssl-known-key: Known compromised SSL keys
- ssl-poodle: CVE-2014-3566 POODLE
- sslv2-drown: CVE-2016-0800 DROWN attack

### SMB Vulnerabilities
- smb-double-pulsar-backdoor: DoublePulsar backdoor
- smb-vuln-conficker: Conficker worm (MS08-067)
- smb-vuln-cve-2017-7494: Samba RCE (SambaCry)
- smb-vuln-cve2009-3103: SMBv2 DoS
- smb-vuln-ms06-025: RRAS memory corruption
- smb-vuln-ms07-029: DNS RPC buffer overflow
- smb-vuln-ms08-067: Conficker/Downadup
- smb-vuln-ms10-054: SMB memory corruption
- smb-vuln-ms10-061: Print spooler
- smb-vuln-ms17-010: EternalBlue
- smb-vuln-regsvc-dos: Registry service DoS
- smb-vuln-webexec: WebExec RCE

### Other Service Vulnerabilities
- mysql-vuln-cve2012-2122: MySQL auth bypass
- rdp-vuln-ms12-020: RDP DoS/RCE
- rmi-vuln-classloader: Java RMI classloader
- rsa-vuln-roca: ROCA factorization attack
- smb2-vuln-uptime: SMBv2 uptime disclosure
- supermicro-ipmi-conf: Supermicro IPMI plaintext passwords
- tls-ticketbleed: CVE-2016-9244 F5 Ticketbleed
- vulners: External CVE database matching (requires install)

## Technology-Specific Script Selection Matrix

| Target Tech | Recommended Scripts | Evasion Compatible |
|------------|--------------------|--------------------|
| Apache/Nginx | http-enum, http-shellshock, http-vuln-*, http-security-headers | Yes with -T2 |
| WordPress | http-wordpress-enum, http-wordpress-brute, http-vuln-cve2017-1001000 | Yes |
| PHP | http-vuln-cve2012-1823, http-phpself-xss, http-phpmyadmin-dir-traversal | Yes |
| ASP.NET/IIS | http-aspnet-debug, http-iis-webdav-vuln, http-vuln-cve2015-1635 | Yes |
| Java/Tomcat | http-vuln-cve2017-5638, http-vuln-cve2010-0738, rmi-vuln-classloader | Yes |
| Node.js/Express | http-enum, http-security-headers, http-cors, http-cookie-flags | Yes |
| Ruby on Rails | http-vuln-cve2013-0156, http-enum, http-git | Yes |
| MySQL | mysql-info, mysql-enum, mysql-vuln-cve2012-2122, mysql-empty-password | Yes |
| PostgreSQL | pgsql-brute (auth only) | Yes |
| Redis | redis-info, redis-brute | Yes |
| MongoDB | mongodb-info, mongodb-databases, mongodb-brute | Yes |
| Elasticsearch | http-vuln-cve2015-1427 | Yes |
| SMB/Windows | smb-vuln-ms17-010, smb-enum-shares, smb-os-discovery | Yes with -T2 |
| SSH | ssh2-enum-algos, ssh-auth-methods, ssh-hostkey | Yes |
| SSL/TLS | ssl-heartbleed, ssl-enum-ciphers, ssl-cert, ssl-poodle, ssl-dh-params | Yes |
| DNS | dns-zone-transfer, dns-brute, dns-recursion | Yes |
| Cloud/AWS | http-security-headers, http-cors, ssl-cert (check SANs), http-git | Yes |
| Docker/K8s | http-enum (API endpoints), http-methods | Yes |
