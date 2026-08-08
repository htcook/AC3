# Extracted Knowledge from Offensive Security Cheat Sheets

## Source 1: Living Off the Living Off the Land (LOTL Resources)

| Resource | URL | Category | Training Value |
|----------|-----|----------|----------------|
| LoFP (Living off the False Positive) | https://br0k3nlab/LoFP/ | False positive detection | ATT&CK-categorized false positives from popular rule sets |
| LOLDrivers | https://loldrivers.io | Windows driver abuse | Curated list of Windows drivers used to bypass security controls |
| GTFOBins | https://gtfobins.github.io | Unix binary abuse | Unix binaries to bypass local security restrictions |
| LOLBAS | https://lolbas-project.github.io | Windows LOTL | Every binary, script, library for Living Off The Land |
| LOTS Project | https://lots-project.com | Legitimate domain abuse | Legitimate domains used for phishing, C2, exfiltration |
| FileSec.io | https://filesec.io | Malicious file extensions | File extensions used by attackers |
| MalAPI.io | https://malapi.io | Windows API abuse | Maps Windows APIs to malware techniques |
| HijackLibs | https://hijacklibs.net | DLL hijacking | Curated DLL hijacking candidates |
| WADComs | https://wadcoms.github.io | AD/Windows attacks | Offensive security tools for Windows/AD environments |
| LOOBins | https://www.loobins.io | macOS binary abuse | macOS built-in binaries for malicious purposes |

## Source 2: File Upload Extension Filter Bypass

### Newline/CR/LF Character Injections (between .php and .png)
- `\n` (0x0A - Line Feed): `qwe.php\n.png`, `qwe.php%0a.png`, `qwe.php\u000a.png`
- `\r` (0x0D - Carriage Return): `qwe.php\r.png`, `qwe.php%0d.png`, `qwe.php\u000d.png`
- `\t` (0x09 - Tab): `qwe.php\t.png`, `qwe.php%09.png`, `qwe.php\u0009.png`
- HTML entities: `&#13;`, `&#10;`, `&#09;`, `&#x0d;`, `&#x0a;`, `&#x09;`
- Unicode overlong: `\u560d`, `\u560a`, `\u5609`
- Double URL encoding: `%C0%8d`, `%C0%8a`, `%C0%89`
- Triple byte: `%E5%98%8d`, `%E5%98%8a`, `%E5%98%89`
- Four byte: `%E0%80%8d`, `%E0%80%8a`, `%E0%80%89`

### Hash/Pound Character (#) Injections
- `qwe.php#.png`, `qwe.php%23.png`, `qwe.php\x23.png`
- `qwe.php&#35;.png`, `qwe.php&#x23;.png`
- Unicode: `\u0023`, `\u5623`, `%C0%A3`

### Semicolon (;) Injections
- `qwe.php;.png`, `qwe.php%3B.png`, `qwe.php\x3B.png`
- `qwe.php&#59;.png`, `qwe.php&#x3b;.png`
- Unicode: `\u003b`, `\u563b`, `%C0%bb`

### Null Byte Injections
- `qwe.php\00.png`, `qwe.php\x00.png`, `qwe.php%00.png`
- `qwe.php&#00;.png`, `qwe.php&#x00;.png`
- Unicode: `\u0000`, `\u5600`, `%C0%80`

### Space Character Injections
- `qwe.php .png` (literal space), `qwe.php\x20.png`, `qwe.php%20.png`
- `qwe.php&#20;.png`, `qwe.php&#x20;.png`
- Unicode: `\u0020`, `\u5620`, `%C0%A0`

### Special Tokens
- `qwe.php&Tab;.png`, `qwe.php&NewLine;.png`

## Source 3: Firewall Testing Checklist (25 Tools)

| # | Technique | Tool | URL |
|---|-----------|------|-----|
| 1 | Port scanning | Nmap | https://nmap.org/ |
| 2 | OS fingerprinting | Xprobe2 | http://xprobe.sourceforge.net/ |
| 3 | Firewall rule testing | Firewalk | https://github.com/defunkt/firewalk |
| 4 | Packet fragmentation evasion | Fragroute | https://github.com/plitex/fragroute |
| 5 | IP spoofing | Hping3 | https://github.com/antirez/hping |
| 6 | Protocol-specific evasion | Metasploit | https://www.metasploit.com/ |
| 7 | ICMP tunneling | ICMPTX | http://thomer.com/icmptx/ |
| 8 | DNS tunneling | Dns2tcp | https://github.com/alex-sector/dns2tcp |
| 9 | HTTP tunneling | HTTPTunnel | https://github.com/larsbrinkhoff/httptunnel |
| 10 | IPv6 tunneling | Teredo | https://tools.ietf.org/html/rfc4380 |
| 11 | ARP spoofing | Ettercap | https://www.ettercap-project.org/ |
| 12 | SSL/TLS interception | SSLstrip | https://github.com/moxie0/sslstrip |
| 13 | SSL/TLS decryption | Wireshark | https://www.wireshark.org/ |
| 14 | SSH tunneling | OpenSSH | https://www.openssh.com/ |
| 15 | Proxy server evasion | Proxychains | https://github.com/rofl0r/proxychains-ng |
| 16 | TOR network evasion | Tor Browser | https://www.torproject.org/ |
| 17 | WAF testing | Wafw00f | https://github.com/EnableSecurity/wafw00f |
| 18 | Session hijacking | Cookie Cadger | https://github.com/cookiecadger/CookieCadger |
| 19 | Man-in-the-middle | Bettercap | https://www.bettercap.org/ |
| 20 | VPN detection | Iodine | https://github.com/yarrick/iodine |
| 21 | Firewall evasion (encrypted) | Veil-Evasion | https://github.com/Veil-Framework/Veil |
| 22 | SQL injection evasion | SQLMap | https://sqlmap.org/ |
| 23 | XSS evasion | XSSer | https://github.com/epsylon/xsser |
| 24 | File type evasion | FuzzDB | https://github.com/fuzzdb-project/fuzzdb |
| 25 | Web service scanning | Nikto | https://github.com/sullo/nikto |

## Source 4: Social Engineering Attack Taxonomy

### Phishing
- Spear Phishing, Vishing, Smishing, Clone Phishing, Link Manipulation, Watering Hole Attack, Business Email Compromise (BEC)

### Pretexting
- Tech Support Scam, CEO Fraud Scam, Trust Scam, Job Scam, Relationship Scam, Charity Scam, Lottery Scam

### Baiting
- USB Drop Attack, Fake WiFi Hotspot, Evil Twin Attack, QR Code Scam, Social Media Scam, Free Gift Scam, Black Hat SEO

### Quid Pro Quo
- Conference Scam, Customer Service Scam, Fake Software Scam, Social Networking Scam, Website Community Scam, Alarm System Scam, IT Support Scam

### Tailgating
- Piggybacking, Keylogging, Dumpster Diving, Shoulder Surfing, Eavesdropping, Credit Card Skimming, Bluetooth Hacking

## Source 5: Shodan Filters Comprehensive Reference

### CLI Commands
- `shodan init <API-KEY>` — Initialize
- `shodan info` — Account info
- `shodan host <IP>` — View all info for IP
- `shodan myip` — Print external IP
- `shodan honeyscore <IP>` — Check if honeypot
- `shodan download <query>` — Download results
- `shodan domain <domain>` — Domain info
- `shodan data` — Bulk data access
- `shodan radar` — Real-time map
- `shodan scan <target>` — Scan IP/netblock
- `shodan search <query>` — Search database
- `shodan count <query>` — Count results
- `shodan stats <query>` — Summary info
- `shodan stream` — Real-time stream
- `shodan alert` — Manage alerts (info/enable/disable/list/remove/triggers/create/clear)

### Common Filters
| Category | Filters |
|----------|---------|
| General | ip, hostname, link, net, has_vuln, has_ssl, has_screenshot, has_ipv6, port, postal, geo, product, device, region, cpe, scan, country, shodan.module, state, city, asn, version, all, org, os |
| HTTP | http.html_hash, http.html, http.robots_hash, http.headers_hash, http.securitytxt, http.favicon.hash, http.status, http.component_category, http.title, http.component, http.waf |
| Cloud | cloud.provider, cloud.region, cloud.service |
| Screenshots | screenshot.hash, screenshot.label |
| SSL | ssl.cert.serial, ssl.cert.pubkey.type, ssl.cert.subject.cn, ssl.cert.pubkey.bits, ssl.chain_count, ssl.cert.issuer.cn, ssl.cipher.bits, ssl.cert.fingerprint, ssl.cipher.name, ssl.cert.extension, ssl.cipher.version, ssl.cert.expired, ssl.ja3s, ssl.cert.alg, ssl.jarm, ssl.alpn, ssl.version, ssl |
| Bitcoin | bitcoin.ip, bitcoin.ip_count, bitcoin.port, bitcoin.version |
| SNMP | snmp.contact, snmp.location, snmp.name |
| NTP | ntp.ip, ntp.ip_count, ntp.more, ntp.port |
| Telnet | telnet.do, telnet.dont, telnet.option, telnet.will, telnet.wont |
| SSH | ssh.hash, ssh.type |
| Restricted | tag, vuln (higher API plans only) |

### Web-Based Search Queries
| Target | Query |
|--------|-------|
| MongoDB servers | `mongodb` |
| Mongo Express GUI | `"Set-Cookie: mongo-express=" "200 OK"` |
| MySQL databases | `mysql port:3306` |
| ElasticSearch | `port:9200 all:"elastic indices"` |
| PostgreSQL | `port:5432 PostgreSQL` |
| FTP (proftpd) | `proftpd port:21` |
| Anonymous FTP | `"220" "230 Login successful." port:21` |
| OpenSSH | `openssh port:22` |
| Telnet | `port:23` |
| EXIM mail | `port:25 product:"exim"` |
| Memcached | `port:11211 product:"Memcached"` |
| Jenkins | `"X-Jenkins" "Set-Cookie: JSESSIONID" http.title:"Dashboard"` |
| MikroTik RouterOS | `port:8291 os:"MikroTik RouterOS 6.45.9"` |
| Apache httpd | `product:"Apache httpd" port:80` |
| Microsoft IIS | `product:"Microsoft IIS httpd"` |
| Nginx | `product:"nginx"` |
| Nginx 8080 | `"port:8080" product:"nginx"` |
| Webcams | `Server: SQ-WEBCAM` |
| Yawcam | `"Server: yawcam" "Mime-Type: text/html"` |
| XZERES Wind Turbines | `title:"xzeres wind"` |
| EV chargers | `Server: gSOAP/2.8 "Content-Length: 583"` |
| Remote Desktop | `remote desktop port:3389` |
| VNC (no auth) | `"authentication disabled" "RFB 003.008"` |
| Samba (no auth) | `"authentication disabled" port:445` |
| Plex servers | `"X-Plex-Protocol" "200 OK" port:32400` |
| NAS FTP | `"220" "230 Login successful." port:21` |
| HP printers | `"Serial Number:" "Built:" "Server: HP HTTP"` |
| EPSON printers | `"SERVER: EPSON_Linux UPnP" "200 OK"` |
| Xerox printers | `ssl:"Xerox Generic Root"` |
| Windows RDP password | `\x03\x00\x00\x0b\x06\xd0\x00\x00\x124\x00` |
| Hiring pages | `"X-Recruiting"` |
| Android Debug Bridge | `"Android Debug Bridge" "Device" port:5555` |
| Ethereum miners | `"ETH - Total speed"` |
| Tesla Powerpack | `http.title:"Tesla PowerPack System" http.component:"d3" -ga3ca4f2` |

## Source 6: Subdomain Enumeration Tools (40+ Tools)

| Tool | Description |
|------|-------------|
| Findomain | Fastest cross-platform subdomain enumerator |
| chaos-client | Go client for Chaos DNS API |
| domained | Multi-tool subdomain enumeration |
| bugcrowd-levelup | Esoteric sub-domain enumeration techniques |
| shuffledns | Wrapper around massdns for valid subdomain enumeration |
| censys-subdomain-finder | Subdomain enumeration via Censys certificate transparency logs |
| Turbolist3r | Subdomain enumeration with analysis features |
| censys-enumeration | Extract subdomains/emails from SSL/TLS certificates on Censys |
| tugarecon | Fast subdomain enumeration for pentesters |
| as3nt | Another Subdomain Enumeration Tool |
| Subra | Web-UI for subdomain enumeration (subfinder) |
| Substr3am | Passive recon by watching SSL certificates being issued |
| domain | enumall.py setup script for Recon-ng |
| altdns | Generates permutations/alterations/mutations of subdomains and resolves them |
| brutesubs | Automation framework for multiple open-source subdomain bruteforcing tools via Docker |
| dns-parallel-prober | Parallelised domain name prober |
| dnscan | Python wordlist-based DNS subdomain scanner |
| hakrevdns | Reverse DNS lookups en masse |
| dnsenum | Multithreaded perl script for DNS enumeration |
| Sudomy | Subdomain enumeration and analysis |
| Sublist3r | Fast subdomain enumeration |
| Sub.sh | Online subdomain detect script |
| Amass | In-depth attack surface mapping and asset discovery |
| Subfinder | Subdomain discovery tool |
| Massdns | High-performance DNS stub resolver for bulk lookups |
| Rsdl | Subdomain scan with Ping method |
| Assetfinder | Find domains and subdomains related to a domain |
| subbrute | DNS meta-query spider for DNS records and subdomains |
| Knockpy | Python tool for subdomain enumeration |
| Aquatone | Tool for domain flyovers |
| sub3suite | Research-grade suite for subdomain enumeration and attack surface mapping |
| scilla | Information gathering: DNS/Subdomains/Ports/Directories |
| crtndstry | Yet another subdomain finder |
| dnsx | Fast multi-purpose DNS toolkit |
