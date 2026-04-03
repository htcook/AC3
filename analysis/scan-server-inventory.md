# Scan Server Tool Inventory — Verified 2026-04-02

## Server: scanforge-dedicated (137.184.71.192)
- OS: Ubuntu 22.04 (5.15.0-171-generic x86_64)
- Go: 1.22.5
- Python: 3.10.12
- Disk: 36GB free / 49GB total
- RAM: 6.2GB available / 7.8GB total

## Installed Tools

### Port Scanning
| Tool | Path | License |
|------|------|---------|
| masscan | /usr/bin/masscan | AGPL-3.0 (standalone OK) |
| naabu | /usr/local/bin/naabu | MIT |
| rustscan | /usr/local/bin/rustscan | GPL-3.0 |
| zmap | /usr/sbin/zmap | Apache 2.0 |

### Service Fingerprinting
| Tool | Path | License |
|------|------|---------|
| nerva | /usr/local/bin/nerva | Apache 2.0 |
| httpx | /usr/local/bin/httpx | MIT |
| whatweb | /usr/bin/whatweb | GPL-2.0 |

### Vulnerability Scanning
| Tool | Path | License |
|------|------|---------|
| nuclei | /usr/local/bin/nuclei | MIT |
| nikto | /usr/bin/nikto | GPL |
| sqlmap | /usr/bin/sqlmap | GPL-2.0 |

### Web Application
| Tool | Path | License |
|------|------|---------|
| wafw00f | /usr/local/bin/wafw00f | BSD 3-Clause |
| katana | /usr/local/bin/katana | MIT |
| ZAP | Docker | Apache 2.0 |

### Credential Attacks
| Tool | Path | License |
|------|------|---------|
| hydra | /usr/bin/hydra | AGPL-3.0 (standalone OK) |
| medusa | /usr/bin/medusa | GPL-2.0 |
| hashcat | /usr/bin/hashcat | MIT |
| john | /usr/sbin/john | GPL-2.0 |
| nxc (NetExec) | /usr/local/bin/nxc | BSD 3-Clause |

### TLS/SSH Auditing
| Tool | Path | License |
|------|------|---------|
| ssh-audit | /usr/local/bin/ssh-audit | MIT |
| testssl.sh | /usr/local/bin/testssl.sh | GPL-2.0 |
| sslscan | /usr/bin/sslscan | GPL-3.0 |

### Network Tools
| Tool | Path | License |
|------|------|---------|
| nc | /usr/bin/nc | BSD |
| ncat | /usr/bin/ncat | GPL-2.0 |
| socat | /usr/bin/socat | GPL-2.0 |
| smbclient | /usr/bin/smbclient | GPL-3.0 |
| ftp | /usr/bin/ftp | BSD |
| telnet | /usr/bin/telnet | BSD |
| redis-cli | /usr/bin/redis-cli | BSD |
| mysql | /usr/bin/mysql | GPL-2.0 |

### Subdomain/DNS
| Tool | Path | License |
|------|------|---------|
| subfinder | /usr/local/bin/subfinder | MIT |

### Cloud
| Tool | Path | License |
|------|------|---------|
| s3scanner | /usr/local/bin/s3scanner | MIT |

### Python Libraries
| Library | Status | License |
|---------|--------|---------|
| impacket | OK | Apache-style |
| jwt (PyJWT) | OK | MIT |
| boto3 | OK | Apache 2.0 |
| requests | OK | Apache 2.0 |
| redis | OK | MIT |
| pymysql | OK | MIT |

## NOT Installed (lower priority)
| Tool | Reason |
|------|--------|
| ncrack | hydra + medusa cover credential brute force |
| metasploit | Large install, use nuclei + custom exploits instead |
| ike-scan | VPN gateway scanning — install when needed |
