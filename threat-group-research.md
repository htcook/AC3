# Threat Group Research Notes

## Top TTPs 2025 (Bitsight)
- T1190: Exploiting Public-Facing Applications (CVE-2025-58360 GeoServer XXE)
- T1566.001: Phishing / spear phishing for credential harvesting
- T1059: Command and Scripting Interpreter (PowerShell T1059.001)
- T1003.001: OS Credential Dumping (Mimikatz)
- T1053/T1547.001: Scheduled Task/Job + Registry Run Keys (persistence)
- T1567.002: Exfiltration Over Web Services (cloud storage: Dropbox, Google Docs)
- T1486/T1485: Data Encrypted for Impact / Data Destruction (ransomware/wiper)
- T1498.002: Reflection/Amplification DDoS
- T1496: Resource Hijacking (supply chain)

## Emerging Threat Actors 2025
- North Korea (Lazarus/Kimsuky): defense, aerospace, nuclear, healthcare ransomware, Log4j exploitation
- China-aligned: telecom, manufacturing, energy, edge device exploitation, long-term persistence
- SonicWall exploitation campaigns
- npm supply chain attacks

## Key Tools Used by Threat Actors
- Mimikatz (credential dumping)
- PowerShell (execution, recon, persistence)
- Cobalt Strike (C2)
- Web shells (persistence on public-facing servers)
- Custom malware + dual-use utilities
- Cloud storage services for exfiltration

## SOCRadar Top 10 APT Groups 2025

### China-Aligned
1. **Mustang Panda (APT27)** — PlugX, Poison Ivy, Cobalt Strike, social engineering, fileless techniques, AitM, valid code signing certs
2. **APT40 (Leviathan)** — Maritime/defense targeting, web shells, long-term access, data exfiltration, C2 infrastructure
3. **APT41 (Double Dragon)** — Dual espionage + financial, spear-phishing, custom malware, supply chain attacks
4. **Volt Typhoon** — Living-off-the-land (LotL), web shells, credential abuse, zero-day exploits, targets US critical infrastructure

### Russia-Aligned
5. **APT29 (Cozy Bear)** — Watering hole campaigns, device code auth abuse, credential harvesting, SolarWinds supply chain
6. **Sandworm (APT44)** — Data wipers (Zerolot, Sting), power grid attacks, NotPetya, targets Ukraine energy/logistics

### Iran-Aligned
7. **APT34 (OilRig)** — Spear-phishing, custom backdoors, email/SSH/DNS exfiltration, PowerShell malware

### North Korea-Aligned
8. **Lazarus Group** — Cryptocurrency theft, ransomware, social engineering, supply chain, custom malware
9. **Andariel (Jumpy Pisces)** — RID hijacking, PsExec, JuicyPotato, SAM registry modification

### South Asia
10. **APT36 (Transparent Tribe)** — Fake PDFs, .desktop file abuse, Bash payloads, DNS/UDP C2, cron/systemd persistence

## Arctic Wolf Top 10 Ransomware TTPs (MITRE ATT&CK)

### Initial Access
- **T1133** — External Remote Services (VPN, RDP) — brute-force, password spraying
- **T1190** — Exploit Public-Facing Application — Exchange, VPN, known CVEs

### Execution
- **T1059.001** — PowerShell — payload deployment, C2 downloads, credential harvesting, LotL

### Privilege Escalation
- **T1078** — Valid Accounts — credential theft, initial access brokers

### Defense Evasion
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1112** — Modify Registry

### Credential Access
- **T1003** — OS Credential Dumping — LSASS, SAM, NTDS.dit, Mimikatz

### Lateral Movement
- **T1021** — Remote Services — RDP, SMB, WinRM, SSH
- **T1570** — Lateral Tool Transfer — PsExec, Cobalt Strike, RMM agents

### Impact
- **T1486** — Data Encrypted for Impact — double/triple extortion
- **T1490** — Inhibit System Recovery — delete shadow copies, vssadmin

### Key Ransomware Groups (2024-2025)
- **LockBit 3.0** — RaaS, StealBit exfiltration, Cobalt Strike, RDP/VPN initial access
- **ALPHV/BlackCat** — Rust-based, triple extortion, API abuse, cross-platform
- **Cl0p** — MOVEit exploitation, mass data theft, zero-day focus
- **Royal/BlackSuit** — Callback phishing, BatLoader, Cobalt Strike
- **Play** — ProxyNotShell exploitation, SystemBC, custom tools
- **Akira** — VPN exploitation, Cisco ASA/FTD targeting, Linux ESXi variants
- **Black Basta** — QakBot distribution, PrintNightmare, Cobalt Strike
