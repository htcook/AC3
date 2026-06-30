# ICS/SCADA Intelligence Research Findings

## Key Data Sources

### 1. CISA ICS Advisories (Primary)
- RSS Feed: https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml
- CSAF JSON: https://github.com/cisagov/CSAF (csaf_files/OT/white/ directory)
- Machine-readable CSAF 2.0 format with CVEs, affected products, vendor info
- Updated continuously, ~300+ advisories per year

### 2. ICS Advisory Project (Enriched Data)
- GitHub: https://github.com/icsadvprj
- Free enriched CISA ICS advisory data
- Dashboards available at icsadvisoryproject.com
- API available (paid) through Industrial Data Works

### 3. MITRE ATT&CK for ICS
- Matrix: https://attack.mitre.org/matrices/ics/
- STIX Data: https://github.com/mitre-attack/attack-stix-data (ics-attack folder)
- 12 tactics, 80+ techniques specific to ICS
- Groups with ICS capabilities mapped

### 4. Dragos (OT Threat Intel)
- Blog: https://www.dragos.com/blog/ (no public RSS confirmed)
- Threat groups: CHERNOVITE, ELECTRUM, XENOTIME, KAMACITE, etc.
- Year in Review reports (annual, free)

### 5. Claroty (OT Security Research)
- Blog: https://claroty.com/team82/research
- Vulnerability disclosures and ICS research

## ICS-Specific Malware Families (Definitive List)
| Year | Name | Target |
|------|------|--------|
| 2005 | fast16 | Engineering simulation software |
| 2010 | Stuxnet | Siemens PLCs (uranium centrifuges) |
| 2010 | Night Dragon | Oil/energy/petrochemical |
| 2011 | Duqu | ICS manufacturers |
| 2012 | Shamoon | Saudi Aramco, RasGas |
| 2013 | Havex/Oldrea | ICS/SCADA via OPC |
| 2014 | BlackEnergy2 | HMIs |
| 2015 | BlackEnergy3 | Ukraine power grid HMIs |
| 2015 | Irongate | Siemens simulated environment |
| 2017 | Industroyer/CRASHOVERRIDE | Ukraine power grid |
| 2017 | TRITON/Trisis/HatMan | Safety instrumented systems (SIS) |
| 2022 | Industroyer2 | Ukraine power grid (simplified) |
| 2022 | PIPEDREAM/INCONTROLLER | OPC-UA, Siemens, Omron PLCs |
| 2024 | FrostyGoop | Modbus TCP devices |
| 2024 | Fuxnet | Russian ICS (BlackJack group) |
| 2024 | IOCONTROL | IoT/OT backdoor |
| 2024 | Chaya_003 | Siemens engineering processes |
| 2025 | DynoWiper | HMIs in Poland |
| 2026 | ZionSiphon | Israeli water treatment |

## Open-Source ICS/SCADA Security Tools
### Honeypots
- Conpot: ICS/SCADA honeypot (Modbus, S7comm, IPMI, etc.)
- GRFICSv2: Graphical Realism Framework for ICS (5 VMs)
- Gridpot: Electric grid honeynet

### Assessment Tools
- Redpoint (Nmap NSE scripts for ICS)
- PLCScan: PLC scanner
- ModbusPal: Modbus simulator
- s7-pcap-tool: Siemens S7 protocol analysis

### Frameworks
- ControlThings Platform: Linux distro for ICS security
- SCADAShutdownTool: SCADA testing tool
- ISF (Industrial Security Framework)

### Monitoring
- Malcolm: Network traffic analysis for OT
- Zeek (with ICS protocol analyzers)
- Grassmarlin: Network situational awareness for ICS

## ICS Vendor CVE Sources
- Siemens ProductCERT: https://www.siemens.com/cert
- Schneider Electric PSIRT
- Rockwell Automation
- ABB Cybersecurity
- Honeywell PSIRT
- GE Digital
- Yokogawa
- Emerson
- Mitsubishi Electric

## Threat Actor Groups with ICS Capability
- XENOTIME (TRITON/Trisis)
- ELECTRUM (Industroyer)
- CHERNOVITE (PIPEDREAM)
- Sandworm (Russia - BlackEnergy, Industroyer)
- Equation Group (Stuxnet attribution)
- APT33/Elfin (Iran - energy sector)
- APT34/OilRig (Iran - ICS reconnaissance)
- Lazarus Group (energy sector targeting)
- Dragonfly/Energetic Bear (ICS reconnaissance)
- BlackJack (Fuxnet)
