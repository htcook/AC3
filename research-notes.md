# GitHub Repositories for TTP Knowledge Integration

## Tier 1: Core Data Sources (Structured, Machine-Readable)

### 1. MITRE ATT&CK STIX Data
- **Repo**: https://github.com/mitre-attack/attack-stix-data
- **Format**: STIX 2.1 JSON bundles
- **Content**: Complete ATT&CK framework - all techniques, tactics, groups, software, mitigations
- **File**: `enterprise-attack/enterprise-attack.json` (latest release)
- **Use**: Master technique catalog with descriptions, platforms, data sources, detections
- **Stars**: 530

### 2. Atomic Red Team
- **Repo**: https://github.com/redcanaryco/atomic-red-team
- **Format**: YAML files per technique (atomics/T1xxx/T1xxx.yaml)
- **Content**: 6,572+ commits of portable detection tests mapped to ATT&CK
- **Use**: Exact commands, tools, and execution steps for each technique
- **Stars**: 11.6k
- **Key**: Each atomic test has: name, description, supported_platforms, input_arguments, executor (command, cleanup_command)

### 3. SigmaHQ Detection Rules
- **Repo**: https://github.com/SigmaHQ/sigma
- **Format**: YAML Sigma rules (3000+ rules)
- **Content**: Detection rules mapped to ATT&CK techniques
- **Use**: Pre-built detection rules in universal Sigma format (convertible to Splunk, Elastic, etc.)
- **Stars**: 8k+

### 4. LOLBAS Project (Living Off The Land)
- **Repo**: https://github.com/LOLBAS-Project/LOLBAS
- **Format**: YAML files per binary (yml/OSBinaries/*.yml)
- **Content**: 827 commits documenting Windows LOLBins/Scripts/Libraries
- **Use**: Native Windows tools abused by attackers - commands, functions, ATT&CK mappings
- **Stars**: 8.3k

### 5. Caldera Stockpile Plugin
- **Repo**: https://github.com/mitre/stockpile
- **Format**: YAML ability definitions (data/abilities/*)
- **Content**: Official Caldera TTPs and adversary profiles
- **Use**: Direct Caldera ability definitions with executors, commands, platforms
- **Stars**: 80

## Tier 2: Enrichment Sources

### 6. Atomic Threat Coverage
- **Repo**: https://github.com/atc-project/atomic-threat-coverage
- **Content**: Combines Atomic Red Team tests + Sigma rules + logging requirements
- **Use**: Maps tests → detections → log sources per technique

### 7. Metasploit Framework
- **Repo**: https://github.com/rapid7/metasploit-framework
- **Content**: Thousands of exploit/auxiliary/post modules
- **Key file**: JSON module database for parsing
- **Parser**: https://github.com/CERTCC/metasploit_json_parser

### 8. MITRE ATT&CK Navigator
- **Repo**: https://github.com/mitre-attack/attack-navigator
- **Use**: Layer format for technique heatmaps (JSON layers)

### 9. Kali Linux Tools
- **Source**: https://www.kali.org/tools/ (web catalog)
- **Repo**: https://github.com/arch3rPro/PentestTools (community catalog)
- **Content**: 600+ tools categorized by function

### 10. GTFOBins (Linux LOLBins)
- **Source**: https://gtfobins.github.io/
- **Content**: Unix binaries that can be exploited for privilege escalation, file operations, etc.

## Integration Strategy

### Phase 1: Download & Parse Core Data
1. Download enterprise-attack.json from attack-stix-data → extract all techniques with IDs, names, tactics, descriptions, platforms, data sources
2. Download atomic red team YAML index → extract test commands per technique
3. Download Sigma rules → map to technique IDs
4. Download LOLBAS YAML files → map to technique IDs
5. Download Stockpile abilities → map to technique IDs

### Phase 2: Build Knowledge Entries
For each technique, combine:
- ATT&CK description + platforms + data sources
- Atomic Red Team test commands (how to execute)
- Sigma detection rules (how to detect)
- LOLBAS entries (native tool abuse)
- Caldera abilities (emulation capabilities)

### Phase 3: LLM Enhancement
Use LLM to:
- Generate IOC patterns from execution commands
- Create additional detection rules (Splunk SPL, KQL)
- Map attack chain positions and prerequisite/follow-up techniques
- Score red/blue/purple team value
- Generate defensive gap analysis
