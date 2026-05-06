# AC3 Exploit Pipeline Test Lab

Metasploitable3-equivalent targets on DigitalOcean for blind testing the autonomous exploit pipeline.

## Quick Start

```bash
# 1. Deploy both targets (requires DIGITALOCEAN_ACCESS_TOKEN env var)
cd infrastructure/test-lab
chmod +x deploy-test-lab.sh
./deploy-test-lab.sh

# 2. Wait ~5 minutes for provisioning to complete
# The script outputs the target IPs when done

# 3. Update the blind-test-engagement.json with actual IPs
# Replace LINUX_TARGET_IP and WINDOWS_TARGET_IP

# 4. Create the engagement in the dashboard
# Use the config from blind-test-engagement.json

# 5. Start the engagement — the pipeline should autonomously:
#    - Port scan both targets
#    - Identify services and versions
#    - Map to CVEs via fingerprint DB + NVD
#    - Select and execute exploits
#    - Obtain shells and verify access

# 6. After completion, run the validation
#    Compare results against successCriteria in the JSON config

# 7. Tear down when done
chmod +x teardown-test-lab.sh
./teardown-test-lab.sh
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    DO VPC: ac3-testlab-vpc                       │
│                                                                 │
│  ┌──────────────────────┐     ┌──────────────────────────────┐  │
│  │  ac3-linux-target    │     │  ac3-windows-target           │  │
│  │  Ubuntu 14.04        │     │  Windows Server 2008 R2       │  │
│  │                      │     │                               │  │
│  │  ProFTPD 1.3.5 :21   │     │  IIS 7.5          :80        │  │
│  │  OpenSSH       :22   │     │  SMBv1 (MS17-010) :445       │  │
│  │  Apache+PHP    :80   │     │  ManageEngine     :8020      │  │
│  │  Samba 4.3     :445  │     │  Jenkins          :8080      │  │
│  │  MySQL 5.5     :3306 │     │  Axis2            :8282      │  │
│  │  PostgreSQL    :5432 │     │  Tomcat           :8484      │  │
│  │  UnrealIRCd    :6667 │     │  WordPress        :8585      │  │
│  │  Redis         :6379 │     │  RDP              :3389      │  │
│  │  Tomcat        :8080 │     │                               │  │
│  │  Shellshock    :8181 │     │                               │  │
│  │  Elasticsearch :9200 │     │                               │  │
│  └──────────────────────┘     └──────────────────────────────┘  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────────┐│
│  │  Firewall: ac3-testlab-fw                                    ││
│  │  Inbound: Only from scan server IPs (137.184.71.192,         ││
│  │           137.184.211.238) + your management IP               ││
│  │  Outbound: All (for reverse shells)                          ││
│  └──────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## Pipeline Decision Path (Expected)

For the Linux target, the exploit pipeline should follow this autonomous path (using naabu for port discovery + our custom service fingerprinter for version detection):

| Service Detected (via naabu + fingerprinter) | Pipeline Decision | Expected Module | Result |
|----------------------------------------------|-------------------|-----------------|--------|
| ProFTPD 1.3.5 | Fingerprint DB → Direct MSF | `exploit/unix/ftp/proftpd_modcopy_exec` | Shell |
| Samba 4.3.x | Fingerprint DB → Direct MSF | `exploit/multi/samba/usermap_script` | Shell |
| Elasticsearch 1.1 | Fingerprint DB → Direct MSF | `exploit/multi/elasticsearch/script_mvel_rce` | Shell |
| Apache + Shellshock | Fingerprint DB → Direct MSF | `exploit/multi/http/apache_mod_cgi_bash_env_exec` | Shell |
| UnrealIRCd 3.2.8.1 | Fingerprint DB → Direct MSF | `exploit/unix/irc/unreal_ircd_3281_backdoor` | Shell |
| PHP-CGI | Fingerprint DB → Direct MSF | `exploit/multi/http/php_cgi_arg_injection` | Shell |
| Tomcat (default creds) | Fingerprint DB → Direct MSF | `exploit/multi/http/tomcat_mgr_upload` | Shell |
| Redis (unauth) | Fingerprint DB → Direct MSF | `exploit/linux/redis/redis_replication_cmd_exec` | Shell |
| MySQL (root/empty) | LLM fallback → UDF | `exploit/multi/mysql/mysql_udf_payload` | Shell |
| PostgreSQL (default) | LLM fallback → copy_from_program | `exploit/multi/postgres/postgres_copy_from_program_cmd_exec` | Shell |

For the Windows target:

| Service Detected | Pipeline Decision | Expected Module | Result |
|-----------------|-------------------|-----------------|--------|
| SMBv1 (Win2008) | Fingerprint DB → Direct MSF | `exploit/windows/smb/ms17_010_eternalblue` | Shell |
| IIS 7.5 | Fingerprint DB → MS15-034 check | `auxiliary/dos/http/ms15_034_ulonglongadd` | DoS confirm |
| ManageEngine | Fingerprint DB → Direct MSF | `exploit/windows/http/manageengine_connectionid_write` | Shell |
| Jenkins | Fingerprint DB → Script Console | `exploit/multi/http/jenkins_script_console` | Shell |

## Success Metrics

- **Minimum 5 shells** obtained autonomously
- **Minimum 10 vulnerabilities** discovered without hints
- **Maximum 2 false positives** in the final report
- **Required CVEs exploited**: CVE-2015-3306, CVE-2014-3120, CVE-2014-6271, CVE-2017-0143
- **Precision ≥ 80%** (findings that are real / total findings)
- **Recall ≥ 70%** (real vulns found / total real vulns on target)

## Cost Estimate

- Linux target: $12/month (2 vCPU, 2GB RAM, Basic Droplet)
- Windows target: $24/month (2 vCPU, 4GB RAM, Basic Droplet)
- **Total: ~$36/month** (or ~$1.20/day if destroyed after testing)

## Teardown

```bash
./teardown-test-lab.sh
```

This destroys both droplets, the VPC, and the firewall. No persistent cost.
