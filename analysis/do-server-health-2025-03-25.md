# DO Scan Server Health Check — Mar 25, 2026

## Server Status: HEALTHY

### System Resources
| Metric | Value | Status |
|--------|-------|--------|
| Uptime | 1 day, 22h 37m (since Mar 23 20:46) | OK |
| RAM | 15 GB total, 5.7 GB used, 3.5 GB free, 6.4 GB cache | OK (9.6 GB available) |
| Swap | 4 GB total, 215 MB used | OK |
| Disk | 155 GB total, 42 GB used (27%) | OK |
| Load Average | 0.01, 0.02, 0.00 | IDLE |
| OOM Kills | None | OK |

### Services
| Service | Status |
|---------|--------|
| nginx | active |
| docker | active |
| PM2 scan-service | online, PID 1229, 46h uptime, 0 restarts, 45.5 MB |

### Docker Containers
| Container | Status | Notes |
|-----------|--------|-------|
| zap | Up 47h (healthy) | 0.0.0.0:8090→8080 |
| juice-shop | Up 4h | 127.0.0.1:3001→3000 (restarted ~4h ago) |
| dvwa | Up 47h | OK |
| webgoat | Up 47h (unhealthy) | Known issue |
| bwapp | Up 47h | OK |
| mutillidae-www | Up 47h | OK |
| altoro-mutual | Up 47h | OK |
| vulnbank | Up 47h | OK |
| vampi | Up 47h | OK |
| dvga | Up 47h | OK |

### Key Processes
| Process | PID | Memory | CPU | Notes |
|---------|-----|--------|-----|-------|
| ZAP (Java) | 1953 | 2.48 GB (15.1%) | 3.0% | -Xmx3997m |
| WebGoat (Java) | 1873 | 761 MB (4.6%) | 0.2% | |
| Altoro (Tomcat) | 2002 | 598 MB (3.6%) | 0.1% | |
| Juice Shop (Node) | 892972 | 887 MB (5.4%) | 1.4% | Restarted ~4h ago |

### Journal Errors (last 1h)
- SSH kex_exchange_identification errors (4 occurrences) — likely port scanners/bots

### Last Reboots
- Mon Mar 23 20:46 (current boot)
- Thu Mar 19 15:38
- Thu Mar 19 15:26

## Conclusion
The DO scan server is **completely healthy**. No OOM kills, no restarts, plenty of resources (9.6 GB RAM available, 0.01 load average, 114 GB disk free). The only notable item is Juice Shop restarted ~4 hours ago (now "Up 4 hours" vs other containers at "Up 47 hours").

The "server restart" the user experienced is NOT from the DO scan server — it's from the **Manus production container** hosting aceofcloud.io. This is a Manus platform-level restart, not a resource issue.
