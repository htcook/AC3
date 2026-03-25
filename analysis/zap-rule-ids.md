# ZAP Active Scan Rule IDs Reference

## High-Value Rules (Fast, Effective for Training Labs)

### SQL Injection
- 40018: SQL Injection (generic, RDBMS-independent) - **CRITICAL**
- 40019: SQL Injection - MySQL (Time Based) - slow
- 40020: SQL Injection - Hypersonic (Time Based) - slow
- 40021: SQL Injection - Oracle (Time Based) - slow
- 40022: SQL Injection - PostgreSQL (Time Based) - slow
- 40027: SQL Injection - MsSQL (Time Based) - slow

### XSS
- 40012: Cross Site Scripting (Reflected) - **CRITICAL**
- 40014: Cross Site Scripting (Persistent) - **CRITICAL** but slow
- 40031: DOM XSS (if available)

### Command Injection
- 90020: Remote OS Command Injection - **CRITICAL**
- 90037: Remote OS Command Injection (Time Based) - slow

### Path Traversal / File Inclusion
- 6: Path Traversal - **CRITICAL**
- 7: Remote File Include - **CRITICAL**

### SSTI
- 90035: Server Side Template Injection - **CRITICAL**
- 90036: Server Side Template Injection (Blind) - slow

### XXE
- 90023: XXE - medium speed

### Other High-Value
- 40003: CRLF Injection - fast
- 90019: Code Injection - fast
- 40009: Server Side Include - fast
- 20019: External Redirect - fast
- 40008: Parameter Tampering - fast
- 10058: GET for POST - fast

### Info Disclosure (fast)
- 40034: .env Information Leak
- 40032: .htaccess Information Leak
- 40035: Hidden File Finder
- 10095: Backup File Disclosure
- 0: Directory Browsing

### Slow Rules to DISABLE for Training Labs
- 40019, 40020, 40021, 40022, 40027: Time-based SQLi variants (very slow through proxy)
- 90037: Time-based command injection (slow)
- 90036: Blind SSTI (slow)
- 30001: Buffer Overflow (slow, irrelevant for web apps)
- 30002: Format String Error (slow, irrelevant)
- 20015: Heartbleed (irrelevant for modern apps)
- 10048: ShellShock (irrelevant for Juice Shop)
- 40044: Billion Laughs (slow)
- 40043: Log4Shell (needs OAST)
- 40045: Spring4Shell (irrelevant for Juice Shop)
- 10104: User Agent Fuzzer (low value)
