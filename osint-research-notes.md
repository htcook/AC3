# OSINT Integration Research Notes

## Available Free APIs & Tools

### Domain Reconnaissance
1. **crt.sh** - Certificate Transparency logs, free API, no auth needed
   - `https://crt.sh/?q=%.domain.com&output=json` → subdomains from CT logs
2. **Node.js dns module** - Built-in, no API key needed
   - `dns.resolveMx()` - MX records
   - `dns.resolveTxt()` - TXT records (SPF, DKIM, DMARC)
   - `dns.resolve()` - A, AAAA, CNAME, NS records
3. **WHOIS** - via `whois` CLI or npm packages like `whois-json`
4. **HackerTarget API** - Free tier: 100 req/day
   - Subdomain finder, DNS lookup, reverse IP

### Email Security Analysis (Spoofability)
- **SPF**: TXT record `v=spf1 ...` - check for `~all` (softfail=spoofable) vs `-all` (hardfail)
- **DKIM**: TXT record at `selector._domainkey.domain.com`
- **DMARC**: TXT record at `_dmarc.domain.com` - check `p=none` (no enforcement=spoofable) vs `p=reject`
- Node.js `dns.resolveTxt()` can check all of these natively

### Typosquatting
1. **dnstwist** - Python tool, generates domain permutations (bitsquatting, homoglyph, insertion, omission, repetition, replacement, transposition, vowel-swap, addition, etc.)
   - Can install via pip and call from Node.js
   - Or implement core algorithms in TypeScript
2. **DNS resolution** - Check if permuted domains resolve (registered vs available)
3. **WHOIS** - Check registration status of permuted domains

### Dark Web / Breach Data
1. **Have I Been Pwned API v3** - Domain search requires subscription ($3.50/mo)
   - Free: individual email breach check
2. **DeHashed** - API for breach data search by domain/email
3. **IntelX (Intelligence X)** - Free tier available for breach/leak search
4. **For MVP**: Use LLM to analyze and summarize known breach data

### Implementation Strategy
- Use Node.js `dns` module for MX/SPF/DKIM/DMARC (zero dependencies)
- Use crt.sh API for subdomain enumeration (free, no auth)
- Implement typosquat algorithms in TypeScript (no Python dependency)
- Use LLM to analyze OSINT findings and auto-design campaigns
- Store all findings in DB for engagement history
