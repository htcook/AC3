# Affiliated Domain Discovery - API Research

## SecurityTrails Associated Domains API
- Endpoint: GET `https://api.securitytrails.com/v1/domain/{hostname}/associated`
- Params: hostname (required), apikey (required), page (optional)
- Returns all domains related to the input domain
- Already have SECURITYTRAILS_API_KEY in env

## crt.sh Certificate Transparency API
- Endpoint: GET `https://crt.sh/?q={org_name}&output=json`
- No API key needed
- Returns certificates issued to the organization
- Can search by org name or domain to find affiliated domains

## Approach
1. SecurityTrails associated domains (most reliable, uses WHOIS/registrant correlation)
2. crt.sh CT log search by organization name (free, no key needed)
3. LLM knowledge for well-known affiliations
4. Deduplicate and score results
