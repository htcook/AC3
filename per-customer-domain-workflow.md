# Per-Customer Phishing Domain Workflow

**Author:** Harrison Cook — AceofCloud  
**Version:** 1.0 | February 2026  
**Classification:** Internal Operations Guide

---

## 1. Overview

This document describes the end-to-end process for provisioning a unique phishing domain for each customer engagement. Using a dedicated domain per customer isolates reputation risk, prevents cross-contamination between campaigns, and produces cleaner deliverables for the client. The workflow assumes the infrastructure stack already running on the AceofCloud Caldera server (137.184.7.224): GoPhish for campaign orchestration, Brevo for SMTP relay, Namecheap for domain registration, and DigitalOcean for hosting.

---

## 2. Infrastructure Reference

| Component | Location | Purpose |
|-----------|----------|---------|
| GoPhish Admin | https://gophish.aceofcloud.io | Campaign management, landing pages, email templates |
| Caldera C2 | https://caldera.aceofcloud.io | Red team operations, agent management |
| C3 Dashboard | https://dashboard.aceofcloud.io | Centralized monitoring and reporting |
| Brevo SMTP | smtp-relay.brevo.com:2525 | Authenticated email relay |
| Namecheap | namecheap.com | Domain registration and DNS management |
| DigitalOcean | 137.184.7.224 | Server hosting, nginx reverse proxy, Let's Encrypt |

---

## 3. Domain Selection Guidelines

When choosing a customer-specific phishing domain, the goal is to select something that appears plausible to the target organization's employees. The following principles should guide domain selection.

**Naming conventions that work well:**

- Mimic the customer's internal tooling names (e.g., `acme-sso-portal.com` for a company called Acme)
- Use common corporate patterns: `{company}-login.com`, `{company}portal.net`, `secure-{company}.io`
- Leverage topical pretexts: `{company}-benefits2026.com`, `{company}-payroll-update.com`
- Avoid exact trademark matches — the domain should be convincing but not infringing

**Domain registrar considerations:**

- Register through Namecheap (existing account: tazewellcook) for consistency
- Enable WhoisGuard privacy protection on every domain
- Choose `.com`, `.io`, or `.net` TLDs — these carry the highest trust with targets
- Avoid newly created gTLDs (`.xyz`, `.click`) which are frequently flagged by email filters

---

## 4. Step-by-Step Domain Provisioning

### 4.1 Register the Domain

1. Log in to Namecheap at https://ap.www.namecheap.com
2. Search for and purchase the desired domain
3. Enable WhoisGuard privacy protection
4. Keep Namecheap's default nameservers (registrar-servers.com)

### 4.2 Configure DNS Records

Navigate to **Domain List → [domain] → Advanced DNS** and add the following records:

| Type | Host | Value | TTL |
|------|------|-------|-----|
| A | @ | 137.184.7.224 | Automatic |
| A | mail | 137.184.7.224 | Automatic |
| MX | @ | mail.[domain] (priority 10) | Automatic |
| TXT | @ | `v=spf1 ip4:137.184.7.224 include:sendinblue.com ~all` | Automatic |
| TXT | _dmarc | `v=DMARC1; p=none; rua=mailto:dmarc@[domain]` | Automatic |

> **Note:** The SPF record includes `sendinblue.com` because Brevo (formerly Sendinblue) is the SMTP relay. This authorizes Brevo to send on behalf of the domain.

### 4.3 Generate DKIM Keys

SSH into the server and generate a DKIM key pair for the new domain:

```bash
ssh -i ~/.ssh/caldera_key root@137.184.7.224

# Install opendkim-tools if not already present
apt-get install -y opendkim-tools

# Create directory for the domain's keys
mkdir -p /etc/opendkim/keys/[domain]

# Generate 2048-bit DKIM key
opendkim-genkey -b 2048 -d [domain] -D /etc/opendkim/keys/[domain] -s mail -v

# View the public key for DNS
cat /etc/opendkim/keys/[domain]/mail.txt
```

Add the DKIM public key as a TXT record in Namecheap:

| Type | Host | Value | TTL |
|------|------|-------|-----|
| TXT | mail._domainkey | `v=DKIM1; h=sha256; k=rsa; p=[PUBLIC_KEY]` | Automatic |

### 4.4 Register Domain in Brevo

1. Log in to Brevo at https://app.brevo.com
2. Navigate to **Settings → Senders, domains, IPs → Domains**
3. Click **Add a domain** and enter the new domain name
4. Select **Authenticate the domain yourself**
5. Add the two DKIM CNAME records Brevo provides:

| Type | Host | Value |
|------|------|-------|
| CNAME | brevo1._domainkey | b1.[domain-with-dashes].dkim.brevo.com |
| CNAME | brevo2._domainkey | b2.[domain-with-dashes].dkim.brevo.com |

6. Add the Brevo verification TXT record:

| Type | Host | Value |
|------|------|-------|
| TXT | @ | brevo-code:[verification-code] |

7. Click **Authenticate** — Brevo will verify the DNS records

### 4.5 Obtain Let's Encrypt SSL Certificate

SSH into the server and request a certificate for the new domain:

```bash
ssh -i ~/.ssh/caldera_key root@137.184.7.224

# Request certificate (DNS must already point to 137.184.7.224)
certbot certonly --nginx -d [domain] -d mail.[domain] --non-interactive --agree-tos -m admin@aceofcloud.io
```

### 4.6 Configure Nginx Virtual Host

Create an nginx configuration file for the new domain:

```bash
cat > /etc/nginx/sites-available/[domain] << 'NGINX'
server {
    listen 80;
    server_name [domain] mail.[domain];
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name [domain];

    ssl_certificate /etc/letsencrypt/live/[domain]/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/[domain]/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # GoPhish phishing server (landing pages)
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
NGINX

# Enable the site
ln -sf /etc/nginx/sites-available/[domain] /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

> **Important:** The domain proxies to GoPhish's phishing server on port 8080, not the admin panel. This is what targets will see when they click phishing links.

### 4.7 Configure GoPhish Sending Profile

1. Open GoPhish Admin at https://gophish.aceofcloud.io
2. Navigate to **Sending Profiles → New Profile**
3. Configure the SMTP settings:

| Field | Value |
|-------|-------|
| Name | [Customer Name] - Brevo SMTP |
| Interface Type | SMTP |
| From | `IT Support <support@[domain]>` |
| Host | smtp-relay.brevo.com:2525 |
| Username | harrison.cook@gmail.com |
| Password | [Brevo SMTP key] |
| Ignore Certificate Errors | Unchecked |

4. Click **Send Test Email** to verify delivery

### 4.8 Create GoPhish Campaign

1. **Email Template:** Create a template matching the customer's pretext (password reset, benefits enrollment, IT notification)
2. **Landing Page:** Clone the target's login page or create a credential harvesting page
3. **User Group:** Import the target email list
4. **Campaign:** Link the sending profile, template, landing page, and user group
5. Set the **URL** to `https://[domain]` so all phishing links point to the customer-specific domain

---

## 5. Post-Engagement Cleanup

After the engagement concludes, perform the following cleanup steps to maintain operational hygiene:

1. **Export results** from GoPhish (CSV + JSON) and archive in the customer's project folder
2. **Delete the campaign** and associated landing pages from GoPhish
3. **Remove the nginx virtual host:**
   ```bash
   rm /etc/nginx/sites-enabled/[domain]
   rm /etc/nginx/sites-available/[domain]
   nginx -t && systemctl reload nginx
   ```
4. **Revoke the SSL certificate:**
   ```bash
   certbot revoke --cert-path /etc/letsencrypt/live/[domain]/fullchain.pem
   certbot delete --cert-name [domain]
   ```
5. **Remove the domain from Brevo** (Settings → Domains → Delete)
6. **Optionally let the domain expire** at Namecheap, or transfer it to the customer if requested

---

## 6. Automation Script

The following script automates steps 4.2 through 4.6 for rapid domain provisioning. Save it on the server as `/root/provision-phish-domain.sh`:

```bash
#!/bin/bash
# Usage: ./provision-phish-domain.sh <domain>
# Prerequisites: DNS A records must already point to this server

set -euo pipefail

DOMAIN="${1:?Usage: $0 <domain>}"
EMAIL="admin@aceofcloud.io"

echo "=== Provisioning phishing domain: $DOMAIN ==="

# Step 1: Obtain Let's Encrypt certificate
echo "[1/3] Requesting SSL certificate..."
certbot certonly --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL"

# Step 2: Create nginx virtual host
echo "[2/3] Configuring nginx..."
cat > "/etc/nginx/sites-available/$DOMAIN" << NGINX
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
NGINX

ln -sf "/etc/nginx/sites-available/$DOMAIN" "/etc/nginx/sites-enabled/"
nginx -t && systemctl reload nginx

# Step 3: Generate DKIM keys
echo "[3/3] Generating DKIM keys..."
mkdir -p "/etc/opendkim/keys/$DOMAIN"
opendkim-genkey -b 2048 -d "$DOMAIN" -D "/etc/opendkim/keys/$DOMAIN" -s mail -v 2>/dev/null || true

echo ""
echo "=== Domain $DOMAIN provisioned ==="
echo ""
echo "Remaining manual steps:"
echo "  1. Add DNS records in Namecheap (A, MX, SPF, DKIM, DMARC)"
echo "  2. Register domain in Brevo and add DKIM CNAME records"
echo "  3. Create GoPhish sending profile and campaign"
echo ""
echo "DKIM public key (add as TXT record for mail._domainkey.$DOMAIN):"
cat "/etc/opendkim/keys/$DOMAIN/mail.txt" 2>/dev/null || echo "  (DKIM generation skipped — install opendkim-tools)"
```

Make it executable:

```bash
chmod +x /root/provision-phish-domain.sh
```

---

## 7. DNS Record Quick Reference

For every new customer domain, the complete set of DNS records is:

| # | Type | Host | Value |
|---|------|------|-------|
| 1 | A | @ | 137.184.7.224 |
| 2 | A | mail | 137.184.7.224 |
| 3 | MX | @ | mail.[domain] (priority 10) |
| 4 | TXT | @ | `v=spf1 ip4:137.184.7.224 include:sendinblue.com ~all` |
| 5 | TXT | mail._domainkey | `v=DKIM1; h=sha256; k=rsa; p=[KEY]` |
| 6 | TXT | _dmarc | `v=DMARC1; p=none; rua=mailto:dmarc@[domain]` |
| 7 | TXT | @ | `brevo-code:[code]` |
| 8 | CNAME | brevo1._domainkey | b1.[domain-dashes].dkim.brevo.com |
| 9 | CNAME | brevo2._domainkey | b2.[domain-dashes].dkim.brevo.com |

---

## 8. Troubleshooting

**Email going to spam:**
- Verify SPF, DKIM, and DMARC records are all resolving correctly with `dig TXT [domain]`
- Check Brevo domain authentication status is green
- Ensure the "From" address domain matches the authenticated domain
- Wait 24-48 hours after DNS changes for full propagation

**SSL certificate errors:**
- Confirm the A record points to 137.184.7.224 before requesting the cert
- Check `certbot certificates` to verify the cert exists
- Ensure nginx config references the correct cert path

**GoPhish landing page not loading:**
- Verify GoPhish phishing server is running on port 8080: `ss -tlnp | grep 8080`
- Check nginx error logs: `tail -f /var/log/nginx/error.log`
- Ensure the campaign URL matches the domain exactly

---

*AceofCloud — Red Team Operations Infrastructure*  
*https://aceofcloud.com*
