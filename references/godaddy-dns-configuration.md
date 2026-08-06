# GoDaddy DNS Configuration for aceofcloud.io

**Prepared by:** Harrison Cook — AceofCloud  
**Date:** May 15, 2026  
**Purpose:** Transfer DNS management from DigitalOcean to GoDaddy, point `aceofcloud.io` to the AWS Production environment, configure SES email sending, and implement DNSSEC.

---

## Overview

This document contains every DNS record that must be entered in GoDaddy to fully replace DigitalOcean as the DNS provider for `aceofcloud.io`. The primary change is that the apex domain (`aceofcloud.io`) will now point to the **Production AWS ALB**, making AC3 the primary application at the root domain.

> **Important:** Before changing nameservers at GoDaddy, enter ALL records below first. DNS propagation can take up to 48 hours after the nameserver change, so having records pre-populated avoids downtime.

**Access Policy:** Only `aceofcloud.io` (Production) is the publicly accessible URL for customers. `staging.aceofcloud.io` and `ac3.aceofcloud.io` are internal environments for development and testing — they should be restricted via security groups or IP allowlisting once the platform has paying customers.

---

## Step 1 — Change Nameservers

The domain `aceofcloud.io` is currently using DigitalOcean nameservers. To manage DNS directly in GoDaddy, switch back to GoDaddy's default nameservers:

1. Log in to GoDaddy and navigate to **My Products** → **aceofcloud.io** → **DNS Management**.
2. Under **Nameservers**, click **Change** and select **"GoDaddy Default"**.
3. GoDaddy will assign nameservers automatically (e.g., `ns77.domaincontrol.com` and `ns78.domaincontrol.com`).

> **Note:** If you prefer to keep using external nameservers (e.g., Route 53 in the future for DNSSEC), you can skip this step and enter these records in that DNS provider instead. The records themselves are the same regardless of provider.

---

## Step 2 — Enter DNS Records

### Complete DNS Record Table

Enter the following records in GoDaddy DNS Management. The **Name** column shows what to enter in GoDaddy's "Host" field (GoDaddy automatically appends `.aceofcloud.io`).

#### CNAME Records — AWS ALB Targets (AC3 Environments)

These point AC3 environments to their respective AWS Application Load Balancers.

| Type | Name | Value | TTL |
|------|------|-------|-----|
| CNAME | www | ac3-production-alb-1966031839.us-east-1.elb.amazonaws.com | 600 |
| CNAME | ac3 | ac3-dev-alb-1142114658.us-east-1.elb.amazonaws.com | 600 |
| CNAME | staging | ac3-staging-alb-707888130.us-east-1.elb.amazonaws.com | 600 |

> **Note:** The `www` CNAME replaces the old `app` subdomain. Combined with apex forwarding (see Step 3), `aceofcloud.io` and `www.aceofcloud.io` both reach Production.

#### CNAME Records — AWS ACM Certificate Validation

These records are **required** for AWS to issue and renew SSL certificates. Do not remove them.

| Type | Name | Value | TTL | Purpose |
|------|------|-------|-----|---------|
| CNAME | _1bcc5c09b0cac18056c92ff42ea92a25 | _f14b969291c9d06e61f2a82271178b8f.jkddzztszm.acm-validations.aws | 600 | Dev cert (aceofcloud.io + *.aceofcloud.io) |
| CNAME | _3732668466269326408f2b4ed185382c.staging | _99796e8ecef7e5a5c30005236ebb1c85.jkddzztszm.acm-validations.aws | 600 | Staging cert (staging.aceofcloud.io) |
| CNAME | _3e4ba8e2ced6a5ee9dec1b265d6ce421 | _3f4186194ea7e9e4651278cd19cc1f23.jkddzztszm.acm-validations.aws | 600 | Production wildcard cert (aceofcloud.io + *.aceofcloud.io) — **NEW, PENDING** |

> **Critical:** The Production wildcard cert (`_3e4ba8e2ced6a5ee9dec1b265d6ce421`) is currently **PENDING_VALIDATION**. It will not validate until this CNAME is resolvable from GoDaddy's nameservers. Once validated, we will update the Production ALB HTTPS listener to use this wildcard cert.

#### CNAME Records — AWS SES Email Authentication (DKIM)

These records enable DKIM signing for emails sent from `noreply@aceofcloud.io`. All three are required for SES to sign outbound emails.

| Type | Name | Value | TTL |
|------|------|-------|-----|
| CNAME | 7ow6ey2zqxlbfmjgdyqnfnqfxfpjnxhq._domainkey | 7ow6ey2zqxlbfmjgdyqnfnqfxfpjnxhq.dkim.amazonses.com | 600 |
| CNAME | gxnqe5xqo3yjqxnvpxrqyxvxnfxqjhqy._domainkey | gxnqe5xqo3yjqxnvpxrqyxvxnfxqjhqy.dkim.amazonses.com | 600 |
| CNAME | hqxnfxqjhqygxnqe5xqo3yjqxnvpxrqy._domainkey | hqxnfxqjhqygxnqe5xqo3yjqxnvpxrqy.dkim.amazonses.com | 600 |

> **Note:** The exact DKIM selector values above are placeholders — the actual values were generated during SES setup. Harrison has the real values from the SES console (Production account 184974284696, us-east-1). Check `SES → Identities → aceofcloud.io → Authentication → DKIM` for the three CNAME records.

#### MX Records — SES Custom MAIL FROM + Existing Mail

| Type | Name | Value | Priority | TTL |
|------|------|-------|----------|-----|
| MX | @ | mail.aceofcloud.io | 10 | 600 |
| MX | bounce | feedback-smtp.us-east-1.amazonses.com | 10 | 600 |

The `bounce` subdomain is the custom MAIL FROM domain for SES, which improves deliverability and SPF alignment.

#### TXT Records — SPF + DMARC

| Type | Name | Value | TTL |
|------|------|-------|-----|
| TXT | @ | v=spf1 ip4:137.184.7.224 ip4:134.199.213.248 include:amazonses.com ~all | 600 |
| TXT | bounce | v=spf1 include:amazonses.com ~all | 600 |
| TXT | _dmarc | v=DMARC1; p=quarantine; rua=mailto:dmarc@aceofcloud.io; pct=100 | 600 |

> **Important:** The SPF record now includes `include:amazonses.com` to authorize AWS SES to send email on behalf of `aceofcloud.io`. The DMARC record sets policy to `quarantine` — messages that fail DKIM+SPF alignment will be sent to spam rather than rejected outright. Tighten to `p=reject` once email delivery is confirmed working.

#### A Records — Infrastructure Servers (DigitalOcean)

These are your core infrastructure servers that remain on DigitalOcean.

| Type | Name | Value | TTL | Purpose |
|------|------|-------|-----|---------|
| A | caldera | 134.199.213.248 | 600 | MITRE Caldera C2 server |
| A | lab | 137.184.211.238 | 600 | Consolidated lab environment |
| A | logsink | 147.182.225.110 | 600 | Log aggregation |
| A | mail | 137.184.7.224 | 600 | Mail server |
| A | scan | 159.223.152.190 | 600 | Scan infrastructure |
| A | scanforge | 137.184.71.192 | 600 | ScanForge scanner |

---

### Records REMOVED (Redundant Test Labs)

The following records existed in DigitalOcean but are **redundant** — they are duplicate entries for the same vulnerable applications that are already accessible through the consolidated `lab.aceofcloud.io` server. Do NOT recreate these:

| Type | Name | Old Value | Reason to Skip |
|------|------|-----------|----------------|
| A | dvwa | 159.223.152.190 | Duplicate — accessible via lab.aceofcloud.io |
| A | dvwa.lab | 137.184.211.238 | Duplicate — accessible via lab.aceofcloud.io |
| A | dvga | 159.223.152.190 | Duplicate — accessible via lab.aceofcloud.io |
| A | hackazon | 159.223.152.190 | Duplicate — accessible via lab.aceofcloud.io |
| A | juice-shop | 159.223.152.190 | Duplicate — same as juiceshop |
| A | juiceshop | 159.223.152.190 | Duplicate — accessible via lab.aceofcloud.io |
| A | juiceshop.lab | 137.184.211.238 | Duplicate — accessible via lab.aceofcloud.io |
| A | mutillidae | 159.223.152.190 | Duplicate — accessible via lab.aceofcloud.io |
| A | mutillidae.lab | 137.184.211.238 | Duplicate — accessible via lab.aceofcloud.io |
| A | vampi | 159.223.152.190 | Duplicate — accessible via lab.aceofcloud.io |
| A | webgoat | 159.223.152.190 | Duplicate — accessible via lab.aceofcloud.io |
| A | webgoat.lab | 137.184.211.238 | Duplicate — accessible via lab.aceofcloud.io |
| A | brokencrystals.lab | 137.184.211.238 | Duplicate — accessible via lab.aceofcloud.io |
| CNAME | c3 | ace-c3-dashboard-aun7k.ondigitalocean.app | Legacy DO App Platform — replaced by AWS |
| CNAME | dashboard | ace-c3-dashboard-aun7k.ondigitalocean.app | Legacy DO App Platform — replaced by AWS |
| CNAME | app | ac3-production-alb-... | Replaced by `www` + apex forwarding |
| A | @ | 172.66.0.96 | Old Cloudflare IPs — replaced by forwarding |
| A | @ | 162.159.140.98 | Old Cloudflare IPs — replaced by forwarding |
| AAAA | @ | 2a06:98c1:58::60 | Old Cloudflare IPv6 — replaced by forwarding |
| AAAA | @ | 2606:4700:7::60 | Old Cloudflare IPv6 — replaced by forwarding |

---

## Step 3 — Set Up Apex Forwarding

Since GoDaddy does not support CNAME records at the apex (`@`), configure domain forwarding so that `aceofcloud.io` redirects to `https://www.aceofcloud.io` (which CNAMEs to the Production ALB):

1. In GoDaddy DNS Management, go to the **Forwarding** section at the bottom.
2. Click **Add** under **Domain**.
3. Configure:
   - **Forward to:** `https://www.aceofcloud.io`
   - **Redirect type:** **Permanent (301)**
   - **Forward settings:** **Forward only** (not masking)
4. Save.

This means:
- `aceofcloud.io` → 301 redirect → `https://www.aceofcloud.io` → CNAME → Production ALB → AC3 login page
- `www.aceofcloud.io` → CNAME → Production ALB → AC3 login page (direct, no redirect)

---

## Step 4 — Enable DNSSEC

DNSSEC adds cryptographic signatures to DNS records, preventing DNS spoofing and cache poisoning attacks. This is a FedRAMP requirement (SC-20, SC-21) and a pentest finding if missing.

### Option A — GoDaddy-Managed DNSSEC (Simplest, Use This for Now)

If using GoDaddy's own nameservers, DNSSEC is a simple toggle:

1. In GoDaddy, go to **My Domains** → **aceofcloud.io** → **DNS Management**.
2. Click the **"..."** (three-dot menu) and select **DNSSEC**.
3. Toggle DNSSEC **ON**.
4. GoDaddy handles zone signing and DS record submission to the `.io` registry automatically.

> **Limitation:** GoDaddy's auto-DNSSEC works only when using GoDaddy nameservers. If you later migrate to Route 53, you must manually configure DNSSEC (see Option B).

### Option B — Route 53 DNSSEC (Recommended Long-Term)

If/when DNS is migrated to Route 53 for ALIAS record support:

1. **Enable DNSSEC signing** in Route 53 → Hosted Zone → `aceofcloud.io` → DNSSEC signing → Enable.
2. Route 53 will generate a KSK (Key Signing Key) and provide DS record details.
3. **Add DS record in GoDaddy** (registrar level, NOT DNS records):
   - Go to GoDaddy → My Domains → aceofcloud.io → DNS Management → "..." → DNSSEC
   - Click **Add** and enter the values from Route 53:
     - **Key Tag:** (from Route 53)
     - **Algorithm:** (from Route 53, typically 13 = ECDSAP256SHA256)
     - **Digest Type:** (from Route 53, typically 2 = SHA-256)
     - **Digest:** (from Route 53)
4. Save. The `.io` registry will publish the DS record, establishing the chain of trust.
5. **Convert all CNAME records for ALBs to A (Alias) records** in Route 53 — this is required because CNAME chains break DNSSEC verification (AWS doesn't sign `amazonaws.com` zones).

### Verification

After enabling DNSSEC, verify using these tools:
- https://dnssec-analyzer.verisignlabs.com — enter `aceofcloud.io`
- https://dnsviz.net — visual DNSSEC chain analysis

All checks should show green/valid. Subdomains pointing to ALBs via CNAME will show warnings about unsigned `amazonaws.com` — this is expected and only fully resolved by migrating to Route 53 with Alias records.

---

## Step 5 — Verification Checklist

After entering all records and changing nameservers, verify the following (allow up to 48 hours for full propagation, but most records propagate within 15-30 minutes):

| Test | Expected Result | Command |
|------|----------------|---------|
| `aceofcloud.io` in browser | Redirects to `https://www.aceofcloud.io`, shows **AC3 login page** | Browse to http://aceofcloud.io |
| `www.aceofcloud.io` | Shows **AC3 login page** (requires authentication to access dashboard) | Browse to https://www.aceofcloud.io |
| `ac3.aceofcloud.io` | Shows **AC3 login page** (Dev environment) | Browse to https://ac3.aceofcloud.io |
| `staging.aceofcloud.io` | Shows **AC3 login page** (Staging environment) | Browse to https://staging.aceofcloud.io |
| `caldera.aceofcloud.io` | Caldera server responds | Browse to http://caldera.aceofcloud.io |
| `scanforge.aceofcloud.io` | ScanForge server responds | Browse to http://scanforge.aceofcloud.io |
| Mail delivery | SPF passes, DKIM valid, mail.aceofcloud.io resolves | Send test from noreply@aceofcloud.io |
| DMARC | `dig TXT _dmarc.aceofcloud.io` returns policy | `dig TXT _dmarc.aceofcloud.io` |
| ACM cert validation | Production wildcard cert status → ISSUED | Check AWS ACM console (184974284696) |
| DNSSEC | All green at verisignlabs.com | https://dnssec-analyzer.verisignlabs.com |

> **Important:** All AC3 URLs (`www.aceofcloud.io`, `ac3.aceofcloud.io`, `staging.aceofcloud.io`) should show the **login page** — not the dashboard. Authentication is enforced on all pages. No data is accessible without logging in.

---

## Environment Summary After Migration

| Environment | URL | AWS Account | Access |
|-------------|-----|-------------|--------|
| **Production** | `aceofcloud.io` / `www.aceofcloud.io` | 184974284696 | Public (customers) |
| **Dev** | `ac3.aceofcloud.io` | 808038814732 | Internal (restrict later) |
| **Staging** | `staging.aceofcloud.io` | 238043187472 | Internal (restrict later) |

---

## Post-Migration: Update Production ALB Cert

Once the new Production wildcard cert (`arn:aws:acm:us-east-1:184974284696:certificate/12b1df70-3a15-4850-930a-60fc6550d90c`) validates and shows status **ISSUED**, update the Production ALB HTTPS listener:

```bash
source /home/ubuntu/aws-env-production.sh

# Get the HTTPS listener ARN
HTTPS_LISTENER=$(aws elbv2 describe-listeners \
  --load-balancer-arn $(aws elbv2 describe-load-balancers --names ac3-production-alb \
    --query 'LoadBalancers[0].LoadBalancerArn' --output text) \
  --query 'Listeners[?Port==`443`].ListenerArn' --output text)

# Update to use the wildcard cert
aws elbv2 modify-listener \
  --listener-arn "$HTTPS_LISTENER" \
  --certificates CertificateArn=arn:aws:acm:us-east-1:184974284696:certificate/12b1df70-3a15-4850-930a-60fc6550d90c
```

---

## Future Consideration: Route 53 Migration

If GoDaddy's apex forwarding proves unreliable or adds latency, the recommended long-term solution is to migrate DNS to **AWS Route 53**. Benefits include:

- **ALIAS records at apex** — `aceofcloud.io` resolves directly to ALB with zero redirect
- **Full DNSSEC support** — proper chain of trust with Alias records (no CNAME issues)
- **Health checks** — automatic failover between environments
- **Cost:** approximately $0.50/month per hosted zone + $0.40 per million queries

This would also eliminate the DNSSEC limitation where CNAME records to `amazonaws.com` show unsigned zone warnings.
