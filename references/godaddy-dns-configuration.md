# GoDaddy DNS Configuration for aceofcloud.io

**Prepared by:** Harrison Cook — AceofCloud  
**Date:** May 15, 2026  
**Purpose:** Transfer DNS management from DigitalOcean to GoDaddy and point `aceofcloud.io` to the AWS Production environment.

---

## Overview

This document contains every DNS record that must be entered in GoDaddy to fully replace DigitalOcean as the DNS provider for `aceofcloud.io`. The primary change is that the apex domain (`aceofcloud.io`) will now point to the **Production AWS ALB**, making AC3 the primary application at the root domain. All existing subdomains for lab environments, scanning infrastructure, and mail are preserved.

> **Important:** Before changing nameservers at GoDaddy, enter ALL records below first. DNS propagation can take up to 48 hours after the nameserver change, so having records pre-populated avoids downtime.

---

## Step 1 — Change Nameservers

The domain `aceofcloud.io` is currently using DigitalOcean nameservers. To manage DNS directly in GoDaddy, switch back to GoDaddy's default nameservers:

1. Log in to GoDaddy and navigate to **My Products** → **aceofcloud.io** → **DNS Management**.
2. Under **Nameservers**, click **Change** and select **"I'll use my own nameservers"** or switch back to **"GoDaddy Default"**.
3. If using GoDaddy defaults, the nameservers will be something like `ns77.domaincontrol.com` and `ns78.domaincontrol.com` (GoDaddy assigns these automatically).

> **Note:** If you prefer to keep using external nameservers (e.g., Route 53 in the future), you can skip this step and enter these records in that DNS provider instead. The records themselves are the same regardless of provider.

---

## Step 2 — Enter DNS Records

### Apex Domain Records (aceofcloud.io → Production ALB)

GoDaddy does not support ALIAS/ANAME records at the apex, so you must use an **A record with Forwarding** or a **CNAME flattening** workaround. The simplest approach for GoDaddy is to use their **Forwarding** feature or an **A record** pointing to the ALB IPs. However, since ALB IPs change, the recommended approach is:

**Option A — Use GoDaddy's Domain Forwarding (Simplest)**

1. Go to **Forwarding** → **Domain** → Add forwarding.
2. Forward `aceofcloud.io` to `https://ac3.aceofcloud.io` with **301 Permanent** redirect and **Forward only** (not masking).
3. Keep the `ac3` CNAME pointing to the Production ALB.

**Option B — Use a CNAME for `www` + Redirect Apex (Recommended)**

Since GoDaddy cannot CNAME an apex, use this two-part approach:

1. Set up a **CNAME** for `www` pointing to the Production ALB.
2. Use GoDaddy's built-in **Domain Forwarding** to redirect `aceofcloud.io` → `https://www.aceofcloud.io`.
3. The HTTPS cert on the ALB already covers `*.aceofcloud.io` via the wildcard cert.

**Option C — A Records with ALB IP Lookup (Not Recommended)**

ALB IPs are dynamic and will change without notice. Only use this as a temporary measure. Current resolved IPs for the Production ALB are not static and should not be hardcoded.

---

### Complete DNS Record Table

Enter the following records in GoDaddy DNS Management. The **Name** column shows what to enter in GoDaddy's "Host" field (GoDaddy automatically appends `.aceofcloud.io`).

#### A Records (Subdomains Pointing to DigitalOcean Droplets)

These are your existing infrastructure servers that remain on DigitalOcean.

| Type | Name | Value | TTL |
|------|------|-------|-----|
| A | brokencrystals.lab | 137.184.211.238 | 600 |
| A | caldera | 134.199.213.248 | 600 |
| A | dvga | 159.223.152.190 | 600 |
| A | dvwa | 159.223.152.190 | 600 |
| A | dvwa.lab | 137.184.211.238 | 600 |
| A | hackazon | 159.223.152.190 | 600 |
| A | juice-shop | 159.223.152.190 | 600 |
| A | juiceshop | 159.223.152.190 | 600 |
| A | juiceshop.lab | 137.184.211.238 | 600 |
| A | lab | 137.184.211.238 | 600 |
| A | logsink | 147.182.225.110 | 600 |
| A | mail | 137.184.7.224 | 600 |
| A | mutillidae | 159.223.152.190 | 600 |
| A | mutillidae.lab | 137.184.211.238 | 600 |
| A | scan | 159.223.152.190 | 600 |
| A | scanforge | 137.184.71.192 | 600 |
| A | vampi | 159.223.152.190 | 600 |
| A | webgoat | 159.223.152.190 | 600 |
| A | webgoat.lab | 137.184.211.238 | 600 |

#### CNAME Records (AWS ALB Targets)

These point AC3 environments to their respective AWS Application Load Balancers.

| Type | Name | Value | TTL |
|------|------|-------|-----|
| CNAME | www | ac3-production-alb-1966031839.us-east-1.elb.amazonaws.com | 600 |
| CNAME | ac3 | ac3-dev-alb-1142114658.us-east-1.elb.amazonaws.com | 600 |
| CNAME | staging | ac3-staging-alb-707888130.us-east-1.elb.amazonaws.com | 600 |

> **Note:** The `www` CNAME replaces the old `app` subdomain. Combined with apex forwarding (see Step 3), `aceofcloud.io` and `www.aceofcloud.io` both reach Production. The old `c3` and `dashboard` CNAMEs pointed to the legacy DigitalOcean App Platform deployment and are no longer needed.

#### CNAME Records (AWS ACM Certificate Validation)

These records are **required** for AWS to issue and renew SSL certificates. Do not remove them.

| Type | Name | Value | TTL | Purpose |
|------|------|-------|-----|---------|
| CNAME | _1bcc5c09b0cac18056c92ff42ea92a25 | _f14b969291c9d06e61f2a82271178b8f.jkddzztszm.acm-validations.aws | 600 | Dev cert (aceofcloud.io + *.aceofcloud.io) |
| CNAME | _3732668466269326408f2b4ed185382c.staging | _99796e8ecef7e5a5c30005236ebb1c85.jkddzztszm.acm-validations.aws | 600 | Staging cert (staging.aceofcloud.io) |
| CNAME | _3e4ba8e2ced6a5ee9dec1b265d6ce421 | _3f4186194ea7e9e4651278cd19cc1f23.jkddzztszm.acm-validations.aws | 600 | Production cert (aceofcloud.io + *.aceofcloud.io) |

> **Critical:** The Production wildcard cert (`_3e4ba8e2ced6a5ee9dec1b265d6ce421`) is **new** and currently PENDING_VALIDATION. It will not validate until this CNAME is resolvable from GoDaddy's nameservers. Once validated, we will update the Production ALB HTTPS listener to use this wildcard cert instead of the `app.aceofcloud.io` cert.

#### MX Record (Mail)

| Type | Name | Value | Priority | TTL |
|------|------|-------|----------|-----|
| MX | @ | mail.aceofcloud.io | 10 | 600 |

#### TXT Record (SPF)

| Type | Name | Value | TTL |
|------|------|-------|-----|
| TXT | @ | v=spf1 ip4:137.184.7.224 ip4:134.199.213.248 ~all | 600 |

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
- `aceofcloud.io` → 301 redirect → `https://www.aceofcloud.io` → CNAME → Production ALB → AC3 Production
- `www.aceofcloud.io` → CNAME → Production ALB → AC3 Production (direct, no redirect)

> **Alternative:** If GoDaddy's forwarding adds unwanted latency, consider migrating DNS to AWS Route 53 in the future. Route 53 supports ALIAS records at the apex, which resolve directly to ALB DNS names without a redirect hop.

---

## Step 4 — Records to NOT Migrate (Deprecated)

The following records existed in DigitalOcean but should **not** be recreated in GoDaddy because they point to the old DigitalOcean App Platform deployment that is being decommissioned:

| Type | Name | Old Value | Reason to Skip |
|------|------|-----------|----------------|
| CNAME | c3 | ace-c3-dashboard-aun7k.ondigitalocean.app | Legacy DO App Platform — replaced by AWS |
| CNAME | dashboard | ace-c3-dashboard-aun7k.ondigitalocean.app | Legacy DO App Platform — replaced by AWS |
| CNAME | app | ac3-production-alb-1966031839.us-east-1.elb.amazonaws.com | Replaced by `www` + apex forwarding |
| CNAME | _87bf461938531f73e3a25445e098340c.app | _59cc9fe0364a4971094ff9d6db545c29.jkddzztszm.acm-validations.aws | ACM cert for app.aceofcloud.io — replaced by wildcard cert |
| A | @ | 172.66.0.96 | Cloudflare IPs for old website — replaced by forwarding |
| A | @ | 162.159.140.98 | Cloudflare IPs for old website — replaced by forwarding |
| AAAA | @ | 2a06:98c1:58::60 | Cloudflare IPv6 — replaced by forwarding |
| AAAA | @ | 2606:4700:7::60 | Cloudflare IPv6 — replaced by forwarding |

---

## Step 5 — Verification Checklist

After entering all records and changing nameservers, verify the following (allow up to 48 hours for full propagation, but most records propagate within 15-30 minutes):

| Test | Expected Result | Command |
|------|----------------|---------|
| `aceofcloud.io` in browser | Redirects to `https://www.aceofcloud.io`, shows AC3 login | Browse to http://aceofcloud.io |
| `www.aceofcloud.io` | AC3 Production dashboard loads over HTTPS | Browse to https://www.aceofcloud.io |
| `ac3.aceofcloud.io` | AC3 Dev dashboard loads over HTTPS | Browse to https://ac3.aceofcloud.io |
| `staging.aceofcloud.io` | AC3 Staging dashboard loads over HTTPS | Browse to https://staging.aceofcloud.io |
| `caldera.aceofcloud.io` | Caldera server responds | Browse to http://caldera.aceofcloud.io |
| `scanforge.aceofcloud.io` | ScanForge server responds | Browse to http://scanforge.aceofcloud.io |
| Mail delivery | SPF passes, mail.aceofcloud.io resolves | Send test email |
| ACM cert validation | Production wildcard cert status changes to ISSUED | Check AWS ACM console in account 184974284696 |

---

## Environment Summary After Migration

| Environment | URL | AWS Account | Infrastructure |
|-------------|-----|-------------|----------------|
| **Production** | `aceofcloud.io` / `www.aceofcloud.io` | 184974284696 | ECS Fargate + RDS MySQL + ALB |
| **Dev** | `ac3.aceofcloud.io` | 808038814732 | ECS Fargate + RDS MySQL + ALB |
| **Staging** | `staging.aceofcloud.io` | 238043187472 | ECS Fargate + RDS MySQL + ALB |

---

## Post-Migration: Update Production ALB Cert

Once the new Production wildcard cert (`arn:aws:acm:us-east-1:184974284696:certificate/12b1df70-3a15-4850-930a-60fc6550d90c`) validates and shows status **ISSUED**, update the Production ALB HTTPS listener to use it instead of the `app.aceofcloud.io` cert. Harrison can run:

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

This ensures the ALB serves a valid cert for both `aceofcloud.io` and `www.aceofcloud.io`.

---

## Future Consideration: Route 53

If GoDaddy's apex forwarding proves unreliable or adds latency, the recommended long-term solution is to migrate DNS to **AWS Route 53**. Route 53 supports **ALIAS records** at the apex, which resolve directly to ALB DNS names without any redirect. This would allow `aceofcloud.io` to resolve directly to the Production ALB with zero redirect overhead. The cost is approximately $0.50/month per hosted zone plus $0.40 per million queries.
