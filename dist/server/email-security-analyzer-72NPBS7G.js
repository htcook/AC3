import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/email-security-analyzer.ts
import dns from "dns";
import { promisify } from "util";
function classifyMailProvider(provider) {
  if (!provider) return null;
  const details = MANAGED_PROVIDER_DETAILS[provider];
  if (!details) {
    return { name: provider, isManaged: false, tier: "self_hosted", serverSecurityNote: `Mail provider "${provider}" is not a recognized managed service. Server-level security may be the customer's responsibility.`, customerResponsibilities: ["Full mail server security stack", "SPF/DKIM/DMARC configuration", "TLS configuration", "Patching and updates"] };
  }
  return { name: provider, ...details };
}
async function analyzeSpf(domain) {
  const result = {
    exists: false,
    record: null,
    mechanisms: [],
    includes: [],
    allMechanism: null,
    weaknesses: [],
    score: 0
  };
  try {
    const txtRecords = await resolveTxt(domain);
    const spfRecords = txtRecords.map((r) => r.join("")).filter((r) => r.startsWith("v=spf1"));
    if (spfRecords.length === 0) {
      result.weaknesses.push({
        id: "spf-missing",
        severity: "critical",
        title: "No SPF Record Found",
        description: `Domain ${domain} has no SPF record. Any mail server can send email claiming to be from this domain.`,
        phishingRelevance: "Attackers can send spoofed emails from this domain with no authentication checks. Phishing campaigns can use the exact domain for impersonation."
      });
      return result;
    }
    if (spfRecords.length > 1) {
      result.weaknesses.push({
        id: "spf-multiple",
        severity: "medium",
        title: "Multiple SPF Records",
        description: `Domain has ${spfRecords.length} SPF records. RFC 7208 specifies only one SPF record per domain; multiple records cause unpredictable behavior.`,
        phishingRelevance: "Multiple SPF records can cause validation failures, meaning some receiving servers may not check SPF at all."
      });
    }
    result.exists = true;
    result.record = spfRecords[0];
    const parts = spfRecords[0].split(/\s+/).filter((p) => p !== "v=spf1");
    result.mechanisms = parts;
    result.includes = parts.filter((p) => p.startsWith("include:")).map((p) => p.replace("include:", ""));
    const allPart = parts.find((p) => p.match(/^[+\-~?]?all$/));
    if (allPart) {
      result.allMechanism = allPart;
    }
    if (!allPart) {
      result.weaknesses.push({
        id: "spf-no-all",
        severity: "high",
        title: "SPF Record Missing 'all' Mechanism",
        description: "SPF record does not end with an 'all' mechanism. Without it, unauthorized senders are not explicitly handled.",
        phishingRelevance: "Without an 'all' mechanism, there is no default policy for unauthorized senders. Spoofed emails may pass SPF checks."
      });
    } else if (allPart === "+all" || allPart === "all") {
      result.weaknesses.push({
        id: "spf-plus-all",
        severity: "critical",
        title: "SPF Record Uses '+all' (Pass All)",
        description: "SPF record ends with '+all', which means ALL servers are authorized to send email for this domain. This completely defeats SPF.",
        phishingRelevance: "Any server in the world can send email as this domain and it will pass SPF. Phishing is trivial."
      });
    } else if (allPart === "?all") {
      result.weaknesses.push({
        id: "spf-neutral-all",
        severity: "high",
        title: "SPF Record Uses '?all' (Neutral)",
        description: "SPF record ends with '?all' (neutral). This means SPF neither passes nor fails for unauthorized senders \u2014 effectively no enforcement.",
        phishingRelevance: "Neutral SPF means receiving servers get no guidance on unauthorized senders. Most will accept the email. Spoofing is easy."
      });
    } else if (allPart === "~all") {
      result.weaknesses.push({
        id: "spf-softfail-all",
        severity: "low",
        title: "SPF Record Uses '~all' (Soft Fail)",
        description: "SPF record uses '~all' (soft fail) instead of '-all' (hard fail). Soft fail marks unauthorized emails as suspicious but does not reject them.",
        phishingRelevance: "Soft fail is the most common configuration and is generally acceptable, but some receiving servers may still deliver spoofed emails to inbox rather than spam."
      });
    }
    const ipv4Ranges = parts.filter((p) => p.match(/^[+]?ip4:/));
    const broadRanges = ipv4Ranges.filter((p) => {
      const cidr = p.match(/\/(\d+)/);
      return cidr && parseInt(cidr[1]) < 16;
    });
    if (broadRanges.length > 0) {
      result.weaknesses.push({
        id: "spf-broad-ip-range",
        severity: "medium",
        title: "SPF Includes Very Broad IP Ranges",
        description: `SPF record includes broad IP ranges (${broadRanges.join(", ")}). This authorizes a large number of IP addresses to send email.`,
        phishingRelevance: "Broad IP ranges mean many servers are authorized. An attacker who controls any IP in these ranges can send authenticated email."
      });
    }
    const lookupMechanisms = parts.filter(
      (p) => p.match(/^[+\-~?]?(include|a|mx|ptr|exists|redirect)[:=]/)
    );
    if (lookupMechanisms.length > 10) {
      result.weaknesses.push({
        id: "spf-too-many-lookups",
        severity: "medium",
        title: "SPF Record Exceeds DNS Lookup Limit",
        description: `SPF record requires ${lookupMechanisms.length} DNS lookups (max 10 per RFC 7208). Excess lookups cause SPF to return 'permerror', effectively disabling it.`,
        phishingRelevance: "When SPF exceeds the lookup limit, it fails open. Receiving servers treat this as no SPF, allowing spoofing."
      });
    }
    let score = 100;
    for (const w of result.weaknesses) {
      if (w.severity === "critical") score -= 40;
      else if (w.severity === "high") score -= 25;
      else if (w.severity === "medium") score -= 15;
      else if (w.severity === "low") score -= 5;
    }
    result.score = Math.max(0, score);
  } catch (err) {
    if (err.code === "ENOTFOUND" || err.code === "ENODATA") {
      result.weaknesses.push({
        id: "spf-missing",
        severity: "critical",
        title: "No SPF Record Found",
        description: `No TXT records found for ${domain}. The domain has no SPF configuration.`,
        phishingRelevance: "Without SPF, any server can send email as this domain. Phishing campaigns can impersonate this domain trivially."
      });
    }
  }
  return result;
}
async function analyzeDkim(domain) {
  const result = {
    selectorsFound: [],
    selectorsChecked: COMMON_DKIM_SELECTORS.slice(0, 15),
    // Check top 15
    selectorResults: [],
    weaknesses: [],
    score: 50
    // Default to 50 since we can't fully verify without knowing all selectors
  };
  const checkPromises = result.selectorsChecked.map(async (selector) => {
    const dkimDomain = `${selector}._domainkey.${domain}`;
    try {
      const txtRecords = await resolveTxt(dkimDomain);
      const dkimRecord = txtRecords.map((r) => r.join("")).find((r) => r.includes("v=DKIM1") || r.includes("k=rsa") || r.includes("p="));
      if (dkimRecord) {
        const keyMatch = dkimRecord.match(/p=([A-Za-z0-9+/=]+)/);
        const keyLength = keyMatch ? Math.floor(keyMatch[1].length * 6 / 8) * 8 : 0;
        return {
          selector,
          exists: true,
          keyType: dkimRecord.includes("k=ed25519") ? "ed25519" : "rsa",
          keyLength,
          weak: keyLength > 0 && keyLength < 1024
        };
      }
    } catch {
      try {
        await resolveCname(dkimDomain);
        return { selector, exists: true, keyType: "delegated", keyLength: 0, weak: false };
      } catch {
      }
    }
    return { selector, exists: false };
  });
  result.selectorResults = await Promise.all(checkPromises);
  result.selectorsFound = result.selectorResults.filter((r) => r.exists).map((r) => r.selector);
  if (result.selectorsFound.length === 0) {
    result.weaknesses.push({
      id: "dkim-none-found",
      severity: "high",
      title: "No DKIM Selectors Found",
      description: `No DKIM records found for common selectors on ${domain}. Either DKIM is not configured or uses non-standard selectors.`,
      phishingRelevance: "Without DKIM, receiving servers cannot verify that emails were actually sent by this domain's mail servers. Spoofed emails will not be flagged by DKIM checks."
    });
    result.score = 20;
  } else {
    const weakKeys = result.selectorResults.filter((r) => r.weak);
    if (weakKeys.length > 0) {
      result.weaknesses.push({
        id: "dkim-weak-key",
        severity: "high",
        title: `Weak DKIM Key(s) Detected (${weakKeys.map((k) => k.selector).join(", ")})`,
        description: `DKIM selector(s) use RSA keys shorter than 1024 bits. Short keys can be factored, allowing attackers to sign emails as this domain.`,
        phishingRelevance: "Weak DKIM keys can be cracked, allowing attackers to forge DKIM signatures. Phishing emails would pass DKIM verification."
      });
      result.score = 40;
    } else {
      result.score = 80;
    }
  }
  return result;
}
async function analyzeDmarc(domain) {
  const result = {
    exists: false,
    record: null,
    policy: null,
    subdomainPolicy: null,
    percentage: 100,
    reportingEnabled: false,
    ruaAddresses: [],
    rufAddresses: [],
    weaknesses: [],
    score: 0
  };
  try {
    const txtRecords = await resolveTxt(`_dmarc.${domain}`);
    const dmarcRecords = txtRecords.map((r) => r.join("")).filter((r) => r.startsWith("v=DMARC1"));
    if (dmarcRecords.length === 0) {
      result.weaknesses.push({
        id: "dmarc-missing",
        severity: "critical",
        title: "No DMARC Record Found",
        description: `Domain ${domain} has no DMARC record. Without DMARC, there is no policy telling receiving servers what to do when SPF and DKIM fail.`,
        phishingRelevance: "Without DMARC, even if SPF/DKIM fail, receiving servers have no instruction to reject or quarantine the email. Spoofed emails will likely be delivered."
      });
      return result;
    }
    result.exists = true;
    result.record = dmarcRecords[0];
    const tags = /* @__PURE__ */ new Map();
    dmarcRecords[0].split(";").forEach((part) => {
      const [key, ...valueParts] = part.trim().split("=");
      if (key && valueParts.length > 0) {
        tags.set(key.trim(), valueParts.join("=").trim());
      }
    });
    result.policy = tags.get("p") || null;
    result.subdomainPolicy = tags.get("sp") || result.policy;
    result.percentage = parseInt(tags.get("pct") || "100", 10);
    const rua = tags.get("rua");
    const ruf = tags.get("ruf");
    if (rua) result.ruaAddresses = rua.split(",").map((a) => a.trim());
    if (ruf) result.rufAddresses = ruf.split(",").map((a) => a.trim());
    result.reportingEnabled = !!(rua || ruf);
    if (result.policy === "none") {
      result.weaknesses.push({
        id: "dmarc-policy-none",
        severity: "high",
        title: "DMARC Policy Set to 'none' (Monitor Only)",
        description: "DMARC policy is 'none', which means receiving servers will not take any action on emails that fail authentication. This is a monitoring-only configuration.",
        phishingRelevance: "With p=none, spoofed emails that fail SPF and DKIM will still be delivered normally. The domain owner only receives reports but emails are not blocked."
      });
    } else if (result.policy === "quarantine") {
      result.weaknesses.push({
        id: "dmarc-policy-quarantine",
        severity: "low",
        title: "DMARC Policy Set to 'quarantine'",
        description: "DMARC policy is 'quarantine', which sends failing emails to spam/junk. This is good but not as strong as 'reject'.",
        phishingRelevance: "Quarantine means spoofed emails go to spam, but users who check spam folders may still see and interact with phishing emails."
      });
    }
    if (result.subdomainPolicy === "none" && result.policy !== "none") {
      result.weaknesses.push({
        id: "dmarc-subdomain-none",
        severity: "medium",
        title: "DMARC Subdomain Policy is 'none'",
        description: `Main domain has DMARC policy '${result.policy}' but subdomain policy is 'none'. Attackers can spoof subdomains (e.g., mail.${domain}, hr.${domain}).`,
        phishingRelevance: "Attackers can send phishing emails from subdomains like hr.${domain} or it.${domain} without being blocked by DMARC."
      });
    }
    if (result.percentage < 100) {
      result.weaknesses.push({
        id: "dmarc-low-percentage",
        severity: "medium",
        title: `DMARC Only Applied to ${result.percentage}% of Emails`,
        description: `DMARC pct tag is set to ${result.percentage}%, meaning only ${result.percentage}% of failing emails are subject to the policy. The remaining ${100 - result.percentage}% are treated as p=none.`,
        phishingRelevance: `${100 - result.percentage}% of spoofed emails will bypass DMARC enforcement. Attackers can send multiple attempts knowing some will get through.`
      });
    }
    if (!result.reportingEnabled) {
      result.weaknesses.push({
        id: "dmarc-no-reporting",
        severity: "low",
        title: "DMARC Reporting Not Configured",
        description: "No rua or ruf addresses configured. The domain owner will not receive reports about authentication failures.",
        phishingRelevance: "Without DMARC reports, the organization has no visibility into spoofing attempts against their domain. They won't know if they're being impersonated."
      });
    }
    let score = 100;
    for (const w of result.weaknesses) {
      if (w.severity === "critical") score -= 40;
      else if (w.severity === "high") score -= 25;
      else if (w.severity === "medium") score -= 15;
      else if (w.severity === "low") score -= 5;
    }
    result.score = Math.max(0, score);
  } catch (err) {
    if (err.code === "ENOTFOUND" || err.code === "ENODATA") {
      result.weaknesses.push({
        id: "dmarc-missing",
        severity: "critical",
        title: "No DMARC Record Found",
        description: `No DMARC record found at _dmarc.${domain}.`,
        phishingRelevance: "Without DMARC, receiving servers have no policy for handling authentication failures. Spoofed emails will be delivered."
      });
    }
  }
  return result;
}
async function analyzeMx(domain) {
  const result = {
    records: [],
    provider: null,
    supportsStartTls: null,
    weaknesses: []
  };
  try {
    const mxRecords = await resolveMx(domain);
    result.records = mxRecords.sort((a, b) => a.priority - b.priority).map((r) => ({ priority: r.priority, exchange: r.exchange }));
    if (result.records.length === 0) {
      result.weaknesses.push({
        id: "mx-none",
        severity: "medium",
        title: "No MX Records Found",
        description: `Domain ${domain} has no MX records. Email may still work via A record fallback, but this is unusual.`,
        phishingRelevance: "No MX records may indicate the domain doesn't receive email, but attackers can still spoof outbound email from this domain."
      });
      return result;
    }
    for (const mx of result.records) {
      const exchange = mx.exchange.toLowerCase();
      for (const [pattern, provider] of Object.entries(MAIL_PROVIDERS)) {
        if (exchange.includes(pattern)) {
          result.provider = provider;
          break;
        }
      }
      if (result.provider) break;
    }
    if (result.records.length === 1) {
      result.weaknesses.push({
        id: "mx-single",
        severity: "info",
        title: "Single MX Record (No Redundancy)",
        description: "Only one MX record configured. If this server goes down, email delivery will fail.",
        phishingRelevance: "Single MX means a single point of failure. During outages, legitimate emails bounce while phishing emails from other servers still work."
      });
    }
  } catch (err) {
    if (err.code === "ENOTFOUND" || err.code === "ENODATA") {
      result.weaknesses.push({
        id: "mx-none",
        severity: "medium",
        title: "No MX Records Found",
        description: `No MX records found for ${domain}.`,
        phishingRelevance: "Domain may not receive email, but outbound spoofing is still possible without proper SPF/DKIM/DMARC."
      });
    }
  }
  return result;
}
async function analyzeEmailSecurity(domain) {
  const [spf, dkim, dmarc, mx] = await Promise.all([
    analyzeSpf(domain),
    analyzeDkim(domain),
    analyzeDmarc(domain),
    analyzeMx(domain)
  ]);
  const overallScore = Math.round(
    spf.score * 0.3 + dkim.score * 0.25 + dmarc.score * 0.35 + (mx.weaknesses.length === 0 ? 100 : 70) * 0.1
  );
  const overallGrade = overallScore >= 90 ? "A" : overallScore >= 80 ? "B" : overallScore >= 60 ? "C" : overallScore >= 40 ? "D" : "F";
  const allWeaknesses = [
    ...spf.weaknesses,
    ...dkim.weaknesses,
    ...dmarc.weaknesses,
    ...mx.weaknesses
  ];
  const totalWeaknesses = allWeaknesses.length;
  const criticalWeaknesses = allWeaknesses.filter((w) => w.severity === "critical" || w.severity === "high").length;
  const phishingDifficultyRating = overallScore >= 85 ? "very_difficult" : overallScore >= 70 ? "difficult" : overallScore >= 50 ? "moderate" : overallScore >= 30 ? "easy" : "trivial";
  const phishingSummary = generatePhishingSummary(spf, dkim, dmarc, mx, phishingDifficultyRating);
  const recommendations = generateRecommendations(spf, dkim, dmarc, mx);
  const managedProvider = classifyMailProvider(mx.provider);
  return {
    domain,
    analyzedAt: (/* @__PURE__ */ new Date()).toISOString(),
    spf,
    dkim,
    dmarc,
    mx,
    overallScore,
    overallGrade,
    totalWeaknesses,
    criticalWeaknesses,
    phishingDifficultyRating,
    phishingSummary,
    recommendations,
    managedProvider
  };
}
function isMailAsset(asset) {
  const h = (asset.hostname || "").toLowerCase();
  const type = (asset.assetType || "").toLowerCase();
  const service = (asset.essentialService || "").toLowerCase();
  const mission = (asset.missionFunction || "").toLowerCase();
  const tags = (asset.tags || []).map((t) => t.toLowerCase());
  if (type === "mail_gateway" || type === "mail_server" || type === "email_server") return true;
  if (service === "email_gateway" || service === "mail_gateway" || service === "smtp_server") return true;
  if (mission === "communication_infrastructure") {
    if (/^(mail|mx|smtp|imap|pop3|exchange|owa|postfix|sendmail|mta|relay)\./i.test(h)) return true;
  }
  if (tags.includes("email") || tags.includes("mail") || tags.includes("email_infrastructure")) return true;
  if (/^(mail|mx|smtp|imap|pop3|pop|exchange|owa|postfix|sendmail|mta|relay|webmail|roundcube|horde|zimbra|dovecot|exim)[.-]/i.test(h)) return true;
  if (/\.(mail|mx|smtp)\./i.test(h)) return true;
  return false;
}
function isNonMailAsset(hostname) {
  const h = hostname.toLowerCase();
  if (/^ec2-[\d-]+\..*\.amazonaws\.com$/.test(h)) return true;
  if (/\.compute\.amazonaws\.com$/.test(h)) return true;
  if (/\.compute\.internal$/.test(h)) return true;
  if (/\.compute\.googleapis\.com$/.test(h)) return true;
  if (/\.cloudapp\.azure\.com$/.test(h)) return true;
  if (/\.azurewebsites\.net$/.test(h)) return true;
  if (/\.herokuapp\.com$/.test(h)) return true;
  if (/\.digitaloceanspaces\.com$/.test(h)) return true;
  if (/\.cloudfront\.net$/.test(h)) return true;
  if (/\.cdn\.cloudflare\.net$/.test(h)) return true;
  if (/\.akamaiedge\.net$/.test(h)) return true;
  if (/\.fastly\.net$/.test(h)) return true;
  if (/\.edgekey\.net$/.test(h)) return true;
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  if (/^\d{1,3}[.-]\d{1,3}[.-]\d{1,3}[.-]\d{1,3}[.-]/.test(h)) return true;
  if (/\.elb\.amazonaws\.com$/.test(h)) return true;
  if (/\.elasticbeanstalk\.com$/.test(h)) return true;
  if (/\.s3[.-].*\.amazonaws\.com$/.test(h)) return true;
  if (/\.s3\.amazonaws\.com$/.test(h)) return true;
  return false;
}
function generateEmailPostureFindings(domain, report) {
  const findings = [];
  if (isNonMailAsset(domain)) {
    return findings;
  }
  const hasMailInfra = report.mx.records.length > 0;
  if (!hasMailInfra) {
    return findings;
  }
  const managedProvider = report.managedProvider;
  const isManaged = managedProvider?.isManaged ?? false;
  const allWeaknesses = [
    ...report.spf.weaknesses.map((w) => ({ ...w, component: "SPF" })),
    ...report.dkim.weaknesses.map((w) => ({ ...w, component: "DKIM" })),
    ...report.dmarc.weaknesses.map((w) => ({ ...w, component: "DMARC" })),
    ...report.mx.weaknesses.map((w) => ({ ...w, component: "MX" }))
  ];
  const severityMap = {
    critical: 9.5,
    high: 7.5,
    medium: 5.5,
    low: 3,
    info: 1.5
  };
  const MX_SERVER_WEAKNESS_IDS = /* @__PURE__ */ new Set(["mx-single", "mx-none", "mx-open-relay", "mx-no-starttls"]);
  for (const w of allWeaknesses) {
    let severity = severityMap[w.severity] || 5;
    let evidenceDetail = w.description;
    let title = w.title;
    if (isManaged && w.component === "MX" && MX_SERVER_WEAKNESS_IDS.has(w.id)) {
      severity = Math.max(1, severity * 0.3);
      title = `${w.title} [Managed by ${managedProvider.name}]`;
      evidenceDetail = `${w.description}

Note: ${managedProvider.serverSecurityNote}`;
    }
    if (isManaged && (w.component === "SPF" || w.component === "DKIM" || w.component === "DMARC")) {
      evidenceDetail = `${w.description}

Mail Provider: ${managedProvider.name} (managed). Customer responsibilities: ${managedProvider.customerResponsibilities.join(", ")}.`;
    }
    findings.push({
      id: `email-${w.id}-${domain}`,
      assetRef: domain,
      category: `Email Security (${w.component})`,
      title,
      severity,
      confidence: 1,
      // DNS-verified findings are always confirmed
      evidenceDetail,
      corroborationTier: "confirmed",
      phishingRelevance: w.phishingRelevance,
      remediation: getRemediation(w.id)
    });
  }
  if (isManaged) {
    findings.push({
      id: `email-managed-provider-${domain}`,
      assetRef: domain,
      category: "Email Security (Provider)",
      title: `Mail Infrastructure Managed by ${managedProvider.name}`,
      severity: 0,
      // Informational — this is a positive finding
      confidence: 1,
      evidenceDetail: `${managedProvider.serverSecurityNote} MX records point to ${managedProvider.name} infrastructure. Server-level CVEs (e.g., Exchange, Postfix vulnerabilities) do NOT apply to this customer's risk posture. Customer responsibilities: ${managedProvider.customerResponsibilities.join(", ")}.`,
      corroborationTier: "confirmed",
      phishingRelevance: "Managed email providers typically include anti-phishing, anti-spam, and anti-malware filtering. However, DNS authentication (SPF/DKIM/DMARC) remains the customer's responsibility and directly impacts phishing campaign viability.",
      remediation: "Ensure DNS authentication records (SPF, DKIM, DMARC) are properly configured for your managed provider. Review provider-specific security settings and policies."
    });
  }
  return findings;
}
function generatePhishingSummary(spf, dkim, dmarc, mx, difficulty) {
  const parts = [];
  if (difficulty === "trivial") {
    parts.push("Email security is critically weak. Direct domain spoofing is trivial \u2014 no SPF, DKIM, or DMARC enforcement prevents impersonation.");
  } else if (difficulty === "easy") {
    parts.push("Email security has significant gaps. Domain spoofing is feasible with minimal effort.");
  } else if (difficulty === "moderate") {
    parts.push("Email security provides partial protection. Some spoofing vectors exist but basic checks are in place.");
  } else if (difficulty === "difficult") {
    parts.push("Email security is well-configured. Direct spoofing is difficult but lookalike domain attacks remain viable.");
  } else {
    parts.push("Email security is strong. Direct domain spoofing is very difficult. Phishing campaigns should focus on lookalike domains or social engineering.");
  }
  if (!spf.exists) parts.push("No SPF record \u2014 any server can send as this domain.");
  else if (spf.allMechanism === "+all") parts.push("SPF uses +all \u2014 effectively no SPF protection.");
  if (dkim.selectorsFound.length === 0) parts.push("No DKIM selectors found \u2014 email authenticity cannot be verified.");
  if (!dmarc.exists) parts.push("No DMARC policy \u2014 no enforcement on authentication failures.");
  else if (dmarc.policy === "none") parts.push("DMARC policy is 'none' \u2014 authentication failures are only monitored, not enforced.");
  if (mx.provider) {
    const providerInfo = classifyMailProvider(mx.provider);
    if (providerInfo?.isManaged) {
      parts.push(`Mail provider: ${mx.provider} (managed service \u2014 server-level security is ${mx.provider}'s responsibility). Customer controls: DNS authentication (SPF/DKIM/DMARC) and tenant configuration.`);
    } else {
      parts.push(`Mail provider: ${mx.provider}.`);
    }
  }
  return parts.join(" ");
}
function generateRecommendations(spf, dkim, dmarc, mx) {
  const recs = [];
  if (!spf.exists) recs.push("Implement SPF record with '-all' (hard fail) to prevent unauthorized email sending.");
  else if (spf.allMechanism !== "-all") recs.push("Strengthen SPF record to use '-all' (hard fail) instead of current configuration.");
  if (dkim.selectorsFound.length === 0) recs.push("Configure DKIM signing for all outbound email to enable cryptographic verification.");
  const weakDkim = dkim.selectorResults.filter((r) => r.weak);
  if (weakDkim.length > 0) recs.push(`Upgrade DKIM keys to 2048-bit RSA or Ed25519 for selectors: ${weakDkim.map((k) => k.selector).join(", ")}.`);
  if (!dmarc.exists) recs.push("Implement DMARC with at minimum p=quarantine. Start with p=none and rua reporting, then escalate to quarantine/reject.");
  else if (dmarc.policy === "none") recs.push("Escalate DMARC policy from 'none' to 'quarantine' or 'reject' to enforce authentication.");
  else if (dmarc.policy === "quarantine") recs.push("Consider upgrading DMARC policy to 'reject' for maximum protection against spoofing.");
  if (dmarc.exists && !dmarc.reportingEnabled) recs.push("Add DMARC rua/ruf reporting addresses to gain visibility into authentication failures and spoofing attempts.");
  if (dmarc.exists && dmarc.percentage < 100) recs.push(`Increase DMARC pct to 100% (currently ${dmarc.percentage}%) to enforce policy on all emails.`);
  if (dmarc.exists && dmarc.subdomainPolicy === "none" && dmarc.policy !== "none") recs.push("Set DMARC sp (subdomain policy) to match the main domain policy to prevent subdomain spoofing.");
  return recs;
}
function getRemediation(weaknessId) {
  const remediations = {
    "spf-missing": "Add an SPF TXT record: v=spf1 include:<your-mail-provider> -all",
    "spf-plus-all": "Change '+all' to '-all' in the SPF record to reject unauthorized senders.",
    "spf-neutral-all": "Change '?all' to '-all' in the SPF record.",
    "spf-softfail-all": "Consider changing '~all' to '-all' for stricter enforcement.",
    "spf-no-all": "Add '-all' at the end of the SPF record.",
    "spf-multiple": "Consolidate into a single SPF record per RFC 7208.",
    "spf-broad-ip-range": "Narrow IP ranges in SPF to only include actual mail server IPs.",
    "spf-too-many-lookups": "Reduce DNS lookups by flattening includes or using ip4/ip6 mechanisms.",
    "dkim-none-found": "Configure DKIM signing in your mail server or provider settings.",
    "dkim-weak-key": "Regenerate DKIM keys with 2048-bit RSA or Ed25519.",
    "dmarc-missing": "Add a DMARC record: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com",
    "dmarc-policy-none": "Escalate DMARC policy from p=none to p=quarantine or p=reject.",
    "dmarc-policy-quarantine": "Consider upgrading to p=reject for maximum protection.",
    "dmarc-subdomain-none": "Add sp=quarantine or sp=reject to your DMARC record.",
    "dmarc-low-percentage": "Increase pct=100 in your DMARC record.",
    "dmarc-no-reporting": "Add rua=mailto:dmarc-reports@yourdomain.com to your DMARC record.",
    "mx-none": "Configure MX records pointing to your mail server.",
    "mx-single": "Add a secondary MX record for redundancy."
  };
  return remediations[weaknessId] || "Review and remediate according to email security best practices.";
}
var resolveTxt, resolveMx, resolveCname, COMMON_DKIM_SELECTORS, MAIL_PROVIDERS, MANAGED_PROVIDER_DETAILS;
var init_email_security_analyzer = __esm({
  "server/lib/email-security-analyzer.ts"() {
    resolveTxt = promisify(dns.resolveTxt);
    resolveMx = promisify(dns.resolveMx);
    resolveCname = promisify(dns.resolveCname);
    COMMON_DKIM_SELECTORS = [
      "default",
      "google",
      "selector1",
      "selector2",
      // Microsoft 365
      "k1",
      "k2",
      "k3",
      // Mailchimp
      "s1",
      "s2",
      // Generic
      "dkim",
      "mail",
      "email",
      "mandrill",
      "mxvault",
      "protonmail",
      "everlytickey1",
      "everlytickey2",
      "smtp",
      "cm",
      "amazonses",
      "sig1",
      // Hubspot
      "pic",
      // Postmark
      "turbo-smtp"
    ];
    MAIL_PROVIDERS = {
      "google.com": "Google Workspace",
      "googlemail.com": "Google Workspace",
      "outlook.com": "Microsoft 365",
      "protection.outlook.com": "Microsoft 365",
      "pphosted.com": "Proofpoint",
      "mimecast.com": "Mimecast",
      "barracudanetworks.com": "Barracuda",
      "messagelabs.com": "Symantec/Broadcom",
      "iphmx.com": "Cisco IronPort",
      "ess.barracuda.com": "Barracuda ESS",
      "secureserver.net": "GoDaddy",
      "zoho.com": "Zoho Mail",
      "protonmail.ch": "ProtonMail",
      "mx.cloudflare.net": "Cloudflare Email",
      "mailgun.org": "Mailgun",
      "sendgrid.net": "SendGrid"
    };
    MANAGED_PROVIDER_DETAILS = {
      "Microsoft 365": {
        isManaged: true,
        tier: "enterprise",
        serverSecurityNote: "Mail server infrastructure (Exchange Online) is managed by Microsoft. Server-level CVEs, TLS configuration, relay security, and anti-spam/anti-malware are Microsoft's responsibility under their shared responsibility model. Customer risk is limited to DNS authentication settings (SPF/DKIM/DMARC) and tenant configuration.",
        customerResponsibilities: ["SPF record configuration", "DKIM signing enablement", "DMARC policy enforcement", "Tenant-level security settings", "Conditional Access policies", "Anti-phishing policy tuning"]
      },
      "Google Workspace": {
        isManaged: true,
        tier: "enterprise",
        serverSecurityNote: "Mail server infrastructure (Gmail) is managed by Google. Server-level CVEs, TLS, and relay security are Google's responsibility. Customer risk is limited to DNS authentication settings (SPF/DKIM/DMARC) and Workspace admin console configuration.",
        customerResponsibilities: ["SPF record configuration", "DKIM signing enablement", "DMARC policy enforcement", "Workspace admin security settings", "Advanced Protection enrollment"]
      },
      "Proofpoint": {
        isManaged: true,
        tier: "enterprise",
        serverSecurityNote: "Mail is routed through Proofpoint's cloud email security gateway. Server-level security is Proofpoint's responsibility. Customer manages DNS settings and Proofpoint policy configuration.",
        customerResponsibilities: ["SPF record configuration", "DKIM signing", "DMARC policy", "Proofpoint policy tuning", "Quarantine management"]
      },
      "Mimecast": {
        isManaged: true,
        tier: "enterprise",
        serverSecurityNote: "Mail is routed through Mimecast's cloud email security platform. Server-level security is Mimecast's responsibility.",
        customerResponsibilities: ["SPF record configuration", "DKIM signing", "DMARC policy", "Mimecast policy configuration"]
      },
      "Barracuda": {
        isManaged: true,
        tier: "business",
        serverSecurityNote: "Mail is filtered through Barracuda's email security gateway. Server-level security is managed by Barracuda.",
        customerResponsibilities: ["SPF record configuration", "DKIM signing", "DMARC policy", "Barracuda policy tuning"]
      },
      "Barracuda ESS": {
        isManaged: true,
        tier: "business",
        serverSecurityNote: "Mail is filtered through Barracuda Email Security Service. Server-level security is managed by Barracuda.",
        customerResponsibilities: ["SPF record configuration", "DKIM signing", "DMARC policy"]
      },
      "Zoho Mail": {
        isManaged: true,
        tier: "business",
        serverSecurityNote: "Mail server infrastructure is managed by Zoho. Server-level security is Zoho's responsibility.",
        customerResponsibilities: ["SPF record configuration", "DKIM signing", "DMARC policy", "Zoho admin settings"]
      },
      "ProtonMail": {
        isManaged: true,
        tier: "enterprise",
        serverSecurityNote: "Mail server infrastructure is managed by Proton AG with end-to-end encryption. Server-level security is Proton's responsibility.",
        customerResponsibilities: ["SPF record configuration", "DKIM signing", "DMARC policy"]
      },
      "Cloudflare Email": {
        isManaged: true,
        tier: "business",
        serverSecurityNote: "Email routing is managed by Cloudflare. Server-level security depends on the destination mail server.",
        customerResponsibilities: ["SPF record configuration", "DKIM signing", "DMARC policy", "Cloudflare email routing rules"]
      }
    };
  }
});
init_email_security_analyzer();
export {
  analyzeDkim,
  analyzeDmarc,
  analyzeEmailSecurity,
  analyzeMx,
  analyzeSpf,
  classifyMailProvider,
  generateEmailPostureFindings,
  isMailAsset,
  isNonMailAsset
};
