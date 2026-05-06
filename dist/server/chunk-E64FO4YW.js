import {
  __esm
} from "./chunk-KFQGP6VL.js";

// shared/vendor-infrastructure-taxonomy.ts
function getHostnameIndex() {
  if (!_hostnameIndex) {
    _hostnameIndex = [];
    for (const v of VENDOR_REGISTRY) {
      for (const p of v.hostPatterns) {
        _hostnameIndex.push({ pattern: p, vendor: v });
      }
    }
  }
  return _hostnameIndex;
}
function getCnameIndex() {
  if (!_cnameIndex) {
    _cnameIndex = [];
    for (const v of VENDOR_REGISTRY) {
      if (v.cnamePatterns) {
        for (const p of v.cnamePatterns) {
          _cnameIndex.push({ pattern: p, vendor: v });
        }
      }
    }
  }
  return _cnameIndex;
}
function classifyVendor(asset) {
  const h = (asset.hostname || "").toLowerCase();
  for (const entry of getHostnameIndex()) {
    if (entry.pattern.test(h)) {
      return {
        vendor: entry.vendor,
        category: entry.vendor.category,
        riskResponsibility: entry.vendor.riskResponsibility,
        matchMethod: "hostname",
        confidence: 95
      };
    }
  }
  if (asset.cnames && asset.cnames.length > 0) {
    for (const cname of asset.cnames) {
      const c = cname.toLowerCase();
      for (const entry of getCnameIndex()) {
        if (entry.pattern.test(c)) {
          return {
            vendor: entry.vendor,
            category: entry.vendor.category,
            // CNAME to vendor = shared responsibility (customer owns the domain, vendor owns infra)
            riskResponsibility: entry.vendor.riskResponsibility,
            matchMethod: "cname",
            confidence: 85
          };
        }
      }
    }
  }
  if (asset.asn) {
    for (const v of VENDOR_REGISTRY) {
      if (v.asns && v.asns.includes(asset.asn)) {
        return {
          vendor: v,
          category: v.category,
          riskResponsibility: v.riskResponsibility,
          matchMethod: "asn",
          confidence: 70
          // Lower confidence — ASN match alone doesn't confirm vendor management
        };
      }
    }
  }
  if (asset.tags) {
    if (asset.tags.includes("managed_provider") || asset.tags.includes("third_party_infrastructure")) {
      return {
        vendor: null,
        category: null,
        riskResponsibility: "vendor_responsibility",
        matchMethod: "tag",
        confidence: 60
      };
    }
  }
  return {
    vendor: null,
    category: null,
    riskResponsibility: "customer_responsibility",
    matchMethod: "none",
    confidence: 100
  };
}
function partitionByResponsibility(items, getAssetInfo) {
  const customerOwned = [];
  const vendorManaged = [];
  const sharedResponsibility = [];
  const classifications = /* @__PURE__ */ new Map();
  for (const item of items) {
    const info = getAssetInfo(item);
    const classification = classifyVendor(info);
    classifications.set(item, classification);
    switch (classification.riskResponsibility) {
      case "vendor_responsibility":
        vendorManaged.push(item);
        break;
      case "shared_responsibility":
        sharedResponsibility.push(item);
        break;
      case "customer_responsibility":
        customerOwned.push(item);
        break;
    }
  }
  return { customerOwned, vendorManaged, sharedResponsibility, classifications };
}
function getRiskResponsibilityLabel(resp) {
  switch (resp) {
    case "vendor_responsibility":
      return "Vendor Managed \u2014 Risk excluded from customer score";
    case "shared_responsibility":
      return "Shared Responsibility \u2014 Configuration risk attributed to customer";
    case "customer_responsibility":
      return "Customer Owned \u2014 Full risk attribution";
  }
}
function getCategoryLabel(cat) {
  const labels = {
    email_provider: "Email Provider",
    web_hosting: "Web Hosting Platform",
    cdn: "CDN / Edge Network",
    dns_provider: "DNS Provider",
    iaas: "IaaS (Infrastructure as a Service)",
    paas: "PaaS (Platform as a Service)",
    saas: "SaaS (Software as a Service)",
    analytics: "Analytics / Tracking",
    isp: "Hosting Provider / ISP",
    registrar: "Domain Registrar",
    ci_cd: "CI/CD Platform",
    identity_provider: "Identity Provider",
    payment_processor: "Payment Processor",
    monitoring: "Monitoring / APM",
    security_vendor: "Security Vendor"
  };
  return labels[cat] || cat;
}
function computeVendorConcentrationRisk(classifications) {
  const vendorCounts = /* @__PURE__ */ new Map();
  let totalVendorAssets = 0;
  for (const c of classifications) {
    if (c.vendor) {
      vendorCounts.set(c.vendor.name, (vendorCounts.get(c.vendor.name) || 0) + 1);
      totalVendorAssets++;
    }
  }
  if (totalVendorAssets === 0) {
    return { score: 0, band: "MINIMAL", topVendors: [] };
  }
  let hhi = 0;
  const topVendors = [];
  for (const [name, count] of vendorCounts) {
    const share = count / totalVendorAssets;
    hhi += share * share;
    topVendors.push({ name, count, percentage: Math.round(share * 100) });
  }
  topVendors.sort((a, b) => b.count - a.count);
  const concentrationScore = Math.round(hhi * 100);
  const band = concentrationScore >= 70 ? "CRITICAL" : concentrationScore >= 50 ? "HIGH" : concentrationScore >= 30 ? "MEDIUM" : concentrationScore >= 15 ? "LOW" : "MINIMAL";
  return { score: concentrationScore, band, topVendors: topVendors.slice(0, 10) };
}
var VENDOR_REGISTRY, _hostnameIndex, _cnameIndex;
var init_vendor_infrastructure_taxonomy = __esm({
  "shared/vendor-infrastructure-taxonomy.ts"() {
    VENDOR_REGISTRY = [
      // ═══ EMAIL PROVIDERS ═══════════════════════════════════════════════════════
      {
        name: "Microsoft 365",
        category: "email_provider",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [
          /outlook\.com$/i,
          /outlook\.office365\.com$/i,
          /protection\.outlook\.com$/i,
          /mail\.protection\.outlook\.com$/i,
          /office365\.com$/i,
          /microsoftonline\.com$/i,
          /onmicrosoft\.com$/i
        ],
        cnamePatterns: [/outlook\.com$/i, /protection\.outlook\.com$/i],
        asns: [8075],
        // Microsoft
        description: "Microsoft manages email infrastructure, patching, and security updates",
        customerResponsibilities: ["Email security policies", "SPF/DKIM/DMARC configuration", "Conditional access rules"]
      },
      {
        name: "Google Workspace",
        category: "email_provider",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [
          /google\.com$/i,
          /gmail\.com$/i,
          /googlemail\.com$/i,
          /aspmx\.l\.google\.com$/i,
          /alt[0-9]\.aspmx\.l\.google\.com$/i,
          /googlehosted\.com$/i
        ],
        cnamePatterns: [/google\.com$/i, /ghs\.googlehosted\.com$/i],
        asns: [15169, 396982],
        // Google
        description: "Google manages email infrastructure and underlying platform security",
        customerResponsibilities: ["Email security policies", "SPF/DKIM/DMARC configuration", "Admin console settings"]
      },
      {
        name: "Proofpoint",
        category: "email_provider",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/proofpoint\.com$/i, /pphosted\.com$/i, /ppe-hosted\.com$/i],
        cnamePatterns: [/proofpoint\.com$/i],
        description: "Proofpoint manages email filtering and threat protection infrastructure",
        customerResponsibilities: ["Filter policy configuration", "Quarantine management"]
      },
      {
        name: "Mimecast",
        category: "email_provider",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/mimecast\.com$/i, /mimecast-offshore\.com$/i],
        cnamePatterns: [/mimecast\.com$/i],
        description: "Mimecast manages email security gateway infrastructure",
        customerResponsibilities: ["Policy configuration", "Allow/block lists"]
      },
      {
        name: "Zoho Mail",
        category: "email_provider",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/zoho\.com$/i, /zohomail\.com$/i, /zohocorp\.com$/i],
        cnamePatterns: [/zoho\.com$/i],
        description: "Zoho manages email hosting infrastructure",
        customerResponsibilities: ["Email policies", "SPF/DKIM configuration"]
      },
      {
        name: "Barracuda",
        category: "email_provider",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/barracuda\.com$/i, /barracudanetworks\.com$/i, /bsn-.*\.barracuda/i],
        description: "Barracuda manages email security gateway infrastructure"
      },
      {
        name: "Cisco Email Security",
        category: "email_provider",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/iphmx\.com$/i, /cisco\.com$/i, /ironport\.com$/i],
        description: "Cisco manages email security appliance infrastructure"
      },
      {
        name: "SendGrid",
        category: "email_provider",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/sendgrid\.net$/i, /sendgrid\.com$/i],
        cnamePatterns: [/sendgrid\.net$/i],
        description: "SendGrid/Twilio manages email delivery infrastructure",
        customerResponsibilities: ["Sender authentication", "Domain verification"]
      },
      {
        name: "Mailchimp / Mandrill",
        category: "email_provider",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/mailchimp\.com$/i, /mandrillapp\.com$/i, /mcsv\.net$/i, /mcdlv\.net$/i],
        description: "Mailchimp manages email marketing and transactional email infrastructure"
      },
      {
        name: "Amazon SES",
        category: "email_provider",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/amazonses\.com$/i, /ses\.amazonaws\.com$/i, /inbound-smtp\..*\.amazonaws\.com$/i],
        description: "AWS manages SES email delivery infrastructure",
        customerResponsibilities: ["Sending policies", "Domain verification", "Bounce handling"]
      },
      {
        name: "Postmark",
        category: "email_provider",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/postmarkapp\.com$/i, /mtasv\.net$/i],
        description: "Postmark manages transactional email delivery infrastructure"
      },
      {
        name: "SpamExperts / N-able Mail Assure",
        category: "email_provider",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/spamexperts\.com$/i, /antispamcloud\.com$/i, /mailassure\.com$/i],
        description: "SpamExperts manages email filtering infrastructure"
      },
      // ═══ WEB HOSTING PLATFORMS ═════════════════════════════════════════════════
      {
        name: "Wix",
        category: "web_hosting",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/wix\.com$/i, /wixsite\.com$/i, /wixdns\.net$/i, /wixmp\.com$/i],
        cnamePatterns: [/wixdns\.net$/i, /wix\.com$/i],
        description: "Wix manages web hosting platform, server infrastructure, and CMS security",
        customerResponsibilities: ["Content management", "Third-party app configuration", "Access controls"]
      },
      {
        name: "Squarespace",
        category: "web_hosting",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/squarespace\.com$/i, /sqsp\.net$/i, /squarespace-cdn\.com$/i],
        cnamePatterns: [/squarespace\.com$/i, /sqsp\.net$/i],
        description: "Squarespace manages web hosting and CMS infrastructure",
        customerResponsibilities: ["Content management", "SSL certificate configuration"]
      },
      {
        name: "Shopify",
        category: "web_hosting",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/shopify\.com$/i, /myshopify\.com$/i, /shopifycloud\.com$/i, /shopifysvc\.net$/i],
        cnamePatterns: [/shopify\.com$/i, /myshopify\.com$/i],
        description: "Shopify manages e-commerce platform infrastructure; customer manages store config and custom code",
        customerResponsibilities: ["Store configuration", "Custom theme code", "Third-party app security", "Payment settings"]
      },
      {
        name: "WordPress.com (Automattic)",
        category: "web_hosting",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/wordpress\.com$/i, /wp\.com$/i, /wpcomstaging\.com$/i, /automattic\.com$/i],
        cnamePatterns: [/wordpress\.com$/i, /wp\.com$/i],
        description: "Automattic manages WordPress.com hosting infrastructure and core updates",
        customerResponsibilities: ["Plugin selection", "Theme configuration", "Content management"]
      },
      {
        name: "GoDaddy Website Builder",
        category: "web_hosting",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/godaddysites\.com$/i, /secureserver\.net$/i, /godaddy\.com$/i],
        cnamePatterns: [/godaddysites\.com$/i, /secureserver\.net$/i],
        description: "GoDaddy manages website builder hosting infrastructure",
        customerResponsibilities: ["Content management", "Domain configuration"]
      },
      {
        name: "Webflow",
        category: "web_hosting",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/webflow\.io$/i, /webflow\.com$/i, /proxy-ssl\.webflow\.com$/i],
        cnamePatterns: [/webflow\.io$/i, /proxy-ssl\.webflow\.com$/i],
        description: "Webflow manages web hosting and CMS infrastructure",
        customerResponsibilities: ["Site design", "Custom code", "Form handling"]
      },
      {
        name: "Weebly",
        category: "web_hosting",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/weebly\.com$/i, /weeblysite\.com$/i],
        cnamePatterns: [/weebly\.com$/i],
        description: "Weebly/Square manages website hosting infrastructure"
      },
      {
        name: "HubSpot CMS",
        category: "web_hosting",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/hubspot\.com$/i, /hubspotpagebuilder\.com$/i, /hs-sites\.com$/i, /hubspot\.net$/i],
        cnamePatterns: [/hubspot\.com$/i, /hubspot\.net$/i],
        description: "HubSpot manages CMS hosting; customer manages content, forms, and integrations",
        customerResponsibilities: ["CMS content", "Form configuration", "Integration security", "Custom modules"]
      },
      // ═══ CDN / EDGE NETWORKS ══════════════════════════════════════════════════
      {
        name: "Cloudflare",
        category: "cdn",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/cloudflare\.com$/i, /cloudflare-dns\.com$/i, /cloudflaressl\.com$/i, /cloudflare\.net$/i],
        cnamePatterns: [/cdn\.cloudflare\.net$/i, /cloudflare-dns\.com$/i],
        asns: [13335],
        description: "Cloudflare manages CDN/WAF infrastructure; customer configures rules and DNS",
        customerResponsibilities: ["WAF rule configuration", "DNS records", "Page rules", "SSL/TLS settings", "Access policies"]
      },
      {
        name: "Akamai",
        category: "cdn",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/akamai\.net$/i, /akamaiedge\.net$/i, /akamaitechnologies\.com$/i, /akamaized\.net$/i, /edgekey\.net$/i, /edgesuite\.net$/i],
        cnamePatterns: [/akamai\.net$/i, /akamaiedge\.net$/i, /edgekey\.net$/i],
        asns: [20940, 16625],
        description: "Akamai manages CDN edge infrastructure; customer configures delivery and security policies",
        customerResponsibilities: ["Delivery configuration", "WAF policies", "Origin server security"]
      },
      {
        name: "Fastly",
        category: "cdn",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/fastly\.net$/i, /fastlylb\.net$/i, /fastly\.com$/i],
        cnamePatterns: [/fastly\.net$/i, /fastlylb\.net$/i],
        asns: [54113],
        description: "Fastly manages CDN edge infrastructure; customer configures VCL and security",
        customerResponsibilities: ["VCL configuration", "WAF rules", "Origin shield settings"]
      },
      {
        name: "AWS CloudFront",
        category: "cdn",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/cloudfront\.net$/i],
        cnamePatterns: [/cloudfront\.net$/i],
        description: "AWS manages CloudFront CDN infrastructure; customer configures distributions",
        customerResponsibilities: ["Distribution configuration", "Origin access", "Cache policies", "WAF rules"]
      },
      {
        name: "Azure CDN / Front Door",
        category: "cdn",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/azureedge\.net$/i, /azurefd\.net$/i, /trafficmanager\.net$/i],
        cnamePatterns: [/azureedge\.net$/i, /azurefd\.net$/i],
        description: "Microsoft manages Azure CDN/Front Door infrastructure",
        customerResponsibilities: ["Routing rules", "WAF policies", "Backend pool configuration"]
      },
      {
        name: "Google Cloud CDN",
        category: "cdn",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/googleapis\.com$/i, /gstatic\.com$/i, /googlevideo\.com$/i],
        cnamePatterns: [/googleapis\.com$/i],
        description: "Google manages Cloud CDN infrastructure",
        customerResponsibilities: ["Cache configuration", "Backend services", "Security policies"]
      },
      {
        name: "KeyCDN",
        category: "cdn",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/kxcdn\.com$/i, /keycdn\.com$/i],
        cnamePatterns: [/kxcdn\.com$/i],
        description: "KeyCDN manages CDN infrastructure"
      },
      {
        name: "StackPath / MaxCDN",
        category: "cdn",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/stackpathdns\.com$/i, /stackpathcdn\.com$/i, /maxcdn\.com$/i, /netdna-cdn\.com$/i],
        cnamePatterns: [/stackpathdns\.com$/i, /stackpathcdn\.com$/i],
        description: "StackPath manages CDN infrastructure"
      },
      {
        name: "Sucuri",
        category: "cdn",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/sucuri\.net$/i, /sucuridns\.com$/i],
        cnamePatterns: [/sucuri\.net$/i],
        description: "Sucuri manages WAF/CDN security infrastructure"
      },
      // ═══ DNS PROVIDERS ════════════════════════════════════════════════════════
      {
        name: "Cloudflare DNS",
        category: "dns_provider",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/ns\.cloudflare\.com$/i, /cloudflare\.com$/i],
        description: "Cloudflare manages DNS infrastructure; customer manages zone records",
        customerResponsibilities: ["DNS record management", "DNSSEC configuration"]
      },
      {
        name: "AWS Route 53",
        category: "dns_provider",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/awsdns-.*\.com$/i, /awsdns-.*\.net$/i, /awsdns-.*\.org$/i, /awsdns-.*\.co\.uk$/i, /route53\.amazonaws\.com$/i],
        description: "AWS manages Route 53 DNS infrastructure; customer manages hosted zones",
        customerResponsibilities: ["DNS record management", "Health checks", "Routing policies"]
      },
      {
        name: "Google Cloud DNS",
        category: "dns_provider",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/googledomains\.com$/i, /ns-cloud-.*\.googledomains\.com$/i],
        description: "Google manages Cloud DNS infrastructure; customer manages zones",
        customerResponsibilities: ["DNS record management", "DNSSEC configuration"]
      },
      {
        name: "NS1 (IBM)",
        category: "dns_provider",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/nsone\.net$/i, /ns1\.net$/i, /p[0-9]+\.nsone\.net$/i],
        description: "NS1/IBM manages DNS infrastructure"
      },
      {
        name: "Dyn (Oracle)",
        category: "dns_provider",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/dynect\.net$/i, /dyn\.com$/i],
        description: "Dyn/Oracle manages DNS infrastructure"
      },
      {
        name: "DNSimple",
        category: "dns_provider",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/dnsimple\.com$/i],
        description: "DNSimple manages DNS infrastructure"
      },
      {
        name: "DNSMadeEasy",
        category: "dns_provider",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/dnsmadeeasy\.com$/i],
        description: "DNSMadeEasy manages DNS infrastructure"
      },
      {
        name: "UltraDNS (Neustar)",
        category: "dns_provider",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/ultradns\.com$/i, /ultradns\.net$/i, /ultradns\.org$/i],
        description: "UltraDNS/Neustar manages DNS infrastructure"
      },
      // ═══ IaaS (Infrastructure as a Service) ═══════════════════════════════════
      {
        name: "Amazon Web Services",
        category: "iaas",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [
          /amazonaws\.com$/i,
          /aws\.amazon\.com$/i,
          /elasticbeanstalk\.com$/i,
          /elb\.amazonaws\.com$/i,
          /s3\.amazonaws\.com$/i,
          /ec2\..*\.compute\.amazonaws\.com$/i
        ],
        cnamePatterns: [/amazonaws\.com$/i, /elasticbeanstalk\.com$/i],
        asns: [16509, 14618],
        description: "AWS manages physical infrastructure, hypervisor, and network; customer manages OS, apps, and data",
        customerResponsibilities: ["OS patching", "Application security", "Security groups", "IAM policies", "Data encryption", "Network ACLs"]
      },
      {
        name: "Microsoft Azure",
        category: "iaas",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [
          /azure\.com$/i,
          /azurewebsites\.net$/i,
          /azure-api\.net$/i,
          /azurecontainer\.io$/i,
          /database\.windows\.net$/i,
          /blob\.core\.windows\.net$/i,
          /cloudapp\.azure\.com$/i,
          /azurestaticapps\.net$/i
        ],
        cnamePatterns: [/azurewebsites\.net$/i, /azure\.com$/i, /cloudapp\.azure\.com$/i],
        asns: [8075],
        description: "Azure manages physical infrastructure; customer manages VMs, apps, and configurations",
        customerResponsibilities: ["OS patching", "Application security", "NSG rules", "RBAC", "Data encryption"]
      },
      {
        name: "Google Cloud Platform",
        category: "iaas",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [
          /googleapis\.com$/i,
          /appspot\.com$/i,
          /run\.app$/i,
          /cloudfunctions\.net$/i,
          /web\.app$/i,
          /firebaseapp\.com$/i,
          /firebaseio\.com$/i
        ],
        cnamePatterns: [/googleapis\.com$/i, /ghs\.googlehosted\.com$/i],
        asns: [15169, 396982],
        description: "GCP manages physical infrastructure; customer manages compute, apps, and data",
        customerResponsibilities: ["Instance security", "IAM policies", "Firewall rules", "Application code"]
      },
      {
        name: "DigitalOcean",
        category: "iaas",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/digitalocean\.com$/i, /digitaloceanspaces\.com$/i, /ondigitalocean\.app$/i],
        cnamePatterns: [/ondigitalocean\.app$/i, /digitaloceanspaces\.com$/i],
        asns: [14061],
        description: "DigitalOcean manages physical infrastructure; customer manages droplets and apps",
        customerResponsibilities: ["Droplet OS patching", "Application security", "Firewall rules"]
      },
      {
        name: "Linode (Akamai)",
        category: "iaas",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/linode\.com$/i, /linodeobjects\.com$/i, /nodebalancer\.linode\.com$/i],
        asns: [63949],
        description: "Linode manages physical infrastructure; customer manages instances",
        customerResponsibilities: ["OS patching", "Application security", "Firewall configuration"]
      },
      {
        name: "Vultr",
        category: "iaas",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/vultr\.com$/i, /vultrobj\.com$/i],
        asns: [20473],
        description: "Vultr manages physical infrastructure; customer manages instances",
        customerResponsibilities: ["OS patching", "Application security", "Firewall rules"]
      },
      {
        name: "OVHcloud",
        category: "iaas",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/ovh\.net$/i, /ovh\.com$/i, /ovhcloud\.com$/i, /kimsufi\.com$/i, /soyoustart\.com$/i],
        asns: [16276],
        description: "OVH manages physical infrastructure; customer manages servers",
        customerResponsibilities: ["OS patching", "Application security", "Firewall configuration"]
      },
      {
        name: "Hetzner",
        category: "iaas",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/hetzner\.com$/i, /hetzner\.cloud$/i, /your-server\.de$/i],
        asns: [24940],
        description: "Hetzner manages physical infrastructure; customer manages servers",
        customerResponsibilities: ["OS patching", "Application security", "Firewall rules"]
      },
      {
        name: "Oracle Cloud",
        category: "iaas",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/oraclecloud\.com$/i, /oraclevcn\.com$/i, /oci\.oraclecloud\.com$/i],
        asns: [31898],
        description: "Oracle manages cloud infrastructure; customer manages instances and applications",
        customerResponsibilities: ["OS patching", "Application security", "Security lists", "IAM policies"]
      },
      {
        name: "IBM Cloud",
        category: "iaas",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/cloud\.ibm\.com$/i, /softlayer\.com$/i, /bluemix\.net$/i, /mybluemix\.net$/i],
        asns: [36351],
        description: "IBM manages cloud infrastructure; customer manages workloads",
        customerResponsibilities: ["Instance security", "Application code", "Access policies"]
      },
      {
        name: "Alibaba Cloud",
        category: "iaas",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/alibabacloud\.com$/i, /aliyuncs\.com$/i, /alicdn\.com$/i],
        asns: [45102],
        description: "Alibaba manages cloud infrastructure; customer manages instances",
        customerResponsibilities: ["OS patching", "Application security", "Security groups"]
      },
      // ═══ PaaS (Platform as a Service) ═════════════════════════════════════════
      {
        name: "Heroku",
        category: "paas",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/heroku\.com$/i, /herokuapp\.com$/i, /herokussl\.com$/i, /herokudns\.com$/i],
        cnamePatterns: [/herokuapp\.com$/i, /herokudns\.com$/i],
        description: "Heroku manages platform infrastructure; customer manages application code and dependencies",
        customerResponsibilities: ["Application code", "Dependency management", "Environment variables", "Add-on configuration"]
      },
      {
        name: "Vercel",
        category: "paas",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/vercel\.app$/i, /vercel\.com$/i, /now\.sh$/i, /zeit\.co$/i],
        cnamePatterns: [/vercel\.app$/i, /cname\.vercel-dns\.com$/i],
        description: "Vercel manages deployment infrastructure; customer manages application code",
        customerResponsibilities: ["Application code", "Environment variables", "Edge function logic"]
      },
      {
        name: "Netlify",
        category: "paas",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/netlify\.app$/i, /netlify\.com$/i, /netlifyglobalcdn\.com$/i],
        cnamePatterns: [/netlify\.app$/i, /netlifyglobalcdn\.com$/i],
        description: "Netlify manages deployment infrastructure; customer manages application code",
        customerResponsibilities: ["Application code", "Build configuration", "Serverless functions"]
      },
      {
        name: "Railway",
        category: "paas",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/railway\.app$/i, /up\.railway\.app$/i],
        cnamePatterns: [/railway\.app$/i],
        description: "Railway manages platform infrastructure; customer manages application",
        customerResponsibilities: ["Application code", "Database management", "Environment configuration"]
      },
      {
        name: "Render",
        category: "paas",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/render\.com$/i, /onrender\.com$/i],
        cnamePatterns: [/onrender\.com$/i],
        description: "Render manages platform infrastructure; customer manages application",
        customerResponsibilities: ["Application code", "Service configuration", "Environment variables"]
      },
      {
        name: "Fly.io",
        category: "paas",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/fly\.dev$/i, /fly\.io$/i, /flycast\.dev$/i],
        cnamePatterns: [/fly\.dev$/i],
        description: "Fly.io manages edge compute infrastructure; customer manages application",
        customerResponsibilities: ["Application code", "Machine configuration", "Secrets management"]
      },
      {
        name: "GitHub Pages",
        category: "paas",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/github\.io$/i, /githubusercontent\.com$/i, /github\.com$/i, /githubassets\.com$/i],
        cnamePatterns: [/github\.io$/i],
        asns: [36459],
        description: "GitHub manages Pages hosting infrastructure",
        customerResponsibilities: ["Repository content", "Custom domain DNS"]
      },
      {
        name: "GitLab Pages",
        category: "paas",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/gitlab\.io$/i, /gitlab\.com$/i],
        cnamePatterns: [/gitlab\.io$/i],
        description: "GitLab manages Pages hosting infrastructure",
        customerResponsibilities: ["Repository content", "CI/CD pipeline configuration"]
      },
      // ═══ SaaS (Software as a Service) ═════════════════════════════════════════
      {
        name: "Salesforce",
        category: "saas",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [
          /salesforce\.com$/i,
          /force\.com$/i,
          /salesforceliveagent\.com$/i,
          /my\.salesforce\.com$/i,
          /lightning\.force\.com$/i,
          /visualforce\.com$/i
        ],
        cnamePatterns: [/salesforce\.com$/i, /force\.com$/i],
        description: "Salesforce manages CRM platform infrastructure and security",
        customerResponsibilities: ["User access controls", "Custom Apex code", "Integration security", "Data classification"]
      },
      {
        name: "Zendesk",
        category: "saas",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/zendesk\.com$/i, /zdassets\.com$/i, /zendesk\.in$/i],
        cnamePatterns: [/zendesk\.com$/i],
        description: "Zendesk manages support platform infrastructure",
        customerResponsibilities: ["Agent access controls", "Automation rules", "Integration configuration"]
      },
      {
        name: "Freshdesk / Freshworks",
        category: "saas",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/freshdesk\.com$/i, /freshworks\.com$/i, /freshservice\.com$/i],
        cnamePatterns: [/freshdesk\.com$/i],
        description: "Freshworks manages support platform infrastructure"
      },
      {
        name: "ServiceNow",
        category: "saas",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/servicenow\.com$/i, /service-now\.com$/i],
        description: "ServiceNow manages ITSM platform infrastructure",
        customerResponsibilities: ["Instance configuration", "Custom scripts", "Access controls", "Integration security"]
      },
      {
        name: "Atlassian (Jira/Confluence)",
        category: "saas",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/atlassian\.net$/i, /atlassian\.com$/i, /jira\.com$/i, /bitbucket\.org$/i, /trello\.com$/i],
        description: "Atlassian manages platform infrastructure",
        customerResponsibilities: ["Project permissions", "App marketplace selections", "Space access"]
      },
      {
        name: "Slack",
        category: "saas",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/slack\.com$/i, /slack-edge\.com$/i, /slack-msgs\.com$/i],
        description: "Slack manages messaging platform infrastructure",
        customerResponsibilities: ["Workspace settings", "App approvals", "Channel permissions", "DLP policies"]
      },
      {
        name: "Zoom",
        category: "saas",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/zoom\.us$/i, /zoom\.com$/i, /zoomgov\.com$/i],
        description: "Zoom manages video conferencing infrastructure",
        customerResponsibilities: ["Meeting security settings", "Recording policies", "SSO configuration"]
      },
      {
        name: "Dropbox",
        category: "saas",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/dropbox\.com$/i, /dropboxapi\.com$/i, /dropboxstatic\.com$/i, /db\.tt$/i],
        description: "Dropbox manages file storage infrastructure",
        customerResponsibilities: ["Sharing policies", "Team folder access", "Third-party app connections"]
      },
      {
        name: "Box",
        category: "saas",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/box\.com$/i, /boxcloud\.com$/i, /boxcdn\.net$/i],
        description: "Box manages enterprise content platform infrastructure",
        customerResponsibilities: ["Collaboration policies", "Access controls", "Retention policies"]
      },
      {
        name: "DocuSign",
        category: "saas",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/docusign\.com$/i, /docusign\.net$/i],
        description: "DocuSign manages e-signature platform infrastructure"
      },
      {
        name: "Workday",
        category: "saas",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/workday\.com$/i, /myworkday\.com$/i],
        description: "Workday manages HCM/finance platform infrastructure",
        customerResponsibilities: ["Tenant configuration", "Security groups", "Integration security"]
      },
      // ═══ ANALYTICS / TRACKING ═════════════════════════════════════════════════
      {
        name: "Google Analytics",
        category: "analytics",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/google-analytics\.com$/i, /googletagmanager\.com$/i, /googlesyndication\.com$/i, /doubleclick\.net$/i],
        description: "Google manages analytics collection infrastructure",
        customerResponsibilities: ["Tag configuration", "Data retention settings", "User consent management"]
      },
      {
        name: "Hotjar",
        category: "analytics",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/hotjar\.com$/i, /hotjar\.io$/i],
        description: "Hotjar manages session recording and analytics infrastructure"
      },
      {
        name: "Mixpanel",
        category: "analytics",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/mixpanel\.com$/i, /mxpnl\.com$/i],
        description: "Mixpanel manages product analytics infrastructure"
      },
      {
        name: "Segment (Twilio)",
        category: "analytics",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/segment\.io$/i, /segment\.com$/i, /segmentapis\.com$/i],
        description: "Segment manages customer data platform infrastructure"
      },
      {
        name: "Heap",
        category: "analytics",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/heap\.io$/i, /heapanalytics\.com$/i],
        description: "Heap manages product analytics infrastructure"
      },
      {
        name: "Amplitude",
        category: "analytics",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/amplitude\.com$/i, /cdn\.amplitude\.com$/i],
        description: "Amplitude manages product analytics infrastructure"
      },
      // ═══ DOMAIN REGISTRARS ════════════════════════════════════════════════════
      {
        name: "GoDaddy",
        category: "registrar",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/godaddy\.com$/i, /domaincontrol\.com$/i, /parkingcrew\.net$/i],
        description: "GoDaddy manages registrar and parking infrastructure",
        customerResponsibilities: ["Domain renewal", "DNS configuration", "Transfer lock settings"]
      },
      {
        name: "Namecheap",
        category: "registrar",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/namecheap\.com$/i, /registrar-servers\.com$/i, /namecheaphosting\.com$/i],
        description: "Namecheap manages registrar infrastructure",
        customerResponsibilities: ["Domain renewal", "DNS configuration"]
      },
      {
        name: "Tucows / Hover",
        category: "registrar",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/tucows\.com$/i, /hover\.com$/i, /opensrs\.net$/i],
        description: "Tucows manages registrar infrastructure"
      },
      {
        name: "Network Solutions",
        category: "registrar",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/networksolutions\.com$/i, /worldnic\.com$/i],
        description: "Network Solutions manages registrar infrastructure"
      },
      {
        name: "Name.com",
        category: "registrar",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/name\.com$/i],
        description: "Name.com manages registrar infrastructure"
      },
      // ═══ IDENTITY PROVIDERS ═══════════════════════════════════════════════════
      {
        name: "Okta",
        category: "identity_provider",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/okta\.com$/i, /oktacdn\.com$/i, /oktapreview\.com$/i, /okta-emea\.com$/i],
        cnamePatterns: [/okta\.com$/i],
        description: "Okta manages identity platform; customer configures policies and integrations",
        customerResponsibilities: ["Authentication policies", "MFA configuration", "App integrations", "User lifecycle"]
      },
      {
        name: "Auth0 (Okta)",
        category: "identity_provider",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/auth0\.com$/i, /a0\.dev$/i],
        cnamePatterns: [/auth0\.com$/i],
        description: "Auth0 manages identity infrastructure; customer configures rules and connections",
        customerResponsibilities: ["Authentication rules", "Connection configuration", "Custom actions"]
      },
      {
        name: "Azure Active Directory",
        category: "identity_provider",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/login\.microsoftonline\.com$/i, /sts\.windows\.net$/i, /msidentity\.com$/i],
        description: "Microsoft manages Azure AD infrastructure; customer configures policies",
        customerResponsibilities: ["Conditional access", "MFA policies", "App registrations", "PIM configuration"]
      },
      {
        name: "Ping Identity",
        category: "identity_provider",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/pingidentity\.com$/i, /pingone\.com$/i],
        description: "Ping Identity manages identity platform infrastructure",
        customerResponsibilities: ["Authentication policies", "Federation configuration"]
      },
      {
        name: "OneLogin",
        category: "identity_provider",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/onelogin\.com$/i],
        description: "OneLogin manages identity platform infrastructure",
        customerResponsibilities: ["SSO configuration", "MFA policies", "User provisioning"]
      },
      // ═══ PAYMENT PROCESSORS ═══════════════════════════════════════════════════
      {
        name: "Stripe",
        category: "payment_processor",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/stripe\.com$/i, /stripe\.network$/i, /stripecdn\.com$/i],
        description: "Stripe manages payment processing infrastructure and PCI compliance",
        customerResponsibilities: ["Integration code", "Webhook handling", "API key management"]
      },
      {
        name: "PayPal",
        category: "payment_processor",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/paypal\.com$/i, /paypalobjects\.com$/i, /braintreegateway\.com$/i, /braintree-api\.com$/i],
        description: "PayPal manages payment platform infrastructure",
        customerResponsibilities: ["Integration configuration", "Webhook handling"]
      },
      {
        name: "Square",
        category: "payment_processor",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/squareup\.com$/i, /square\.com$/i, /squareupsandbox\.com$/i],
        description: "Square manages payment processing infrastructure"
      },
      {
        name: "Adyen",
        category: "payment_processor",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/adyen\.com$/i, /adyenpayments\.com$/i],
        description: "Adyen manages payment platform infrastructure"
      },
      // ═══ MONITORING / APM ═════════════════════════════════════════════════════
      {
        name: "Datadog",
        category: "monitoring",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/datadoghq\.com$/i, /datadoghq\.eu$/i, /ddog-gov\.com$/i],
        description: "Datadog manages monitoring platform infrastructure",
        customerResponsibilities: ["Agent configuration", "Dashboard setup", "Alert policies"]
      },
      {
        name: "New Relic",
        category: "monitoring",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/newrelic\.com$/i, /nr-data\.net$/i, /nr-assets\.net$/i],
        description: "New Relic manages observability platform infrastructure"
      },
      {
        name: "PagerDuty",
        category: "monitoring",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/pagerduty\.com$/i],
        description: "PagerDuty manages incident management platform infrastructure"
      },
      {
        name: "Sentry",
        category: "monitoring",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/sentry\.io$/i, /sentry-cdn\.com$/i],
        description: "Sentry manages error tracking platform infrastructure"
      },
      {
        name: "Splunk Cloud",
        category: "monitoring",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/splunkcloud\.com$/i, /splunk\.com$/i],
        description: "Splunk manages cloud SIEM infrastructure",
        customerResponsibilities: ["Search queries", "Alert configuration", "Data onboarding"]
      },
      // ═══ CI/CD PLATFORMS ══════════════════════════════════════════════════════
      {
        name: "GitHub Actions",
        category: "ci_cd",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/github\.com$/i, /actions\.githubusercontent\.com$/i],
        description: "GitHub manages CI/CD infrastructure; customer manages workflow definitions",
        customerResponsibilities: ["Workflow YAML", "Secret management", "Runner configuration"]
      },
      {
        name: "GitLab CI",
        category: "ci_cd",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/gitlab\.com$/i],
        description: "GitLab manages CI/CD infrastructure; customer manages pipeline definitions",
        customerResponsibilities: ["Pipeline YAML", "Variable management", "Runner configuration"]
      },
      {
        name: "CircleCI",
        category: "ci_cd",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/circleci\.com$/i],
        description: "CircleCI manages CI/CD infrastructure; customer manages config",
        customerResponsibilities: ["Config YAML", "Context/secret management", "Orb selection"]
      },
      {
        name: "Jenkins (CloudBees)",
        category: "ci_cd",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/cloudbees\.com$/i],
        description: "CloudBees manages Jenkins platform; customer manages jobs and plugins",
        customerResponsibilities: ["Job configuration", "Plugin management", "Credential storage"]
      },
      // ═══ SECURITY VENDORS ═════════════════════════════════════════════════════
      {
        name: "CrowdStrike",
        category: "security_vendor",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/crowdstrike\.com$/i, /falcon\.crowdstrike\.com$/i],
        description: "CrowdStrike manages endpoint security platform infrastructure",
        customerResponsibilities: ["Policy configuration", "Response actions", "Exclusion management"]
      },
      {
        name: "Qualys",
        category: "security_vendor",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/qualys\.com$/i, /qualysguard\.com$/i],
        description: "Qualys manages vulnerability management platform infrastructure"
      },
      {
        name: "Rapid7",
        category: "security_vendor",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/rapid7\.com$/i, /insight\.rapid7\.com$/i],
        description: "Rapid7 manages security platform infrastructure"
      },
      {
        name: "Tenable",
        category: "security_vendor",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/tenable\.com$/i, /tenable\.io$/i, /tenablecloud\.com$/i],
        description: "Tenable manages vulnerability management platform infrastructure"
      },
      {
        name: "Zscaler",
        category: "security_vendor",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/zscaler\.com$/i, /zscaler\.net$/i, /zscalerone\.net$/i, /zscloud\.net$/i],
        description: "Zscaler manages cloud security infrastructure",
        customerResponsibilities: ["Policy configuration", "App connector setup", "User provisioning"]
      },
      {
        name: "Palo Alto Networks",
        category: "security_vendor",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/paloaltonetworks\.com$/i, /prismacloud\.io$/i, /gpcloudservice\.com$/i],
        description: "Palo Alto manages security platform infrastructure"
      },
      {
        name: "Fortinet",
        category: "security_vendor",
        riskResponsibility: "vendor_responsibility",
        hostPatterns: [/fortinet\.com$/i, /forticloud\.com$/i, /fortigate\.com$/i, /fortiguard\.com$/i],
        description: "Fortinet manages security platform infrastructure"
      },
      // ═══ ISPs / HOSTING ISPs ══════════════════════════════════════════════════
      {
        name: "Rackspace",
        category: "isp",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/rackspace\.com$/i, /rackspacecloud\.com$/i, /emailsrvr\.com$/i, /stabletransit\.com$/i],
        asns: [33070, 19994],
        description: "Rackspace manages hosting infrastructure; customer manages servers/applications",
        customerResponsibilities: ["Server configuration", "Application security", "Access controls"]
      },
      {
        name: "Leaseweb",
        category: "isp",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/leaseweb\.com$/i, /leaseweb\.net$/i],
        asns: [60781, 28753],
        description: "Leaseweb manages hosting infrastructure",
        customerResponsibilities: ["Server management", "Application security"]
      },
      {
        name: "InMotion Hosting",
        category: "isp",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/inmotionhosting\.com$/i],
        description: "InMotion manages hosting infrastructure",
        customerResponsibilities: ["Website management", "Application security"]
      },
      {
        name: "Bluehost (Newfold)",
        category: "isp",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/bluehost\.com$/i, /hostgator\.com$/i, /justhost\.com$/i],
        description: "Bluehost manages shared hosting infrastructure",
        customerResponsibilities: ["Website management", "Plugin/theme security", "Access controls"]
      },
      {
        name: "SiteGround",
        category: "isp",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/siteground\.com$/i, /sgvps\.net$/i, /sgedu\.site$/i],
        description: "SiteGround manages hosting infrastructure",
        customerResponsibilities: ["Website management", "Application security"]
      },
      {
        name: "DreamHost",
        category: "isp",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/dreamhost\.com$/i, /dreamhosters\.com$/i],
        description: "DreamHost manages hosting infrastructure",
        customerResponsibilities: ["Website management", "Application security"]
      },
      {
        name: "WP Engine",
        category: "isp",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/wpengine\.com$/i, /wpenginepowered\.com$/i],
        cnamePatterns: [/wpengine\.com$/i, /wpenginepowered\.com$/i],
        description: "WP Engine manages WordPress hosting infrastructure; customer manages site content and plugins",
        customerResponsibilities: ["WordPress plugins", "Theme security", "Content management", "User access"]
      },
      {
        name: "Kinsta",
        category: "isp",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/kinsta\.cloud$/i, /kinsta\.com$/i],
        cnamePatterns: [/kinsta\.cloud$/i],
        description: "Kinsta manages WordPress hosting infrastructure",
        customerResponsibilities: ["WordPress plugins", "Theme security", "Content management"]
      },
      {
        name: "Pantheon",
        category: "isp",
        riskResponsibility: "shared_responsibility",
        hostPatterns: [/pantheonsite\.io$/i, /pantheon\.io$/i],
        cnamePatterns: [/pantheonsite\.io$/i],
        description: "Pantheon manages Drupal/WordPress hosting infrastructure",
        customerResponsibilities: ["CMS configuration", "Module/plugin security", "Custom code"]
      }
    ];
    _hostnameIndex = null;
    _cnameIndex = null;
  }
});

export {
  VENDOR_REGISTRY,
  classifyVendor,
  partitionByResponsibility,
  getRiskResponsibilityLabel,
  getCategoryLabel,
  computeVendorConcentrationRisk,
  init_vendor_infrastructure_taxonomy
};
