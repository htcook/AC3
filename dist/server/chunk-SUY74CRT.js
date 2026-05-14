import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/cisa-kev-product-map.ts
function classifyKEVEntry(entry) {
  const vendor = entry.vendorProject || "";
  const product = entry.product || "";
  const vulnName = entry.vulnerabilityName || "";
  for (const rule of VENDOR_PRODUCT_RULES) {
    if (!vendor.toLowerCase().includes(rule.vendor.toLowerCase())) continue;
    if (rule.products.length === 0) return rule.family;
    const productMatch = rule.products.some(
      (p) => product.toLowerCase().includes(p.toLowerCase()) || vulnName.toLowerCase().includes(p.toLowerCase())
    );
    if (productMatch) return rule.family;
  }
  return null;
}
async function loadKEVCatalog() {
  try {
    const response = await fetch(KEV_URL, {
      signal: AbortSignal.timeout(15e3)
    });
    if (!response.ok) {
      console.error(`[KEV] Failed to fetch catalog: ${response.status}`);
      return kevIndex.size;
    }
    const data = await response.json();
    const vulns = data.vulnerabilities || [];
    const newIndex = /* @__PURE__ */ new Map();
    let classified = 0;
    for (const v of vulns) {
      const family = classifyKEVEntry(v);
      if (family && TECH_FAMILY_KEYWORDS[family]) {
        newIndex.set(v.cveID, {
          family,
          keywords: TECH_FAMILY_KEYWORDS[family],
          vendor: v.vendorProject,
          product: v.product,
          ransomwareLinked: v.knownRansomwareCampaignUse === "Known"
        });
        classified++;
      }
    }
    kevIndex = newIndex;
    kevLoaded = true;
    kevLastRefresh = Date.now();
    console.log(`[KEV] Loaded ${vulns.length} entries, classified ${classified} CVEs into ${new Set(Array.from(newIndex.values()).map((v) => v.family)).size} families`);
    return classified;
  } catch (err) {
    console.error(`[KEV] Catalog load error: ${err.message}`);
    return kevIndex.size;
  }
}
async function ensureKEVLoaded() {
  if (!kevLoaded || Date.now() - kevLastRefresh > KEV_REFRESH_INTERVAL) {
    await loadKEVCatalog();
  }
}
function lookupCVEProduct(cveId) {
  const kevEntry = kevIndex.get(cveId);
  if (kevEntry) {
    return {
      family: kevEntry.family,
      keywords: kevEntry.keywords,
      vendor: kevEntry.vendor,
      product: kevEntry.product,
      ransomwareLinked: kevEntry.ransomwareLinked,
      source: "kev_live"
    };
  }
  const staticEntry = STATIC_CVE_PRODUCT_MAP[cveId];
  if (staticEntry) {
    return {
      family: staticEntry.family,
      keywords: staticEntry.keywords,
      source: "static_fallback"
    };
  }
  return {
    family: "",
    keywords: [],
    source: "not_found"
  };
}
function validateCVEAgainstTarget(cveId, confirmedTechnologies, serviceVersions = []) {
  const lookup = lookupCVEProduct(cveId);
  if (lookup.source === "not_found") return null;
  const allEvidence = [
    ...confirmedTechnologies.map((t) => t.toLowerCase()),
    ...serviceVersions.map((s) => s.toLowerCase())
  ];
  const hasMatch = lookup.keywords.some(
    (kw) => allEvidence.some((ev) => ev.includes(kw.toLowerCase()))
  );
  if (hasMatch) return null;
  return {
    violation: `CVE ${cveId} targets ${lookup.family} (${lookup.vendor || "unknown vendor"} / ${lookup.product || "unknown product"}) but target has no matching technology. Required keywords: [${lookup.keywords.join(", ")}]. Confirmed: [${confirmedTechnologies.join(", ")}]`,
    family: lookup.family,
    keywords: lookup.keywords
  };
}
function getKEVStats() {
  const families = new Set(Array.from(kevIndex.values()).map((v) => v.family));
  return {
    loaded: kevLoaded,
    totalCVEs: kevIndex.size,
    families: families.size,
    lastRefresh: kevLastRefresh,
    staticFallbackCount: Object.keys(STATIC_CVE_PRODUCT_MAP).length
  };
}
function getRansomwareLinkedCVEs() {
  return Array.from(kevIndex.entries()).filter(([_, info]) => info.ransomwareLinked).map(([cve]) => cve);
}
var TECH_FAMILY_KEYWORDS, VENDOR_PRODUCT_RULES, kevIndex, kevLoaded, kevLastRefresh, KEV_REFRESH_INTERVAL, KEV_URL, STATIC_CVE_PRODUCT_MAP;
var init_cisa_kev_product_map = __esm({
  "server/lib/cisa-kev-product-map.ts"() {
    "use strict";
    TECH_FAMILY_KEYWORDS = {
      // Microsoft
      microsoft_windows: ["windows", "win32k", "mshtml", "clfs", "ntfs", "win32", "microsoft windows"],
      microsoft_exchange: ["exchange", "microsoft exchange", "owa", "exchange server"],
      microsoft_office: ["office", "excel", "word", "outlook", "powerpoint", "microsoft office"],
      microsoft_sharepoint: ["sharepoint", "microsoft sharepoint"],
      microsoft_dotnet: [".net", "asp.net", "dotnet", "aspnet"],
      microsoft_iis: ["iis", "internet information services", "microsoft-iis"],
      microsoft_sql_server: ["sql server", "mssql", "microsoft sql"],
      // Apple
      apple_ios: ["ios", "ipados", "iphone", "apple ios"],
      apple_macos: ["macos", "os x", "mac os", "apple macos", "darwin"],
      apple_webkit: ["safari", "webkit", "apple safari"],
      // Cisco
      cisco_ios: ["cisco ios", "ios xe", "ios xr", "cisco ios xe"],
      cisco_asa: ["cisco asa", "adaptive security", "firepower", "asa"],
      cisco_webex: ["webex", "cisco webex"],
      cisco_small_business: ["cisco small business", "cisco rv", "cisco router"],
      // Adobe
      adobe_reader: ["acrobat", "adobe reader", "pdf reader", "adobe acrobat"],
      adobe_flash: ["flash", "adobe flash", "flash player", "swf"],
      adobe_coldfusion: ["coldfusion", "adobe coldfusion", "cfml"],
      adobe_commerce: ["magento", "adobe commerce"],
      // Google / Chromium
      google_chrome: ["chrome", "chromium", "google chrome", "v8", "chromium-based"],
      google_android: ["android", "pixel", "google android", "aosp"],
      // Apache
      apache_http: ["apache httpd", "apache http server", "apache2", "apache/2"],
      apache_tomcat: ["tomcat", "apache tomcat", "catalina"],
      apache_struts: ["struts", "apache struts"],
      apache_log4j: ["log4j", "log4shell", "jndi", "log4j2"],
      apache_activemq: ["activemq", "apache activemq"],
      apache_superset: ["superset", "apache superset"],
      apache_ofbiz: ["ofbiz", "apache ofbiz"],
      apache_solr: ["solr", "apache solr"],
      // VMware
      vmware_vcenter: ["vcenter", "vmware vcenter", "vsphere"],
      vmware_esxi: ["esxi", "vmware esxi", "hypervisor"],
      vmware_workspace: ["workspace one", "airwatch", "vmware workspace"],
      vmware_horizon: ["vmware horizon", "horizon"],
      // Fortinet
      fortinet_fortios: ["fortios", "fortigate", "fortiproxy", "fortinet"],
      fortinet_forticlient: ["forticlient", "fortinet forticlient", "forticlient ems"],
      // Ivanti / Pulse Secure
      ivanti_epmm: ["epmm", "mobileiron", "ivanti endpoint manager mobile"],
      ivanti_connect_secure: ["connect secure", "pulse secure", "ivanti connect", "pulse connect"],
      ivanti_sentry: ["ivanti sentry", "mobileiron sentry"],
      // Citrix
      citrix_adc: ["netscaler", "citrix adc", "citrix gateway", "citrix netscaler"],
      citrix_sharefile: ["sharefile", "citrix sharefile"],
      citrix_virtual_apps: ["citrix virtual apps", "xenapp", "xendesktop"],
      // Oracle
      oracle_weblogic: ["weblogic", "oracle weblogic"],
      oracle_java: ["java se", "jre", "oracle java", "jdk"],
      oracle_ebs: ["e-business suite", "oracle ebs"],
      // Linux
      linux_kernel: ["linux kernel", "linux", "kernel", "glibc"],
      // Network / Firewall
      paloalto_panos: ["pan-os", "panos", "globalprotect", "palo alto"],
      sonicwall_sma: ["sonicwall sma", "sonicwall sra", "sonicwall"],
      f5_bigip: ["big-ip", "bigip", "f5 big-ip", "f5 bigip"],
      zyxel: ["zyxel"],
      sophos: ["sophos", "sophos firewall", "xg firewall"],
      barracuda: ["barracuda", "barracuda esg", "email security gateway"],
      // NAS / Storage
      dlink_router: ["d-link", "dlink", "d-link router"],
      qnap: ["qnap", "qnap nas"],
      netgear: ["netgear"],
      // Collaboration / CMS
      zimbra: ["zimbra", "zimbra collaboration"],
      atlassian_confluence: ["confluence", "atlassian confluence"],
      atlassian_jira: ["jira", "atlassian jira"],
      drupal: ["drupal"],
      wordpress: ["wordpress", "wp-", "wp-admin"],
      joomla: ["joomla"],
      // DevOps / CI
      jenkins: ["jenkins"],
      gitlab: ["gitlab"],
      // Enterprise
      sap_netweaver: ["netweaver", "sap netweaver", "sap"],
      telerik: ["telerik", "progress telerik", "telerik ui"],
      veeam: ["veeam", "veeam backup"],
      connectwise: ["screenconnect", "connectwise"],
      mitel: ["mitel", "micollab"],
      moveit: ["moveit", "progress moveit", "moveit transfer"],
      // Languages / Runtimes
      php: ["php"],
      nodejs: ["node.js", "nodejs", "express"],
      python_django: ["django", "python django"],
      ruby_rails: ["rails", "ruby on rails"],
      // Browsers
      mozilla_firefox: ["firefox", "thunderbird", "mozilla firefox"],
      // Misc
      rejetto_hfs: ["rejetto", "hfs", "http file server"],
      samsung_mobile: ["samsung", "exynos", "samsung mobile"],
      microsoft_edge: ["edge", "microsoft edge"]
    };
    VENDOR_PRODUCT_RULES = [
      // Microsoft
      { vendor: "Microsoft", products: ["Windows", "Win32k", "MSHTML", "CLFS", "Kernel Streaming", "Windows Kernel", "NTFS", "Windows Ancillary", "Windows Task Scheduler", "Windows Hyper-V", "Windows DWM", "Windows MSHTML", "Windows SmartScreen", "Windows Mark of the Web", "Windows AppLocker"], family: "microsoft_windows" },
      { vendor: "Microsoft", products: ["Exchange Server", "Exchange"], family: "microsoft_exchange" },
      { vendor: "Microsoft", products: ["Office", "Excel", "Word", "Outlook", "PowerPoint", "Access", "Publisher"], family: "microsoft_office" },
      { vendor: "Microsoft", products: ["SharePoint"], family: "microsoft_sharepoint" },
      { vendor: "Microsoft", products: [".NET", "ASP.NET"], family: "microsoft_dotnet" },
      { vendor: "Microsoft", products: ["Internet Information Services", "IIS"], family: "microsoft_iis" },
      { vendor: "Microsoft", products: ["SQL Server"], family: "microsoft_sql_server" },
      { vendor: "Microsoft", products: ["Edge"], family: "microsoft_edge" },
      // Apple
      { vendor: "Apple", products: ["iOS", "iPadOS", "iPhone OS"], family: "apple_ios" },
      { vendor: "Apple", products: ["macOS", "OS X", "Mac OS X"], family: "apple_macos" },
      { vendor: "Apple", products: ["Safari", "WebKit", "Multiple Products"], family: "apple_webkit" },
      // Cisco
      { vendor: "Cisco", products: ["IOS", "IOS XE", "IOS XR"], family: "cisco_ios" },
      { vendor: "Cisco", products: ["Adaptive Security Appliance", "ASA", "Firepower"], family: "cisco_asa" },
      { vendor: "Cisco", products: ["Webex"], family: "cisco_webex" },
      { vendor: "Cisco", products: ["Small Business", "RV"], family: "cisco_small_business" },
      // Adobe
      { vendor: "Adobe", products: ["Acrobat", "Reader", "Acrobat and Reader"], family: "adobe_reader" },
      { vendor: "Adobe", products: ["Flash Player", "Flash"], family: "adobe_flash" },
      { vendor: "Adobe", products: ["ColdFusion"], family: "adobe_coldfusion" },
      { vendor: "Adobe", products: ["Commerce", "Magento"], family: "adobe_commerce" },
      // Google
      { vendor: "Google", products: ["Chromium", "Chrome"], family: "google_chrome" },
      { vendor: "Google", products: ["Android"], family: "google_android" },
      { vendor: "Android", products: [], family: "google_android" },
      { vendor: "Samsung", products: ["Mobile Devices", "Exynos"], family: "samsung_mobile" },
      { vendor: "Qualcomm", products: [], family: "google_android" },
      // Apache
      { vendor: "Apache", products: ["HTTP Server", "httpd"], family: "apache_http" },
      { vendor: "Apache", products: ["Tomcat"], family: "apache_tomcat" },
      { vendor: "Apache", products: ["Struts"], family: "apache_struts" },
      { vendor: "Apache", products: ["Log4j"], family: "apache_log4j" },
      { vendor: "Apache", products: ["ActiveMQ"], family: "apache_activemq" },
      { vendor: "Apache", products: ["Superset"], family: "apache_superset" },
      { vendor: "Apache", products: ["OFBiz"], family: "apache_ofbiz" },
      { vendor: "Apache", products: ["Solr"], family: "apache_solr" },
      // VMware
      { vendor: "VMware", products: ["vCenter", "vCenter Server"], family: "vmware_vcenter" },
      { vendor: "VMware", products: ["ESXi"], family: "vmware_esxi" },
      { vendor: "VMware", products: ["Workspace ONE", "AirWatch"], family: "vmware_workspace" },
      { vendor: "VMware", products: ["Horizon"], family: "vmware_horizon" },
      // Fortinet
      { vendor: "Fortinet", products: ["FortiOS", "FortiGate", "FortiProxy"], family: "fortinet_fortios" },
      { vendor: "Fortinet", products: ["FortiClient"], family: "fortinet_forticlient" },
      // Ivanti
      { vendor: "Ivanti", products: ["Endpoint Manager Mobile", "EPMM"], family: "ivanti_epmm" },
      { vendor: "MobileIron", products: [], family: "ivanti_epmm" },
      { vendor: "Ivanti", products: ["Connect Secure", "Policy Secure"], family: "ivanti_connect_secure" },
      { vendor: "Pulse Secure", products: [], family: "ivanti_connect_secure" },
      { vendor: "Ivanti", products: ["Sentry"], family: "ivanti_sentry" },
      // Citrix
      { vendor: "Citrix", products: ["ADC", "NetScaler", "Gateway"], family: "citrix_adc" },
      { vendor: "Citrix", products: ["ShareFile"], family: "citrix_sharefile" },
      { vendor: "Citrix", products: ["Virtual Apps"], family: "citrix_virtual_apps" },
      // Oracle
      { vendor: "Oracle", products: ["WebLogic"], family: "oracle_weblogic" },
      { vendor: "Oracle", products: ["Java SE", "Java", "JRE"], family: "oracle_java" },
      { vendor: "Oracle", products: ["E-Business"], family: "oracle_ebs" },
      // Linux
      { vendor: "Linux", products: ["Kernel"], family: "linux_kernel" },
      // Network / Firewall
      { vendor: "Palo Alto Networks", products: [], family: "paloalto_panos" },
      { vendor: "SonicWall", products: [], family: "sonicwall_sma" },
      { vendor: "F5", products: ["BIG-IP"], family: "f5_bigip" },
      { vendor: "Zyxel", products: [], family: "zyxel" },
      { vendor: "Sophos", products: [], family: "sophos" },
      { vendor: "Barracuda Networks", products: [], family: "barracuda" },
      { vendor: "D-Link", products: [], family: "dlink_router" },
      { vendor: "QNAP", products: [], family: "qnap" },
      { vendor: "NETGEAR", products: [], family: "netgear" },
      // Collaboration / CMS
      { vendor: "Synacor", products: ["Zimbra"], family: "zimbra" },
      { vendor: "Atlassian", products: ["Confluence"], family: "atlassian_confluence" },
      { vendor: "Atlassian", products: ["Jira"], family: "atlassian_jira" },
      { vendor: "Drupal", products: [], family: "drupal" },
      { vendor: "WordPress", products: [], family: "wordpress" },
      // DevOps
      { vendor: "Jenkins", products: [], family: "jenkins" },
      { vendor: "GitLab", products: [], family: "gitlab" },
      // Enterprise
      { vendor: "SAP", products: ["NetWeaver"], family: "sap_netweaver" },
      { vendor: "Progress", products: ["Telerik"], family: "telerik" },
      { vendor: "Telerik", products: [], family: "telerik" },
      { vendor: "Veeam", products: [], family: "veeam" },
      { vendor: "ConnectWise", products: [], family: "connectwise" },
      { vendor: "Mitel", products: [], family: "mitel" },
      { vendor: "Progress", products: ["MOVEit"], family: "moveit" },
      // Languages
      { vendor: "PHP Group", products: [], family: "php" },
      { vendor: "PHP", products: [], family: "php" },
      // Browsers
      { vendor: "Mozilla", products: ["Firefox", "Thunderbird"], family: "mozilla_firefox" },
      // Misc
      { vendor: "Rejetto", products: [], family: "rejetto_hfs" }
    ];
    kevIndex = /* @__PURE__ */ new Map();
    kevLoaded = false;
    kevLastRefresh = 0;
    KEV_REFRESH_INTERVAL = 24 * 60 * 60 * 1e3;
    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    STATIC_CVE_PRODUCT_MAP = {
      // Rejetto HFS
      "CVE-2024-23692": { family: "rejetto_hfs", keywords: ["rejetto", "hfs", "http file server"] },
      "CVE-2014-6287": { family: "rejetto_hfs", keywords: ["rejetto", "hfs", "http file server"] },
      // Log4Shell
      "CVE-2021-44228": { family: "apache_log4j", keywords: ["log4j", "log4shell", "jndi", "log4j2"] },
      "CVE-2021-45046": { family: "apache_log4j", keywords: ["log4j", "log4shell", "jndi", "log4j2"] },
      // EternalBlue / MS17-010
      "CVE-2017-0144": { family: "microsoft_windows", keywords: ["windows", "smb", "eternalblue"] },
      "CVE-2017-0145": { family: "microsoft_windows", keywords: ["windows", "smb", "eternalblue"] },
      "CVE-2017-0143": { family: "microsoft_windows", keywords: ["windows", "smb", "eternalblue"] },
      // ProxyShell / ProxyLogon
      "CVE-2021-34473": { family: "microsoft_exchange", keywords: ["exchange", "microsoft exchange", "proxyshell"] },
      "CVE-2021-34523": { family: "microsoft_exchange", keywords: ["exchange", "microsoft exchange", "proxyshell"] },
      "CVE-2021-31207": { family: "microsoft_exchange", keywords: ["exchange", "microsoft exchange", "proxyshell"] },
      "CVE-2021-26855": { family: "microsoft_exchange", keywords: ["exchange", "microsoft exchange", "proxylogon"] },
      "CVE-2021-27065": { family: "microsoft_exchange", keywords: ["exchange", "microsoft exchange", "proxylogon"] },
      // Apache Struts
      "CVE-2017-5638": { family: "apache_struts", keywords: ["struts", "apache struts"] },
      "CVE-2018-11776": { family: "apache_struts", keywords: ["struts", "apache struts"] },
      // Spring4Shell
      "CVE-2022-22965": { family: "apache_tomcat", keywords: ["spring", "spring4shell", "tomcat", "spring framework"] },
      // Citrix / NetScaler
      "CVE-2023-3519": { family: "citrix_adc", keywords: ["netscaler", "citrix adc", "citrix gateway"] },
      "CVE-2019-19781": { family: "citrix_adc", keywords: ["netscaler", "citrix adc", "citrix gateway"] },
      // MOVEit
      "CVE-2023-34362": { family: "moveit", keywords: ["moveit", "progress moveit", "moveit transfer"] },
      // Fortinet
      "CVE-2024-21762": { family: "fortinet_fortios", keywords: ["fortios", "fortigate", "fortinet"] },
      "CVE-2023-27997": { family: "fortinet_fortios", keywords: ["fortios", "fortigate", "fortinet"] },
      "CVE-2022-42475": { family: "fortinet_fortios", keywords: ["fortios", "fortigate", "fortinet"] },
      "CVE-2018-13379": { family: "fortinet_fortios", keywords: ["fortios", "fortigate", "fortinet"] },
      // Ivanti / Pulse Secure
      "CVE-2024-21887": { family: "ivanti_connect_secure", keywords: ["connect secure", "ivanti connect", "pulse secure"] },
      "CVE-2023-46805": { family: "ivanti_connect_secure", keywords: ["connect secure", "ivanti connect", "pulse secure"] },
      "CVE-2019-11510": { family: "ivanti_connect_secure", keywords: ["pulse secure", "pulse connect"] },
      // Palo Alto
      "CVE-2024-3400": { family: "paloalto_panos", keywords: ["pan-os", "panos", "globalprotect", "palo alto"] },
      // VMware
      "CVE-2021-21972": { family: "vmware_vcenter", keywords: ["vcenter", "vmware vcenter", "vsphere"] },
      "CVE-2021-22005": { family: "vmware_vcenter", keywords: ["vcenter", "vmware vcenter"] },
      // Confluence
      "CVE-2023-22515": { family: "atlassian_confluence", keywords: ["confluence", "atlassian confluence"] },
      "CVE-2022-26134": { family: "atlassian_confluence", keywords: ["confluence", "atlassian confluence"] },
      "CVE-2021-26084": { family: "atlassian_confluence", keywords: ["confluence", "atlassian confluence"] },
      // F5 BIG-IP
      "CVE-2022-1388": { family: "f5_bigip", keywords: ["big-ip", "bigip", "f5 big-ip"] },
      "CVE-2020-5902": { family: "f5_bigip", keywords: ["big-ip", "bigip", "f5 big-ip"] },
      // SonicWall
      "CVE-2021-20016": { family: "sonicwall_sma", keywords: ["sonicwall sma", "sonicwall"] },
      // Barracuda
      "CVE-2023-2868": { family: "barracuda", keywords: ["barracuda", "barracuda esg"] },
      // ConnectWise
      "CVE-2024-1709": { family: "connectwise", keywords: ["screenconnect", "connectwise"] },
      "CVE-2024-1708": { family: "connectwise", keywords: ["screenconnect", "connectwise"] },
      // Telerik
      "CVE-2019-18935": { family: "telerik", keywords: ["telerik", "progress telerik"] },
      // Veeam
      "CVE-2023-27532": { family: "veeam", keywords: ["veeam", "veeam backup"] },
      // Jenkins
      "CVE-2024-23897": { family: "jenkins", keywords: ["jenkins"] },
      // GitLab
      "CVE-2023-7028": { family: "gitlab", keywords: ["gitlab"] },
      // PHP
      "CVE-2024-4577": { family: "php", keywords: ["php", "php-cgi"] },
      // Zimbra
      "CVE-2022-27925": { family: "zimbra", keywords: ["zimbra", "zimbra collaboration"] },
      "CVE-2022-41352": { family: "zimbra", keywords: ["zimbra", "zimbra collaboration"] },
      // Oracle WebLogic
      "CVE-2020-14882": { family: "oracle_weblogic", keywords: ["weblogic", "oracle weblogic"] },
      "CVE-2019-2725": { family: "oracle_weblogic", keywords: ["weblogic", "oracle weblogic"] },
      // Drupal
      "CVE-2018-7600": { family: "drupal", keywords: ["drupal"] },
      // Adobe ColdFusion
      "CVE-2023-26360": { family: "adobe_coldfusion", keywords: ["coldfusion", "adobe coldfusion"] },
      "CVE-2023-29298": { family: "adobe_coldfusion", keywords: ["coldfusion", "adobe coldfusion"] },
      // Linux Kernel
      "CVE-2022-0847": { family: "linux_kernel", keywords: ["linux kernel", "linux", "dirty pipe"] },
      "CVE-2016-5195": { family: "linux_kernel", keywords: ["linux kernel", "linux", "dirty cow"] },
      // Sophos
      "CVE-2022-1040": { family: "sophos", keywords: ["sophos", "sophos firewall"] },
      // Apache ActiveMQ
      "CVE-2023-46604": { family: "apache_activemq", keywords: ["activemq", "apache activemq"] },
      // Mitel
      "CVE-2022-29499": { family: "mitel", keywords: ["mitel", "micollab"] }
    };
  }
});

export {
  loadKEVCatalog,
  ensureKEVLoaded,
  lookupCVEProduct,
  validateCVEAgainstTarget,
  getKEVStats,
  getRansomwareLinkedCVEs,
  init_cisa_kev_product_map
};
