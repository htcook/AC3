# Legal Pentesting Training Targets Research

## Currently Configured Targets
1. testphp.vulnweb.com (Acunetix Acuart) - PHP/MySQL
2. demo.testfire.net (IBM Altoro Mutual) - ASP.NET
3. juice-shop.herokuapp.com (OWASP Juice Shop) - Node.js

## New Online-Hosted Targets (Publicly Accessible, No Self-Hosting Required)

### Tier 1 - High Priority (Modern, Well-Documented, Online)

| # | Name | URL | Technology | Creds | Known Vulns |
|---|------|-----|-----------|-------|-------------|
| 4 | Broken Crystals | https://brokencrystals.com/ | Node.js, React, GraphQL | admin:admin | 30+ (JWT bypass, XSS, SQLi, SSRF, SSTI, CSRF, IDOR, XXE, LDAP injection, OS command injection, prototype pollution, brute force, cookie security, common files, open database, default login, email header injection, file upload, full path disclosure, header security, HTML injection, HTTP method tampering, mass assignment, secret tokens, unvalidated redirect, version control, GraphQL introspection, business constraint bypass, date manipulation, ID enumeration) |
| 5 | Gin & Juice Shop | https://ginandjuice.shop/ | AWS | unknown | 20+ (PortSwigger's benchmark - XSS, SQLi, SSRF, SSTI, XXE, CORS, clickjacking, DOM-based vulns, HTTP request smuggling, WebSocket vulns, deserialization, path traversal, authentication bypass, access control, information disclosure) |
| 6 | Hackazon | http://hackazon.webscantest.com/ | Apache, PHP, Ajax, JSON, XML, GWT, AMF | admin:admin:123456 | 15+ (XSS, SQLi, session fixation, CSRF, unvalidated redirects, file inclusion, command injection) |
| 7 | Google Gruyere | http://google-gruyere.appspot.com/start | Python, GAE | unknown | 10+ (XSS, CSRF, remote code execution, DoS, information disclosure) |
| 8 | Firing Range | https://public-firing-range.appspot.com/ | Google App Engine | unknown | 50+ (Google's testbed - DOM XSS, reflected XSS, CORS, reverse clickjacking, mixed content, flash injection, remote inclusion) |

### Tier 2 - Good Coverage (Online, Various Tech Stacks)

| # | Name | URL | Technology | Creds | Known Vulns |
|---|------|-----|-----------|-------|-------------|
| 9 | Acunetix Acuforum | http://testasp.vulnweb.com/ | IIS, ASP, MSSQL | unknown | 10+ (SQLi, directory traversal, web-based attacks) |
| 10 | Acunetix Acublog | http://testaspnet.vulnweb.com/ | IIS, ASP.NET, MSSQL | unknown | 10+ (SQLi, XSS, ASP.NET specific vulns) |
| 11 | Acunetix SecurityTweets | http://testhtml5.vulnweb.com/ | nginx, Python, Flask, CouchDB | admin:admin:1234 | 10+ (HTML5-specific vulns, NoSQL injection, XSS) |
| 12 | HP Zero Bank | http://zero.webappsecurity.com/ | Apache Tomcat | unknown | 8+ (authentication bypass, XSS, parameter tampering) |
| 13 | WebScanTest | http://webscantest.com/ | Apache, PHP | testuser:testpass | 10+ (common web vulns for scanner benchmarking) |
| 14 | Hack Yourself First | http://hack-yourself-first.com/ | IIS, ASP.NET | unknown | 8+ (Troy Hunt's training site - SQLi, XSS, CSRF, insecure direct object references) |
| 15 | IBM AltoroJ Mutual | http://www.altoromutual.com:8080/ | Tomcat, Java | jsmith:Demo1234 | 10+ (Java variant of Altoro Mutual) |

### Tier 3 - Specialized/Niche

| # | Name | URL | Technology | Creds | Known Vulns |
|---|------|-----|-----------|-------|-------------|
| 16 | Testsparker ASP.NET | http://aspnet.testsparker.com/ | IIS, ASP.NET, MSSQL | alan@turing.com:theturingtest | 8+ (ASP.NET specific vulns) |
| 17 | Testsparker PHP | http://php.testsparker.com/ | Apache, PHP, MySQL | admin:admin123456 | 8+ (PHP-specific vulns) |
| 18 | Testsparker Angular | http://angular.testsparker.com/ | Apache, PHP, Angular 5, MySQL | unknown | 8+ (SPA-specific vulns) |
| 19 | Pentest-Ground | https://pentest-ground.com | Apache, Nginx, Redis | unknown | Multiple deliberately vulnerable apps |
| 20 | bWAPP Online | http://bwapp.ywnxs.com/ | Ubuntu, Nginx, PHP | bee:bug | 100+ (OWASP Top 10 comprehensive) |
| 21 | Cenzic CrackMe Bank | http://crackme.cenzic.com/ | CentOS, Apache, PHP | unknown | 10+ (banking app vulns) |
| 22 | Acunetix REST API | http://rest.vulnweb.com/ | API | Basic Auth | API-specific vulns |
| 23 | OWASP NodeGoat | http://nodegoat.herokuapp.com/ | Node.js | unknown | OWASP Top 10 for Node.js |

### Network Scanning Targets
| # | Name | URL | Purpose |
|---|------|-----|---------|
| 24 | Nmap ScanMe | http://scanme.nmap.org | Authorized Nmap scanning target |

## Technology Coverage Matrix
| Technology | Targets |
|-----------|---------|
| PHP/MySQL | testphp.vulnweb.com, hackazon.webscantest.com, php.testsparker.com, bwapp.ywnxs.com, crackme.cenzic.com |
| ASP.NET/MSSQL | demo.testfire.net, testasp.vulnweb.com, testaspnet.vulnweb.com, aspnet.testsparker.com, hack-yourself-first.com |
| Node.js | juice-shop.herokuapp.com, brokencrystals.com, nodegoat.herokuapp.com |
| Python | testhtml5.vulnweb.com, google-gruyere.appspot.com |
| Java/Tomcat | zero.webappsecurity.com, altoromutual.com:8080 |
| Angular/SPA | angular.testsparker.com, ginandjuice.shop |
| GraphQL | brokencrystals.com |
| REST API | rest.vulnweb.com |

## Vulnerability Type Coverage
| Vuln Category | Best Targets |
|--------------|-------------|
| SQL Injection | testphp.vulnweb.com, brokencrystals.com, hackazon.webscantest.com, testasp.vulnweb.com |
| XSS (Reflected/Stored/DOM) | brokencrystals.com, public-firing-range.appspot.com, ginandjuice.shop, testphp.vulnweb.com |
| SSRF | brokencrystals.com, ginandjuice.shop |
| SSTI | brokencrystals.com, ginandjuice.shop |
| JWT/Auth Bypass | brokencrystals.com, juice-shop.herokuapp.com |
| CSRF | brokencrystals.com, google-gruyere.appspot.com, hack-yourself-first.com |
| XXE | brokencrystals.com, ginandjuice.shop |
| Command Injection | brokencrystals.com, hackazon.webscantest.com |
| IDOR | brokencrystals.com, juice-shop.herokuapp.com |
| NoSQL Injection | testhtml5.vulnweb.com |
| LDAP Injection | brokencrystals.com |
| GraphQL Vulns | brokencrystals.com |
| API Security | rest.vulnweb.com, brokencrystals.com |
| Prototype Pollution | brokencrystals.com |
| HTTP Request Smuggling | ginandjuice.shop |
| Deserialization | ginandjuice.shop |
