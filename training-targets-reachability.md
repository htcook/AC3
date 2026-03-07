# Training Target Reachability Check (2026-03-07)

## REACHABLE (HTTP 200) - Ready for Pipeline Validation
1. https://brokencrystals.com/ → 200 ✅ (Node.js, 30+ vulns, GraphQL)
2. https://ginandjuice.shop/ → 200 ✅ (PortSwigger benchmark, 20+ vulns)
3. http://google-gruyere.appspot.com/start → 200 ✅ (Python/GAE, 10+ vulns)
4. https://public-firing-range.appspot.com/ → 200 ✅ (Google testbed, 50+ XSS/DOM vulns)
5. http://testasp.vulnweb.com/ → 200 ✅ (ASP/MSSQL, SQLi/dir traversal)
6. http://testaspnet.vulnweb.com/ → 200 ✅ (ASP.NET/MSSQL, SQLi/XSS)
7. http://testhtml5.vulnweb.com/ → 200 ✅ (Flask/CouchDB, HTML5/NoSQL vulns)
8. http://zero.webappsecurity.com/ → 200 ✅ (Tomcat, auth bypass/XSS)
9. http://hack-yourself-first.com/ → 200 ✅ (ASP.NET, Troy Hunt's training)
10. http://aspnet.testsparker.com/ → 200 ✅ (ASP.NET/MSSQL)
11. http://php.testsparker.com/ → 200 ✅ (PHP/MySQL)
12. http://angular.testsparker.com/ → 200 ✅ (Angular SPA/PHP/MySQL)
13. https://pentest-ground.com → 200 ✅ (Multiple vuln apps)
14. http://rest.vulnweb.com/ → 200 ✅ (REST API vulns)
15. http://scanme.nmap.org → 200 ✅ (Network scanning target)

## ALREADY CONFIGURED (existing targets)
- http://testphp.vulnweb.com/ (Acunetix Acuart)
- http://demo.testfire.net/ (IBM Altoro Mutual)
- https://juice-shop.herokuapp.com/ (OWASP Juice Shop)

## UNREACHABLE / DOWN
- http://hackazon.webscantest.com/ → 403 (Forbidden)
- http://webscantest.com/ → 403 (Forbidden)
- http://www.altoromutual.com:8080/ → TIMEOUT
- http://bwapp.ywnxs.com/ → TIMEOUT
- http://crackme.cenzic.com/ → TIMEOUT
- http://nodegoat.herokuapp.com/ → 404 (Heroku shutdown)

## RECOMMENDED ADDITIONS (15 new reachable targets)
Total targets after additions: 18 (3 existing + 15 new)
