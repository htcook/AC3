# RoE Research Notes for Training Targets

## Acunetix Vulnweb (testphp, testasp, testaspnet, testhtml5, rest)
- Provider: Acunetix (Invicti)
- Statement: "These are intentionally vulnerable websites and web applications designed for testing web vulnerability scanners."
- URL: http://www.vulnweb.com/
- Rules: Designed for automated scanner testing. No explicit rate limits published. No brute-force restrictions mentioned.
- Allowed: Web vulnerability scanning, automated DAST testing
- Prohibited: Nothing explicitly stated beyond common sense (no DDoS)

## Nmap ScanMe (scanme.nmap.org)
- Provider: Nmap Project (Fyodor)
- Statement: "You are authorized to scan this machine with Nmap or other port scanners."
- Rules: "Try not to hammer on the server too hard. A few scans in a day is fine, but don't scan 100 times a day."
- Allowed: Port scanning, service detection, OS detection
- Prohibited: SSH brute-force password cracking, excessive scanning (>100/day)
- Rate limit: A few scans per day

## Google Gruyere (google-gruyere.appspot.com)
- Provider: Google
- Statement: "You are specifically granted authorization to attack the Gruyere application as directed."
- Rules: "You may not attack Gruyere in ways other than described in this codelab, nor may you attack App Engine directly or any other Google service."
- Allowed: XSS, CSRF, path traversal, info disclosure, DoS (on your instance), RCE (on your instance)
- Prohibited: Attacking App Engine infrastructure, attacking other Google services, attacks not described in the codelab
- Note: Each user gets their own sandboxed instance via /start URL

## Google Firing Range (public-firing-range.appspot.com)
- Provider: Google
- Statement: "Firing Range is a test bed for automated web application security scanners."
- Rules: Open source under Apache 2.0 license. Designed for automated scanner testing.
- Allowed: XSS testing, CORS testing, DOM manipulation testing, automated scanning
- Prohibited: Attacking App Engine infrastructure

## Altoro Mutual / demo.testfire.net
- Provider: HCL Technologies (formerly IBM)
- Statement: "Published for the sole purpose of demonstrating the effectiveness of HCL products in detecting web application vulnerabilities and website defects."
- Rules: "This site is not a real banking site. This site is provided 'as is' without warranty of any kind."
- Allowed: Web vulnerability scanning, SQL injection testing, XSS testing
- Prohibited: Nothing explicitly stated beyond it being a demo site

## Zero Bank (zero.webappsecurity.com)
- Provider: Micro Focus (now OpenText)
- Statement: "Use of this Web site indicates that you have read and agree to Micro Focus Fortify's Terms of Use"
- Rules: Designed for Fortify WebInspect testing
- Allowed: Web vulnerability scanning, auth testing
- Prohibited: Nothing explicitly stated

## OWASP Juice Shop
- Provider: OWASP Foundation
- License: MIT License
- Statement: Free software for security training
- Rules: Open source, designed for CTF and training. Online demo instance available.
- Allowed: All web vulnerability testing, CTF challenges
- Prohibited: Nothing - it's designed to be attacked

## Broken Crystals (brokencrystals.com)
- Provider: Bright Security (NeuraLegion)
- License: MIT License (GitHub)
- Statement: "A benchmark application that uses modern technologies and implements a set of common security vulnerabilities."
- Rules: "Only perform scans on instances you own or have explicit permission to test. Do not perform scans that could disrupt service. Use responsibly, respecting rate limits."
- Allowed: Web vulnerability scanning, API testing, GraphQL testing
- Prohibited: Disruptive scans, ignoring rate limits, destructive operations without permission

## Gin & Juice Shop (ginandjuice.shop)
- Provider: PortSwigger
- Statement: PortSwigger's DAST benchmark application
- Rules: Designed for Burp Suite testing. PortSwigger Terms of Use apply.
- Allowed: Web vulnerability scanning, DAST testing
- Prohibited: Nothing explicitly stated for the benchmark site

## Hack Yourself First (hack-yourself-first.com)
- Provider: Troy Hunt
- Statement: "Hack Yourself First advocates building up our cyber-offense skills"
- Rules: Designed for developer security training
- Allowed: SQL injection, XSS, CSRF testing, IDOR testing
- Prohibited: Nothing explicitly stated

## Testsparker sites (aspnet, php, angular)
- Provider: Invicti (formerly Netsparker)
- Statement: Test sites for Invicti/Netsparker scanner validation
- Rules: Designed for automated scanner testing
- Allowed: Web vulnerability scanning
- Prohibited: Nothing explicitly stated

## Pentest-Ground (pentest-ground.com)
- Provider: Community
- Statement: "Free playground with deliberately vulnerable web applications"
- Rules: Designed for scanner testing
- Allowed: Web vulnerability scanning, network scanning
- Prohibited: Nothing explicitly stated

## Hackazon (hackazon.webscantest.com)
- Provider: Rapid7
- Statement: Intentionally vulnerable e-commerce application
- Rules: Designed for security testing
- Allowed: Web vulnerability scanning, business logic testing
- Prohibited: Nothing explicitly stated

## WebScanTest (webscantest.com)
- Provider: Community
- Statement: General-purpose vulnerable web application
- Rules: Designed for scanner benchmarking
- Allowed: Web vulnerability scanning
- Prohibited: Nothing explicitly stated
