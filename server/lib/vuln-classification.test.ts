import { describe, it, expect } from 'vitest';
import { classifyVulnClass, VULN_CLASS_TO_OWASP } from './exploit-learning-engine';

describe('classifyVulnClass', () => {
  // ── Injection (A03) ──
  describe('SQL Injection', () => {
    it('classifies SQL injection from title', () => {
      expect(classifyVulnClass('SQL Injection in login form')).toBe('sqli');
    });
    it('classifies SQLi abbreviation', () => {
      expect(classifyVulnClass('[Nuclei] Blind SQLi via parameter')).toBe('sqli');
    });
    it('classifies union select', () => {
      expect(classifyVulnClass('Union Select data extraction')).toBe('sqli');
    });
  });

  describe('XSS', () => {
    it('classifies reflected XSS', () => {
      expect(classifyVulnClass('Reflected XSS in search param')).toBe('xss');
    });
    it('classifies stored XSS', () => {
      expect(classifyVulnClass('Stored XSS in testimonials')).toBe('xss');
    });
    it('classifies DOM XSS', () => {
      expect(classifyVulnClass('DOM-based XSS in subscription form')).toBe('xss');
    });
    it('classifies cross-site scripting full name', () => {
      expect(classifyVulnClass('Cross-Site Scripting vulnerability')).toBe('xss');
    });
  });

  describe('RCE / Command Injection', () => {
    it('classifies OS command injection', () => {
      expect(classifyVulnClass('OS Command Injection via /api/spawn')).toBe('rce');
    });
    it('classifies remote code execution', () => {
      expect(classifyVulnClass('Remote Code Execution in parser')).toBe('rce');
    });
    it('classifies RCE abbreviation', () => {
      expect(classifyVulnClass('RCE via deserialization chain')).toBe('rce');
    });
  });

  describe('SSTI', () => {
    it('classifies server-side template injection', () => {
      expect(classifyVulnClass('Server-Side Template Injection via doT')).toBe('ssti');
    });
    it('classifies template injection', () => {
      expect(classifyVulnClass('Template Injection in /api/render')).toBe('ssti');
    });
  });

  describe('XXE', () => {
    it('classifies XML External Entity', () => {
      expect(classifyVulnClass('XML External Entity in metadata endpoint')).toBe('xxe');
    });
    it('classifies XXE abbreviation', () => {
      expect(classifyVulnClass('XXE via /api/metadata')).toBe('xxe');
    });
  });

  describe('LDAP Injection', () => {
    it('classifies LDAP injection', () => {
      expect(classifyVulnClass('LDAP Injection in user search')).toBe('ldap_injection');
    });
  });

  describe('XPATH Injection', () => {
    it('classifies XPATH injection', () => {
      expect(classifyVulnClass('XPATH Injection in partner login')).toBe('xpath_injection');
    });
  });

  describe('Prototype Pollution', () => {
    it('classifies prototype pollution', () => {
      expect(classifyVulnClass('Client-Side Prototype Pollution')).toBe('prototype_pollution');
    });
    it('classifies server-side prototype pollution', () => {
      expect(classifyVulnClass('Server-Side Prototype Pollution via email endpoint')).toBe('prototype_pollution');
    });
  });

  describe('Code Injection', () => {
    it('classifies JavaScript injection', () => {
      expect(classifyVulnClass('Server-Side JavaScript Injection')).toBe('code_injection');
    });
    it('classifies SSJI', () => {
      expect(classifyVulnClass('SSJI via process_numbers')).toBe('code_injection');
    });
  });

  // ── File Inclusion / Upload ──
  describe('File Inclusion', () => {
    it('classifies LFI', () => {
      expect(classifyVulnClass('Local File Inclusion via /api/files')).toBe('file_inclusion');
    });
    it('classifies RFI', () => {
      expect(classifyVulnClass('Remote File Inclusion in safe-files')).toBe('file_inclusion');
    });
    it('classifies path traversal', () => {
      expect(classifyVulnClass('Path Traversal in file endpoint')).toBe('file_inclusion');
    });
  });

  describe('File Upload', () => {
    it('classifies unrestricted file upload', () => {
      expect(classifyVulnClass('Unrestricted File Upload in avatar')).toBe('file_upload');
    });
  });

  // ── SSRF / Cloud Metadata ──
  describe('SSRF', () => {
    it('classifies SSRF', () => {
      expect(classifyVulnClass('Server-Side Request Forgery via /api/file')).toBe('ssrf');
    });
    it('classifies cloud metadata access', () => {
      expect(classifyVulnClass('[Nuclei] DigitalOcean Metadata Service Check')).toBe('ssrf');
    });
  });

  // ── Authentication / JWT ──
  describe('Auth Bypass', () => {
    it('classifies broken authentication', () => {
      expect(classifyVulnClass('Broken Authentication in login')).toBe('auth_bypass');
    });
    it('classifies default credentials', () => {
      expect(classifyVulnClass('Default Credentials admin:admin')).toBe('auth_bypass');
    });
    it('classifies brute force', () => {
      expect(classifyVulnClass('Brute Force Login Attack')).toBe('auth_bypass');
    });
  });

  describe('JWT', () => {
    it('classifies JWT attacks', () => {
      expect(classifyVulnClass('JWT None Algorithm Bypass')).toBe('jwt_attack');
    });
    it('classifies JSON Web Token', () => {
      expect(classifyVulnClass('JSON Web Token signature bypass')).toBe('jwt_attack');
    });
  });

  // ── Access Control ──
  describe('Broken Access Control', () => {
    it('classifies IDOR', () => {
      expect(classifyVulnClass('Insecure Direct Object Reference')).toBe('broken_access_control');
    });
    it('classifies mass assignment', () => {
      expect(classifyVulnClass('Mass Assignment privilege escalation')).toBe('broken_access_control');
    });
    it('classifies BFLA', () => {
      expect(classifyVulnClass('BFLA in delete photo endpoint')).toBe('broken_access_control');
    });
    it('classifies BOPLA', () => {
      expect(classifyVulnClass('BOPLA in /api/users/me')).toBe('broken_access_control');
    });
  });

  describe('Open Redirect', () => {
    it('classifies open redirect', () => {
      expect(classifyVulnClass('Open Redirect via /api/goto')).toBe('open_redirect');
    });
    it('classifies unvalidated redirect', () => {
      expect(classifyVulnClass('Unvalidated Redirect in goto endpoint')).toBe('open_redirect');
    });
  });

  // ── Security Misconfiguration (A05) ──
  describe('Info Disclosure', () => {
    it('classifies .env file exposure', () => {
      expect(classifyVulnClass('[Nuclei] Laravel - Sensitive Information Disclosure @ .env')).toBe('info_disclosure');
    });
    it('classifies env file discovery', () => {
      expect(classifyVulnClass('[Nuclei] Codeigniter - .env File Discovery')).toBe('info_disclosure');
    });
    it('classifies config file exposure', () => {
      expect(classifyVulnClass('[Nuclei] Exposed JSON Configuration Files')).toBe('info_disclosure');
    });
    it('classifies configuration file detect', () => {
      expect(classifyVulnClass('[Nuclei] Configuration File - Detect')).toBe('info_disclosure');
    });
    it('classifies secret token exposure', () => {
      expect(classifyVulnClass('Secret Tokens Exposure via /api/secrets')).toBe('info_disclosure');
    });
    it('classifies full path disclosure', () => {
      expect(classifyVulnClass('Full Path Disclosure in error response')).toBe('info_disclosure');
    });
  });

  describe('VCS Exposure', () => {
    it('classifies git config detect', () => {
      expect(classifyVulnClass('[Nuclei] Git Configuration - Detect')).toBe('vcs_exposure');
    });
    it('classifies SVN exposure', () => {
      expect(classifyVulnClass('[Nuclei] SVN wc.db File Exposure')).toBe('vcs_exposure');
    });
    it('classifies version control system', () => {
      expect(classifyVulnClass('Version Control System Exposure')).toBe('vcs_exposure');
    });
  });

  describe('Missing Headers', () => {
    it('classifies missing security headers', () => {
      expect(classifyVulnClass('Missing Security Headers')).toBe('missing_headers');
    });
    it('classifies X-Frame-Options', () => {
      expect(classifyVulnClass('Missing X-Frame-Options header')).toBe('missing_headers');
    });
  });

  describe('Insecure Cookie', () => {
    it('classifies insecure cookie flags', () => {
      expect(classifyVulnClass('Cookie without Secure flag')).toBe('insecure_cookie');
    });
    it('classifies missing HttpOnly', () => {
      expect(classifyVulnClass('Cookie without HttpOnly flag')).toBe('insecure_cookie');
    });
  });

  describe('CORS Misconfiguration', () => {
    it('classifies CORS misconfiguration', () => {
      expect(classifyVulnClass('CORS Misconfiguration allows wildcard origin')).toBe('cors_misconfiguration');
    });
  });

  // ── Vulnerable Components ──
  describe('Vulnerable Components', () => {
    it('classifies Apache null pointer', () => {
      expect(classifyVulnClass('[Nuclei] Apache HTTP Server - NULL Pointer Dereference')).toBe('vulnerable_component');
    });
    it('classifies CVE references', () => {
      expect(classifyVulnClass('CVE-2021-44228 Log4Shell')).toBe('vulnerable_component');
    });
  });

  // ── Fallback ──
  describe('Unknown', () => {
    it('returns unknown for unrecognized patterns', () => {
      expect(classifyVulnClass('Some random finding')).toBe('unknown');
    });
  });

  // ── Real nuclei findings from engagement 1800033 ──
  describe('Real nuclei findings classification', () => {
    const realFindings = [
      { title: '[Nuclei] Apache HTTP Server - NULL Pointer Dereference', expected: 'vulnerable_component' },
      { title: '[Nuclei] Codeigniter - .env File Discovery', expected: 'info_disclosure' },
      { title: '[Nuclei] Exposed JSON Configuration Files', expected: 'info_disclosure' },
      { title: '[Nuclei] Laravel - Sensitive Information Disclosure', expected: 'info_disclosure' },
      { title: '[Nuclei] Generic Env File Disclosure', expected: 'info_disclosure' },
      { title: '[Nuclei] Git Configuration - Detect', expected: 'vcs_exposure' },
      { title: '[Nuclei] SVN wc.db File Exposure', expected: 'vcs_exposure' },
      { title: '[Nuclei] Configuration File - Detect', expected: 'info_disclosure' },
      { title: '[Nuclei] DigitalOcean Metadata Service Check', expected: 'ssrf' },
    ];

    for (const { title, expected } of realFindings) {
      it(`classifies "${title}" as ${expected}`, () => {
        expect(classifyVulnClass(title)).toBe(expected);
      });
    }

    it('none of the real findings should be "unknown"', () => {
      for (const { title } of realFindings) {
        expect(classifyVulnClass(title)).not.toBe('unknown');
      }
    });
  });
});

describe('VULN_CLASS_TO_OWASP', () => {
  it('maps sqli to A03', () => {
    expect(VULN_CLASS_TO_OWASP['sqli']).toBe('A03');
  });
  it('maps xss to A03', () => {
    expect(VULN_CLASS_TO_OWASP['xss']).toBe('A03');
  });
  it('maps info_disclosure to A05', () => {
    expect(VULN_CLASS_TO_OWASP['info_disclosure']).toBe('A05');
  });
  it('maps vcs_exposure to A05', () => {
    expect(VULN_CLASS_TO_OWASP['vcs_exposure']).toBe('A05');
  });
  it('maps ssrf to A10', () => {
    expect(VULN_CLASS_TO_OWASP['ssrf']).toBe('A10');
  });
  it('maps auth_bypass to A07', () => {
    expect(VULN_CLASS_TO_OWASP['auth_bypass']).toBe('A07');
  });
  it('maps jwt_attack to A07', () => {
    expect(VULN_CLASS_TO_OWASP['jwt_attack']).toBe('A07');
  });
  it('maps broken_access_control to A01', () => {
    expect(VULN_CLASS_TO_OWASP['broken_access_control']).toBe('A01');
  });
  it('maps vulnerable_component to A06', () => {
    expect(VULN_CLASS_TO_OWASP['vulnerable_component']).toBe('A06');
  });
  it('maps prototype_pollution to A03', () => {
    expect(VULN_CLASS_TO_OWASP['prototype_pollution']).toBe('A03');
  });
});
