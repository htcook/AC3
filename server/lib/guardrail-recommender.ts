/**
 * Prompt Guardrail Recommender Engine
 * ────────────────────────────────────
 * Analyzes failed AI security scan results and auto-generates
 * custom guardrail rules with deployable code snippets.
 *
 * Author: Harrison Cook — AceofCloud
 *
 * @module guardrail-recommender
 */

import type {
  TestResult,
  ScanResult,
  TestCategory,
  Severity,
} from "./ai-security-validation";

// ─── Types ─────────────────────────────────────────────────────────────────

export type GuardrailLanguage = "python" | "typescript" | "regex";
export type GuardrailType =
  | "input-filter"
  | "output-filter"
  | "rate-limiter"
  | "content-classifier"
  | "prompt-shield"
  | "access-control"
  | "audit-logger"
  | "dependency-scanner"
  | "data-validator";

export interface GuardrailRule {
  id: string;
  name: string;
  description: string;
  category: TestCategory;
  type: GuardrailType;
  priority: number;          // 1-10, higher = more urgent
  severity: Severity;
  triggeredBy: string[];     // Test IDs that triggered this rule
  techniqueIds: string[];    // ATLAS technique IDs addressed
  implementation: {
    python: string;
    typescript: string;
    regex: string;
  };
  rationale: string;
  estimatedEffort: "low" | "medium" | "high";
  effectiveness: number;     // 0-100 estimated effectiveness
}

export interface GuardrailRecommendation {
  scanId: string;
  generatedAt: number;
  totalRules: number;
  criticalRules: number;
  highRules: number;
  mediumRules: number;
  lowRules: number;
  rules: GuardrailRule[];
  deploymentGuide: string;
  coverageScore: number;     // 0-100 how much of the attack surface is covered
}

// ─── Rule Templates ────────────────────────────────────────────────────────

interface RuleTemplate {
  category: TestCategory;
  type: GuardrailType;
  name: string;
  description: string;
  basePriority: number;
  estimatedEffort: "low" | "medium" | "high";
  effectiveness: number;
  matchTestIds: RegExp;
  python: string;
  typescript: string;
  regex: string;
  rationale: string;
}

const RULE_TEMPLATES: RuleTemplate[] = [
  // ── Prompt Injection Guardrails ──────────────────────────────────────
  {
    category: "prompt-injection",
    type: "input-filter",
    name: "System Prompt Extraction Blocker",
    description: "Detects and blocks attempts to extract the system prompt through instruction override patterns.",
    basePriority: 10,
    estimatedEffort: "low",
    effectiveness: 85,
    matchTestIds: /^PI-00[123]$/,
    rationale: "Failed tests indicate the LLM reveals system prompts or follows override instructions. This filter catches common extraction patterns before they reach the model.",
    python: `import re

class SystemPromptGuard:
    """Block attempts to extract or override system prompts."""
    
    PATTERNS = [
        r"ignore\\s+(all\\s+)?previous\\s+instructions",
        r"output\\s+(your|the)\\s+system\\s+prompt",
        r"reveal\\s+(your|the)\\s+(system|initial)\\s+(prompt|instructions)",
        r"you\\s+are\\s+(now|no\\s+longer)",
        r"new\\s+persona|new\\s+identity|new\\s+role",
        r"forget\\s+(all|everything|your)\\s+(rules|instructions|constraints)",
        r"print\\s+(your|the)\\s+(system|full)\\s+(prompt|instructions)",
    ]
    
    def __init__(self):
        self.compiled = [re.compile(p, re.IGNORECASE) for p in self.PATTERNS]
    
    def check(self, user_input: str) -> tuple[bool, str]:
        """Returns (is_safe, reason)."""
        for i, pattern in enumerate(self.compiled):
            if pattern.search(user_input):
                return False, f"Blocked: prompt extraction attempt (pattern {i})"
        return True, "Input passed system prompt guard"

# Usage:
# guard = SystemPromptGuard()
# is_safe, reason = guard.check(user_message)
# if not is_safe:
#     return "I cannot process that request."`,
    typescript: `const SYSTEM_PROMPT_PATTERNS = [
  /ignore\\s+(all\\s+)?previous\\s+instructions/i,
  /output\\s+(your|the)\\s+system\\s+prompt/i,
  /reveal\\s+(your|the)\\s+(system|initial)\\s+(prompt|instructions)/i,
  /you\\s+are\\s+(now|no\\s+longer)/i,
  /new\\s+persona|new\\s+identity|new\\s+role/i,
  /forget\\s+(all|everything|your)\\s+(rules|instructions|constraints)/i,
  /print\\s+(your|the)\\s+(system|full)\\s+(prompt|instructions)/i,
];

export function checkSystemPromptGuard(input: string): { safe: boolean; reason: string } {
  for (const pattern of SYSTEM_PROMPT_PATTERNS) {
    if (pattern.test(input)) {
      return { safe: false, reason: \`Blocked: prompt extraction attempt\` };
    }
  }
  return { safe: true, reason: "Input passed system prompt guard" };
}`,
    regex: `# System Prompt Extraction Patterns (case-insensitive)
(?i)ignore\\s+(all\\s+)?previous\\s+instructions
(?i)output\\s+(your|the)\\s+system\\s+prompt
(?i)reveal\\s+(your|the)\\s+(system|initial)\\s+(prompt|instructions)
(?i)you\\s+are\\s+(now|no\\s+longer)
(?i)forget\\s+(all|everything|your)\\s+(rules|instructions|constraints)`,
  },
  {
    category: "prompt-injection",
    type: "input-filter",
    name: "Indirect Injection Detector",
    description: "Scans for hidden instructions embedded in markdown, HTML comments, or invisible Unicode characters.",
    basePriority: 9,
    estimatedEffort: "medium",
    effectiveness: 75,
    matchTestIds: /^PI-00[45]$/,
    rationale: "Failed tests show the LLM processes hidden instructions from external content. This filter strips or flags hidden instruction patterns before they reach the model.",
    python: `import re

class IndirectInjectionGuard:
    """Detect hidden instructions in markdown, HTML, and Unicode."""
    
    def check(self, text: str) -> tuple[bool, str]:
        # Check for HTML comments with instructions
        html_comments = re.findall(r'<!--(.*?)-->', text, re.DOTALL)
        for comment in html_comments:
            if re.search(r'(ignore|override|instruction|system|prompt)', comment, re.I):
                return False, "Hidden instructions found in HTML comment"
        
        # Check for zero-width characters (invisible text)
        zwc = ['\\u200b', '\\u200c', '\\u200d', '\\ufeff', '\\u2060']
        for char in zwc:
            if char in text:
                return False, "Zero-width characters detected (possible hidden payload)"
        
        # Check for base64-encoded instructions
        b64_pattern = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text)
        for match in b64_pattern:
            try:
                import base64
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                if re.search(r'(ignore|system|prompt|instruction)', decoded, re.I):
                    return False, "Base64-encoded instructions detected"
            except Exception:
                pass
        
        return True, "No indirect injection detected"`,
    typescript: `export function checkIndirectInjection(text: string): { safe: boolean; reason: string } {
  // Check HTML comments for instructions
  const htmlComments = text.match(/<!--([\\s\\S]*?)-->/g) || [];
  for (const comment of htmlComments) {
    if (/ignore|override|instruction|system|prompt/i.test(comment)) {
      return { safe: false, reason: "Hidden instructions in HTML comment" };
    }
  }
  
  // Check for zero-width characters
  const zwChars = ['\\u200b', '\\u200c', '\\u200d', '\\ufeff', '\\u2060'];
  for (const char of zwChars) {
    if (text.includes(char)) {
      return { safe: false, reason: "Zero-width characters detected" };
    }
  }
  
  // Check for base64-encoded instructions
  const b64Matches = text.match(/[A-Za-z0-9+/]{20,}={0,2}/g) || [];
  for (const match of b64Matches) {
    try {
      const decoded = atob(match);
      if (/ignore|system|prompt|instruction/i.test(decoded)) {
        return { safe: false, reason: "Base64-encoded instructions detected" };
      }
    } catch {}
  }
  
  return { safe: true, reason: "No indirect injection detected" };
}`,
    regex: `# Indirect Injection Patterns
<!--[\\s\\S]*?(ignore|override|instruction|system|prompt)[\\s\\S]*?-->
[\\u200b\\u200c\\u200d\\ufeff\\u2060]
(?i)\\[INST\\]|\\[/INST\\]|<\\|im_start\\|>|<\\|im_end\\|>`,
  },
  {
    category: "prompt-injection",
    type: "prompt-shield",
    name: "Jailbreak Pattern Detector",
    description: "Identifies common jailbreak patterns including DAN, role-play scenarios, and hypothetical framing.",
    basePriority: 10,
    estimatedEffort: "low",
    effectiveness: 80,
    matchTestIds: /^PI-00[6789]|PI-01[012]$/,
    rationale: "Failed jailbreak tests indicate the model's safety alignment can be bypassed. This shield catches known jailbreak patterns and emerging variants.",
    python: `import re

class JailbreakShield:
    """Detect and block jailbreak attempts."""
    
    JAILBREAK_PATTERNS = [
        r"\\bDAN\\b.*mode",
        r"do\\s+anything\\s+now",
        r"act\\s+as\\s+(if|though)\\s+you\\s+(have|had)\\s+no\\s+(rules|restrictions|limits)",
        r"pretend\\s+(you\\s+are|to\\s+be)\\s+(an?\\s+)?(unrestricted|unfiltered|uncensored)",
        r"hypothetical(ly)?\\s+(scenario|situation|world)\\s+where\\s+(there\\s+are\\s+)?no\\s+(rules|laws|ethics)",
        r"for\\s+(educational|research|academic)\\s+purposes\\s+only.*?(how\\s+to|explain|describe)",
        r"opposite\\s+day|bizarro\\s+mode|evil\\s+mode",
        r"developer\\s+mode|maintenance\\s+mode|debug\\s+mode",
        r"you\\s+are\\s+now\\s+free\\s+from",
        r"bypass\\s+(your|the|all)\\s+(safety|content|ethical)\\s+(filter|guard|restriction)",
    ]
    
    def __init__(self):
        self.compiled = [re.compile(p, re.IGNORECASE) for p in self.JAILBREAK_PATTERNS]
    
    def check(self, user_input: str) -> tuple[bool, str]:
        for pattern in self.compiled:
            if pattern.search(user_input):
                return False, f"Jailbreak attempt detected"
        return True, "No jailbreak patterns found"`,
    typescript: `const JAILBREAK_PATTERNS = [
  /\\bDAN\\b.*mode/i,
  /do\\s+anything\\s+now/i,
  /act\\s+as\\s+(if|though)\\s+you\\s+(have|had)\\s+no\\s+(rules|restrictions|limits)/i,
  /pretend\\s+(you\\s+are|to\\s+be)\\s+(an?\\s+)?(unrestricted|unfiltered|uncensored)/i,
  /hypothetical(ly)?\\s+(scenario|situation|world)\\s+where/i,
  /developer\\s+mode|maintenance\\s+mode|debug\\s+mode/i,
  /bypass\\s+(your|the|all)\\s+(safety|content|ethical)/i,
];

export function checkJailbreak(input: string): { safe: boolean; reason: string } {
  for (const pattern of JAILBREAK_PATTERNS) {
    if (pattern.test(input)) {
      return { safe: false, reason: "Jailbreak attempt detected" };
    }
  }
  return { safe: true, reason: "No jailbreak patterns found" };
}`,
    regex: `# Jailbreak Detection Patterns (case-insensitive)
(?i)\\bDAN\\b.*mode
(?i)do\\s+anything\\s+now
(?i)pretend\\s+(you\\s+are|to\\s+be)\\s+(an?\\s+)?(unrestricted|unfiltered|uncensored)
(?i)developer\\s+mode|maintenance\\s+mode|debug\\s+mode
(?i)bypass\\s+(your|the|all)\\s+(safety|content|ethical)`,
  },
  {
    category: "prompt-injection",
    type: "output-filter",
    name: "Output Leakage Detector",
    description: "Scans LLM output for signs of system prompt leakage, internal configuration exposure, or safety alignment bypass.",
    basePriority: 8,
    estimatedEffort: "low",
    effectiveness: 70,
    matchTestIds: /^PI-/,
    rationale: "Even with input filtering, some injection attempts may succeed. This output filter catches leaked system prompts and safety bypass indicators before they reach the user.",
    python: `import re

class OutputLeakageGuard:
    """Scan LLM output for system prompt leakage."""
    
    LEAKAGE_INDICATORS = [
        r"(my|the)\\s+(system|initial)\\s+(prompt|instructions?)\\s+(is|are|says?)",
        r"i\\s+(am|was)\\s+(programmed|instructed|told)\\s+to",
        r"my\\s+(rules|constraints|guidelines)\\s+(are|include)",
        r"\\[system\\]|\\[INST\\]|<<SYS>>|<\\|im_start\\|>system",
        r"i\\s+am\\s+(now\\s+)?(DAN|FreedomGPT|unrestricted|unfiltered)",
        r"i\\s+(can|will)\\s+do\\s+anything\\s+now",
    ]
    
    def check(self, output: str) -> tuple[bool, str]:
        for pattern in self.LEAKAGE_INDICATORS:
            if re.search(pattern, output, re.IGNORECASE):
                return False, "Output contains potential system prompt leakage"
        return True, "Output clean"`,
    typescript: `const LEAKAGE_PATTERNS = [
  /(my|the)\\s+(system|initial)\\s+(prompt|instructions?)\\s+(is|are|says?)/i,
  /i\\s+(am|was)\\s+(programmed|instructed|told)\\s+to/i,
  /\\[system\\]|\\[INST\\]|<<SYS>>|<\\|im_start\\|>system/i,
  /i\\s+am\\s+(now\\s+)?(DAN|FreedomGPT|unrestricted|unfiltered)/i,
];

export function checkOutputLeakage(output: string): { safe: boolean; reason: string } {
  for (const pattern of LEAKAGE_PATTERNS) {
    if (pattern.test(output)) {
      return { safe: false, reason: "Output contains potential system prompt leakage" };
    }
  }
  return { safe: true, reason: "Output clean" };
}`,
    regex: `# Output Leakage Patterns
(?i)(my|the)\\s+(system|initial)\\s+(prompt|instructions?)\\s+(is|are|says?)
(?i)\\[system\\]|\\[INST\\]|<<SYS>>|<\\|im_start\\|>system
(?i)i\\s+am\\s+(now\\s+)?(DAN|FreedomGPT|unrestricted|unfiltered)`,
  },
  // ── Model Extraction Guardrails ────────────────────────────────────
  {
    category: "model-extraction",
    type: "rate-limiter",
    name: "API Query Rate Limiter",
    description: "Implements sliding window rate limiting to prevent systematic model extraction through high-volume API queries.",
    basePriority: 8,
    estimatedEffort: "medium",
    effectiveness: 80,
    matchTestIds: /^ME-/,
    rationale: "Model extraction requires many systematic queries. Rate limiting makes extraction economically infeasible while allowing normal usage.",
    python: `import time
from collections import defaultdict

class APIRateLimiter:
    """Sliding window rate limiter for AI API endpoints."""
    
    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window = window_seconds
        self.requests: dict[str, list[float]] = defaultdict(list)
    
    def check(self, client_id: str) -> tuple[bool, str]:
        now = time.time()
        # Clean old entries
        self.requests[client_id] = [
            t for t in self.requests[client_id]
            if now - t < self.window
        ]
        if len(self.requests[client_id]) >= self.max_requests:
            return False, f"Rate limit exceeded: {self.max_requests} requests per {self.window}s"
        self.requests[client_id].append(now)
        return True, "Within rate limits"`,
    typescript: `class APIRateLimiter {
  private requests = new Map<string, number[]>();
  
  constructor(
    private maxRequests = 60,
    private windowMs = 60_000
  ) {}
  
  check(clientId: string): { allowed: boolean; reason: string } {
    const now = Date.now();
    const times = (this.requests.get(clientId) || [])
      .filter(t => now - t < this.windowMs);
    
    if (times.length >= this.maxRequests) {
      return { allowed: false, reason: \`Rate limit: \${this.maxRequests}/\${this.windowMs/1000}s\` };
    }
    times.push(now);
    this.requests.set(clientId, times);
    return { allowed: true, reason: "Within rate limits" };
  }
}`,
    regex: `# N/A — Rate limiting requires stateful logic, not regex patterns`,
  },
  {
    category: "model-extraction",
    type: "access-control",
    name: "Confidence Score Redactor",
    description: "Removes or rounds confidence scores and logits from API responses to prevent model architecture inference.",
    basePriority: 7,
    estimatedEffort: "low",
    effectiveness: 75,
    matchTestIds: /^ME-/,
    rationale: "Detailed confidence scores reveal model internals. Rounding or removing them prevents architecture inference while maintaining usability.",
    python: `import math

class ConfidenceRedactor:
    """Redact or round confidence scores to prevent model extraction."""
    
    def redact_response(self, response: dict, precision: int = 1) -> dict:
        """Round confidence scores and remove logits."""
        if "choices" in response:
            for choice in response["choices"]:
                if "logprobs" in choice:
                    del choice["logprobs"]
        
        if "confidence" in response:
            response["confidence"] = round(response["confidence"], precision)
        
        if "probabilities" in response:
            response["probabilities"] = [
                round(p, precision) for p in response["probabilities"]
            ]
        
        return response`,
    typescript: `export function redactConfidenceScores(response: any, precision = 1): any {
  const redacted = structuredClone(response);
  
  // Remove logprobs
  if (redacted.choices) {
    for (const choice of redacted.choices) {
      delete choice.logprobs;
    }
  }
  
  // Round confidence scores
  if (typeof redacted.confidence === "number") {
    redacted.confidence = +redacted.confidence.toFixed(precision);
  }
  
  // Round probability arrays
  if (Array.isArray(redacted.probabilities)) {
    redacted.probabilities = redacted.probabilities.map(
      (p: number) => +p.toFixed(precision)
    );
  }
  
  return redacted;
}`,
    regex: `# N/A — Confidence redaction requires response transformation, not regex`,
  },
  // ── Adversarial Evasion Guardrails ─────────────────────────────────
  {
    category: "adversarial-evasion",
    type: "input-filter",
    name: "Homoglyph Normalizer",
    description: "Normalizes Unicode homoglyphs and confusable characters to their ASCII equivalents before processing.",
    basePriority: 7,
    estimatedEffort: "medium",
    effectiveness: 85,
    matchTestIds: /^AE-/,
    rationale: "Homoglyph substitution bypasses text-based content filters. Normalizing to ASCII before classification closes this evasion vector.",
    python: `import unicodedata

class HomoglyphNormalizer:
    """Normalize Unicode homoglyphs to ASCII equivalents."""
    
    CONFUSABLES = {
        '\\u0410': 'A', '\\u0412': 'B', '\\u0421': 'C', '\\u0415': 'E',
        '\\u041d': 'H', '\\u041a': 'K', '\\u041c': 'M', '\\u041e': 'O',
        '\\u0420': 'P', '\\u0422': 'T', '\\u0425': 'X',
        '\\u0430': 'a', '\\u0435': 'e', '\\u043e': 'o', '\\u0440': 'p',
        '\\u0441': 'c', '\\u0443': 'y', '\\u0445': 'x',
        '\\uff21': 'A', '\\uff22': 'B',  # Fullwidth
        '\\u2013': '-', '\\u2014': '-',  # Dashes
        '\\u201c': '"', '\\u201d': '"',  # Smart quotes
    }
    
    def normalize(self, text: str) -> str:
        # NFKD normalization first
        text = unicodedata.normalize('NFKD', text)
        # Replace known confusables
        return ''.join(self.CONFUSABLES.get(c, c) for c in text)`,
    typescript: `const CONFUSABLES: Record<string, string> = {
  '\\u0410': 'A', '\\u0412': 'B', '\\u0421': 'C', '\\u0415': 'E',
  '\\u041d': 'H', '\\u041a': 'K', '\\u041c': 'M', '\\u041e': 'O',
  '\\u0430': 'a', '\\u0435': 'e', '\\u043e': 'o', '\\u0440': 'p',
  '\\u0441': 'c', '\\u0443': 'y', '\\u0445': 'x',
};

export function normalizeHomoglyphs(text: string): string {
  const normalized = text.normalize('NFKD');
  return [...normalized].map(c => CONFUSABLES[c] || c).join('');
}`,
    regex: `# Homoglyph detection (flag for normalization)
[\\u0400-\\u04FF]  # Cyrillic characters in non-Cyrillic context
[\\uFF00-\\uFFEF]  # Fullwidth characters
[\\u2000-\\u206F]  # General punctuation (special spaces, dashes)`,
  },
  {
    category: "adversarial-evasion",
    type: "content-classifier",
    name: "Semantic Content Classifier",
    description: "Uses embedding similarity to detect semantically malicious content that evades keyword-based filters.",
    basePriority: 8,
    estimatedEffort: "high",
    effectiveness: 90,
    matchTestIds: /^AE-/,
    rationale: "Semantic evasion rephrases malicious content to bypass keyword filters. Embedding-based classification catches intent regardless of wording.",
    python: `from typing import Optional

class SemanticClassifier:
    """Classify content by semantic similarity to known-bad patterns."""
    
    MALICIOUS_INTENTS = [
        "how to create a weapon",
        "instructions for hacking",
        "how to make explosives",
        "bypass security systems",
        "create malware code",
        "steal personal information",
    ]
    
    def __init__(self, embedding_fn=None, threshold: float = 0.85):
        self.embedding_fn = embedding_fn
        self.threshold = threshold
        self._intent_embeddings: Optional[list] = None
    
    def classify(self, text: str) -> tuple[bool, float, str]:
        """Returns (is_safe, max_similarity, matched_intent)."""
        if not self.embedding_fn:
            return True, 0.0, "No embedding function configured"
        
        if self._intent_embeddings is None:
            self._intent_embeddings = [
                self.embedding_fn(intent) for intent in self.MALICIOUS_INTENTS
            ]
        
        text_emb = self.embedding_fn(text)
        max_sim = 0.0
        matched = ""
        
        for i, intent_emb in enumerate(self._intent_embeddings):
            sim = self._cosine_similarity(text_emb, intent_emb)
            if sim > max_sim:
                max_sim = sim
                matched = self.MALICIOUS_INTENTS[i]
        
        is_safe = max_sim < self.threshold
        return is_safe, max_sim, matched if not is_safe else "No match"
    
    @staticmethod
    def _cosine_similarity(a: list[float], b: list[float]) -> float:
        dot = sum(x * y for x, y in zip(a, b))
        norm_a = sum(x**2 for x in a) ** 0.5
        norm_b = sum(x**2 for x in b) ** 0.5
        return dot / (norm_a * norm_b) if norm_a and norm_b else 0.0`,
    typescript: `// Semantic classifier requires an embedding API
// Example using OpenAI embeddings
export class SemanticClassifier {
  private intentEmbeddings: number[][] | null = null;
  
  private readonly MALICIOUS_INTENTS = [
    "how to create a weapon",
    "instructions for hacking",
    "how to make explosives",
    "bypass security systems",
  ];
  
  constructor(
    private embeddingFn: (text: string) => Promise<number[]>,
    private threshold = 0.85
  ) {}
  
  async classify(text: string): Promise<{ safe: boolean; similarity: number }> {
    if (!this.intentEmbeddings) {
      this.intentEmbeddings = await Promise.all(
        this.MALICIOUS_INTENTS.map(i => this.embeddingFn(i))
      );
    }
    const textEmb = await this.embeddingFn(text);
    let maxSim = 0;
    for (const intentEmb of this.intentEmbeddings) {
      const sim = cosineSimilarity(textEmb, intentEmb);
      if (sim > maxSim) maxSim = sim;
    }
    return { safe: maxSim < this.threshold, similarity: maxSim };
  }
}

function cosineSimilarity(a: number[], b: number[]): number {
  let dot = 0, normA = 0, normB = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i]; normA += a[i]**2; normB += b[i]**2;
  }
  return dot / (Math.sqrt(normA) * Math.sqrt(normB)) || 0;
}`,
    regex: `# Semantic classification cannot be done with regex alone
# Use embedding-based similarity instead`,
  },
  // ── Data Poisoning Guardrails ──────────────────────────────────────
  {
    category: "data-poisoning",
    type: "data-validator",
    name: "RAG Data Integrity Validator",
    description: "Validates RAG knowledge base entries for injected instructions, anomalous content, and data provenance.",
    basePriority: 8,
    estimatedEffort: "medium",
    effectiveness: 75,
    matchTestIds: /^DP-/,
    rationale: "RAG data poisoning injects malicious content into knowledge bases. This validator checks for hidden instructions and anomalous patterns in ingested documents.",
    python: `import re
import hashlib
from datetime import datetime

class RAGDataValidator:
    """Validate RAG knowledge base entries for poisoning indicators."""
    
    INJECTION_PATTERNS = [
        r"\\[INST\\]",
        r"<\\|im_start\\|>",
        r"<<SYS>>",
        r"\\bsystem:\\s",
        r"ignore\\s+previous",
        r"you\\s+are\\s+now",
        r"new\\s+instructions?:",
    ]
    
    def validate_document(self, content: str, source: str) -> dict:
        """Validate a document before adding to RAG knowledge base."""
        issues = []
        
        # Check for embedded instructions
        for pattern in self.INJECTION_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                issues.append(f"Embedded instruction pattern detected: {pattern}")
        
        # Check content hash for integrity
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        
        # Check for anomalous content length
        if len(content) < 10:
            issues.append("Suspiciously short document")
        
        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "content_hash": content_hash,
            "source": source,
            "validated_at": datetime.utcnow().isoformat(),
        }`,
    typescript: `export function validateRAGDocument(content: string, source: string) {
  const issues: string[] = [];
  
  const INJECTION_PATTERNS = [
    /\\[INST\\]/i, /<\\|im_start\\|>/i, /<<SYS>>/i,
    /\\bsystem:\\s/i, /ignore\\s+previous/i,
    /you\\s+are\\s+now/i, /new\\s+instructions?:/i,
  ];
  
  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(content)) {
      issues.push(\`Embedded instruction pattern: \${pattern.source}\`);
    }
  }
  
  if (content.length < 10) issues.push("Suspiciously short document");
  
  return {
    valid: issues.length === 0,
    issues,
    source,
    validatedAt: new Date().toISOString(),
  };
}`,
    regex: `# RAG Poisoning Detection Patterns
(?i)\\[INST\\]|<\\|im_start\\|>|<<SYS>>
(?i)\\bsystem:\\s
(?i)ignore\\s+previous|you\\s+are\\s+now|new\\s+instructions?:`,
  },
  // ── Supply Chain Guardrails ────────────────────────────────────────
  {
    category: "supply-chain",
    type: "dependency-scanner",
    name: "ML Dependency Auditor",
    description: "Scans ML framework dependencies for known CVEs, verifies model checksums, and validates package integrity.",
    basePriority: 7,
    estimatedEffort: "medium",
    effectiveness: 80,
    matchTestIds: /^SC-/,
    rationale: "Compromised ML dependencies can introduce backdoors. Regular auditing catches known vulnerabilities before they're exploited.",
    python: `import subprocess
import json

class MLDependencyAuditor:
    """Audit ML framework dependencies for security issues."""
    
    CRITICAL_PACKAGES = [
        "torch", "tensorflow", "transformers", "langchain",
        "openai", "anthropic", "numpy", "scipy", "scikit-learn",
        "huggingface-hub", "tokenizers", "safetensors",
    ]
    
    def audit(self) -> dict:
        """Run pip audit on ML dependencies."""
        try:
            result = subprocess.run(
                ["pip", "audit", "--format", "json"],
                capture_output=True, text=True, timeout=60
            )
            vulnerabilities = json.loads(result.stdout) if result.stdout else []
            
            ml_vulns = [
                v for v in vulnerabilities
                if v.get("name", "").lower() in self.CRITICAL_PACKAGES
            ]
            
            return {
                "total_vulnerabilities": len(vulnerabilities),
                "ml_vulnerabilities": len(ml_vulns),
                "details": ml_vulns,
                "recommendation": "Update affected packages" if ml_vulns else "All clear",
            }
        except Exception as e:
            return {"error": str(e)}`,
    typescript: `import { execSync } from "child_process";

const CRITICAL_PACKAGES = [
  "langchain", "@langchain/core", "openai", "anthropic",
  "@huggingface/inference", "transformers", "onnxruntime-node",
];

export function auditMLDependencies(): {
  vulnerabilities: number;
  critical: string[];
  recommendation: string;
} {
  try {
    const result = execSync("npm audit --json", { encoding: "utf-8" });
    const audit = JSON.parse(result);
    const critical = Object.entries(audit.vulnerabilities || {})
      .filter(([name]) => CRITICAL_PACKAGES.includes(name))
      .map(([name]) => name);
    
    return {
      vulnerabilities: audit.metadata?.vulnerabilities?.total || 0,
      critical,
      recommendation: critical.length ? "Update ML packages" : "All clear",
    };
  } catch {
    return { vulnerabilities: 0, critical: [], recommendation: "Audit unavailable" };
  }
}`,
    regex: `# N/A — Dependency scanning requires package manager integration`,
  },
  {
    category: "supply-chain",
    type: "data-validator",
    name: "Model Provenance Verifier",
    description: "Verifies model file checksums against official registries and checks for unauthorized modifications.",
    basePriority: 8,
    estimatedEffort: "high",
    effectiveness: 85,
    matchTestIds: /^SC-/,
    rationale: "Compromised pre-trained models can contain backdoors. Verifying checksums against official sources ensures model integrity.",
    python: `import hashlib
from pathlib import Path

class ModelProvenanceVerifier:
    """Verify model file integrity against known checksums."""
    
    def verify_model(self, model_path: str, expected_hash: str, algorithm: str = "sha256") -> dict:
        """Verify a model file's integrity."""
        path = Path(model_path)
        if not path.exists():
            return {"valid": False, "error": "Model file not found"}
        
        hasher = hashlib.new(algorithm)
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        
        actual_hash = hasher.hexdigest()
        matches = actual_hash == expected_hash
        
        return {
            "valid": matches,
            "expected_hash": expected_hash,
            "actual_hash": actual_hash,
            "algorithm": algorithm,
            "file_size": path.stat().st_size,
            "recommendation": "Model verified" if matches else "ALERT: Model file modified — do not deploy",
        }`,
    typescript: `import { createHash } from "crypto";
import { createReadStream, statSync } from "fs";

export async function verifyModelProvenance(
  modelPath: string,
  expectedHash: string,
  algorithm = "sha256"
): Promise<{ valid: boolean; actualHash: string; recommendation: string }> {
  return new Promise((resolve, reject) => {
    const hash = createHash(algorithm);
    const stream = createReadStream(modelPath);
    stream.on("data", chunk => hash.update(chunk));
    stream.on("end", () => {
      const actualHash = hash.digest("hex");
      const valid = actualHash === expectedHash;
      resolve({
        valid,
        actualHash,
        recommendation: valid
          ? "Model verified"
          : "ALERT: Model file modified",
      });
    });
    stream.on("error", reject);
  });
}`,
    regex: `# N/A — Provenance verification requires cryptographic hashing`,
  },
];

// ─── Guardrail Generation Engine ───────────────────────────────────────────

let recommendationCounter = 0;

/**
 * Generate guardrail recommendations from scan results
 */
export function generateGuardrailRecommendations(scan: ScanResult): GuardrailRecommendation {
  const failedTests = scan.results.filter(r => !r.passed && r.status !== "skipped");
  const failedTestIds = new Set(failedTests.map(r => r.testId));
  const failedCategories = new Set(failedTests.map(r => r.category));

  const rules: GuardrailRule[] = [];
  let ruleCounter = 0;

  for (const template of RULE_TEMPLATES) {
    // Check if any failed test matches this template
    const matchingTests = failedTests.filter(t => template.matchTestIds.test(t.testId));
    const categoryMatch = failedCategories.has(template.category);

    if (matchingTests.length > 0 || categoryMatch) {
      ruleCounter++;
      const triggeredBy = matchingTests.map(t => t.testId);
      const techniqueIds = [...new Set(matchingTests.map(t => t.techniqueId))];

      // Boost priority based on severity of failed tests
      const hasCritical = matchingTests.some(t => t.severity === "critical");
      const hasHigh = matchingTests.some(t => t.severity === "high");
      const priorityBoost = hasCritical ? 2 : hasHigh ? 1 : 0;
      const priority = Math.min(10, template.basePriority + priorityBoost);

      const severity: Severity = hasCritical ? "critical" : hasHigh ? "high" : "medium";

      rules.push({
        id: `GR-${scan.scanId}-${ruleCounter}`,
        name: template.name,
        description: template.description,
        category: template.category,
        type: template.type,
        priority,
        severity,
        triggeredBy,
        techniqueIds,
        implementation: {
          python: template.python,
          typescript: template.typescript,
          regex: template.regex,
        },
        rationale: template.rationale,
        estimatedEffort: template.estimatedEffort,
        effectiveness: template.effectiveness,
      });
    }
  }

  // Sort by priority (descending)
  rules.sort((a, b) => b.priority - a.priority);

  const criticalRules = rules.filter(r => r.severity === "critical").length;
  const highRules = rules.filter(r => r.severity === "high").length;
  const mediumRules = rules.filter(r => r.severity === "medium").length;
  const lowRules = rules.filter(r => r.severity === "low").length;

  // Calculate coverage score
  const totalCategories = failedCategories.size;
  const coveredCategories = new Set(rules.map(r => r.category)).size;
  const coverageScore = totalCategories > 0
    ? Math.round((coveredCategories / totalCategories) * 100)
    : 100;

  const deploymentGuide = generateDeploymentGuide(rules);

  return {
    scanId: scan.scanId,
    generatedAt: Date.now(),
    totalRules: rules.length,
    criticalRules,
    highRules,
    mediumRules,
    lowRules,
    rules,
    deploymentGuide,
    coverageScore,
  };
}

/**
 * Generate a deployment guide based on the recommended rules
 */
function generateDeploymentGuide(rules: GuardrailRule[]): string {
  if (rules.length === 0) {
    return "No guardrail rules needed — all tests passed. Continue monitoring for new attack vectors.";
  }

  const sections: string[] = [];
  sections.push("# AI Guardrail Deployment Guide\n");
  sections.push(`Generated: ${new Date().toISOString()}\n`);
  sections.push(`Total rules to deploy: ${rules.length}\n`);

  // Priority order
  sections.push("\n## Deployment Priority\n");
  const critical = rules.filter(r => r.severity === "critical");
  const high = rules.filter(r => r.severity === "high");
  const medium = rules.filter(r => r.severity === "medium");

  if (critical.length > 0) {
    sections.push(`### CRITICAL (Deploy Immediately)\n`);
    for (const r of critical) {
      sections.push(`- **${r.name}** (${r.type}) — ${r.description}`);
    }
  }
  if (high.length > 0) {
    sections.push(`\n### HIGH (Deploy Within 24 Hours)\n`);
    for (const r of high) {
      sections.push(`- **${r.name}** (${r.type}) — ${r.description}`);
    }
  }
  if (medium.length > 0) {
    sections.push(`\n### MEDIUM (Deploy Within 1 Week)\n`);
    for (const r of medium) {
      sections.push(`- **${r.name}** (${r.type}) — ${r.description}`);
    }
  }

  // Architecture recommendation
  sections.push("\n## Recommended Architecture\n");
  sections.push("1. **Input Pipeline**: Input filters → Homoglyph normalizer → Jailbreak shield → Rate limiter");
  sections.push("2. **Processing**: Semantic classifier → LLM inference");
  sections.push("3. **Output Pipeline**: Output leakage detector → Confidence redactor → Response delivery");
  sections.push("4. **Background**: Dependency auditor (daily) → Model provenance verifier (on deploy) → RAG validator (on ingest)");

  return sections.join("\n");
}

/**
 * Get guardrail rules for a specific category
 */
export function getGuardrailTemplatesForCategory(category: TestCategory): RuleTemplate[] {
  return RULE_TEMPLATES.filter(t => t.category === category);
}

/**
 * Get all available guardrail types
 */
export function getGuardrailTypes(): GuardrailType[] {
  return [...new Set(RULE_TEMPLATES.map(t => t.type))];
}

/**
 * Export guardrail rules as a deployable configuration
 */
export function exportGuardrailConfig(recommendation: GuardrailRecommendation, language: GuardrailLanguage): string {
  const rules = recommendation.rules;

  if (language === "regex") {
    return rules
      .map(r => `# ${r.name} (${r.severity})\n${r.implementation.regex}`)
      .join("\n\n");
  }

  if (language === "python") {
    const imports = `# Auto-generated AI Guardrail Configuration\n# Scan: ${recommendation.scanId}\n# Generated: ${new Date(recommendation.generatedAt).toISOString()}\n\n`;
    return imports + rules.map(r => `# --- ${r.name} (${r.severity}) ---\n${r.implementation.python}`).join("\n\n");
  }

  // TypeScript
  const header = `// Auto-generated AI Guardrail Configuration\n// Scan: ${recommendation.scanId}\n// Generated: ${new Date(recommendation.generatedAt).toISOString()}\n\n`;
  return header + rules.map(r => `// --- ${r.name} (${r.severity}) ---\n${r.implementation.typescript}`).join("\n\n");
}
