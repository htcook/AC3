import {
  __esm
} from "./chunk-KFQGP6VL.js";

// shared/llm-json-parser.ts
function sanitizeLLMJson(raw) {
  let s = raw.trim();
  if (s.startsWith("```")) {
    s = s.replace(/^```(?:json|JSON|js|typescript)?\s*\n?/, "").replace(/\n?```\s*$/, "");
  }
  s = s.trim();
  if (!s.startsWith("{") && !s.startsWith("[")) {
    const objIdx = s.indexOf("{");
    const arrIdx = s.indexOf("[");
    if (objIdx >= 0 && (arrIdx < 0 || objIdx < arrIdx)) {
      s = s.substring(objIdx);
    } else if (arrIdx >= 0) {
      s = s.substring(arrIdx);
    }
  }
  const lastBrace = s.lastIndexOf("}");
  const lastBracket = s.lastIndexOf("]");
  const lastClose = Math.max(lastBrace, lastBracket);
  if (lastClose > 0 && lastClose < s.length - 1) {
    s = s.substring(0, lastClose + 1);
  }
  return s;
}
function repairLLMJson(sanitized) {
  let s = sanitized;
  let wasRepaired = false;
  const trailingCommaRegex = /,\s*([}\]])/g;
  if (trailingCommaRegex.test(s)) {
    s = s.replace(trailingCommaRegex, "$1");
    wasRepaired = true;
  }
  if (/'\w+':\s*'/.test(s) && !/"/.test(s)) {
    s = s.replace(/'/g, '"');
    wasRepaired = true;
  }
  const unquotedKeyRegex = /([{,]\s*)([a-zA-Z_$][a-zA-Z0-9_$]*)(\s*:)/g;
  if (unquotedKeyRegex.test(s)) {
    s = s.replace(unquotedKeyRegex, '$1"$2"$3');
    wasRepaired = true;
  }
  if (/\bNaN\b/.test(s)) {
    s = s.replace(/\bNaN\b/g, "null");
    wasRepaired = true;
  }
  if (/\bInfinity\b/.test(s)) {
    s = s.replace(/\bInfinity\b/g, "999999");
    wasRepaired = true;
  }
  if (/\b-Infinity\b/.test(s)) {
    s = s.replace(/\b-Infinity\b/g, "-999999");
    wasRepaired = true;
  }
  if (/\/\/.*$/m.test(s) || /\/\*[\s\S]*?\*\//.test(s)) {
    s = s.replace(/\/\/.*$/gm, "");
    s = s.replace(/\/\*[\s\S]*?\*\//g, "");
    wasRepaired = true;
  }
  return { repaired: s, wasRepaired };
}
function parseLLMJson(content, options = {}) {
  const raw = String(content || "{}");
  const label = options.label || "LLM";
  const sanitized = sanitizeLLMJson(raw);
  try {
    const data = JSON.parse(sanitized);
    return { ok: true, data, repaired: false };
  } catch {
  }
  const { repaired, wasRepaired } = repairLLMJson(sanitized);
  if (wasRepaired) {
    try {
      const data = JSON.parse(repaired);
      return { ok: true, data, repaired: true };
    } catch {
    }
  }
  const rawExcerpt = raw.substring(0, 500);
  const error = `[${label}] JSON parse failed after sanitization and repair`;
  if (!options.silent) {
    console.error(`${error}. Raw excerpt: ${rawExcerpt}`);
  }
  if (options.fallback !== void 0) {
    return { ok: true, data: options.fallback, repaired: false };
  }
  return { ok: false, error, rawExcerpt };
}
function safeParseLLMJson(content, fallback) {
  const result = parseLLMJson(content, { fallback });
  return result.data;
}
var init_llm_json_parser = __esm({
  "shared/llm-json-parser.ts"() {
    "use strict";
  }
});

export {
  parseLLMJson,
  safeParseLLMJson,
  init_llm_json_parser
};
