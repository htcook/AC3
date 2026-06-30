/**
 * Shiki Language & Theme Subset — Minimal Edition
 *
 * This module replaces the bare `import ... from "shiki"` used by streamdown.
 * Uses JavaScript regex engine (no WASM) and only 10 essential languages.
 *
 * The Vite alias in vite.config.ts redirects `"shiki"` → this file.
 * Sub-path imports like `"shiki/engine/javascript"` are NOT affected.
 */

// Re-export everything from shiki/core (createHighlighter, types, etc.)
export * from "shiki/core";

// Import only 10 essential language grammars for security/pentest output
import langBash from "shiki/dist/langs/bash.mjs";
import langCss from "shiki/dist/langs/css.mjs";
import langHtml from "shiki/dist/langs/html.mjs";
import langJavascript from "shiki/dist/langs/javascript.mjs";
import langJson from "shiki/dist/langs/json.mjs";
import langMarkdown from "shiki/dist/langs/markdown.mjs";
import langPython from "shiki/dist/langs/python.mjs";
import langSql from "shiki/dist/langs/sql.mjs";
import langTypescript from "shiki/dist/langs/typescript.mjs";
import langYaml from "shiki/dist/langs/yaml.mjs";

// Import only the 2 themes streamdown uses
import themeGithubDark from "shiki/dist/themes/github-dark.mjs";
import themeGithubLight from "shiki/dist/themes/github-light.mjs";

/**
 * Subset of bundledLanguages — only the languages we actually need.
 * Each value is a dynamic import function matching shiki's expected format.
 */
export const bundledLanguages: Record<string, any> = {
  bash: langBash,
  sh: langBash,
  shell: langBash,
  shellscript: langBash,
  css: langCss,
  html: langHtml,
  javascript: langJavascript,
  js: langJavascript,
  json: langJson,
  markdown: langMarkdown,
  md: langMarkdown,
  python: langPython,
  py: langPython,
  sql: langSql,
  typescript: langTypescript,
  ts: langTypescript,
  yaml: langYaml,
  yml: langYaml,
};

/**
 * Subset of bundledThemes — only github-dark and github-light.
 */
export const bundledThemes: Record<string, any> = {
  "github-dark": themeGithubDark,
  "github-light": themeGithubLight,
};

// Use JavaScript regex engine instead of Oniguruma WASM (saves ~456KB WASM + engine overhead)
import { createdBundledHighlighter, createSingletonShorthands } from "shiki/core";
import { createJavaScriptRegexEngine } from "shiki/engine/javascript";

export const createHighlighter = /* @__PURE__ */ createdBundledHighlighter({
  langs: bundledLanguages,
  themes: bundledThemes,
  engine: () => createJavaScriptRegexEngine(),
});

const {
  codeToHtml,
  codeToHast,
  codeToTokens,
  codeToTokensBase,
  codeToTokensWithThemes,
  getSingletonHighlighter,
  getLastGrammarState,
} = /* @__PURE__ */ createSingletonShorthands(createHighlighter);

export {
  codeToHtml,
  codeToHast,
  codeToTokens,
  codeToTokensBase,
  codeToTokensWithThemes,
  getSingletonHighlighter,
  getLastGrammarState,
};
