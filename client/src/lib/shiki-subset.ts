/**
 * Shiki Language & Theme Subset
 *
 * This module replaces the bare `import ... from "shiki"` used by streamdown.
 * Instead of bundling all 327 languages and 60+ themes, we only include the
 * ~20 languages commonly seen in security/pentest output and 2 themes.
 *
 * The Vite alias in vite.config.ts redirects `"shiki"` → this file.
 * Sub-path imports like `"shiki/engine/javascript"` are NOT affected.
 */

// Re-export everything from shiki/core (createHighlighter, types, etc.)
export * from "shiki/core";

// Import individual language grammars (lazy dynamic imports via shiki's own files)
import langBash from "shiki/dist/langs/bash.mjs";
import langC from "shiki/dist/langs/c.mjs";
import langCpp from "shiki/dist/langs/cpp.mjs";
import langCss from "shiki/dist/langs/css.mjs";
import langDiff from "shiki/dist/langs/diff.mjs";
import langDockerfile from "shiki/dist/langs/dockerfile.mjs";
import langGo from "shiki/dist/langs/go.mjs";
import langHtml from "shiki/dist/langs/html.mjs";
import langIni from "shiki/dist/langs/ini.mjs";
import langJava from "shiki/dist/langs/java.mjs";
import langJavascript from "shiki/dist/langs/javascript.mjs";
import langJson from "shiki/dist/langs/json.mjs";
import langMarkdown from "shiki/dist/langs/markdown.mjs";
import langPhp from "shiki/dist/langs/php.mjs";
import langPowershell from "shiki/dist/langs/powershell.mjs";
import langPython from "shiki/dist/langs/python.mjs";
import langRuby from "shiki/dist/langs/ruby.mjs";
import langRust from "shiki/dist/langs/rust.mjs";
import langShellscript from "shiki/dist/langs/shellscript.mjs";
import langSql from "shiki/dist/langs/sql.mjs";
import langToml from "shiki/dist/langs/toml.mjs";
import langTsx from "shiki/dist/langs/tsx.mjs";
import langTypescript from "shiki/dist/langs/typescript.mjs";
import langXml from "shiki/dist/langs/xml.mjs";
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
  c: langC,
  cpp: langCpp,
  css: langCss,
  diff: langDiff,
  dockerfile: langDockerfile,
  go: langGo,
  html: langHtml,
  ini: langIni,
  java: langJava,
  javascript: langJavascript,
  json: langJson,
  markdown: langMarkdown,
  php: langPhp,
  powershell: langPowershell,
  python: langPython,
  ruby: langRuby,
  rust: langRust,
  sh: langShellscript,
  shell: langShellscript,
  shellscript: langShellscript,
  sql: langSql,
  toml: langToml,
  tsx: langTsx,
  typescript: langTypescript,
  xml: langXml,
  yaml: langYaml,
  yml: langYaml,
  // Aliases
  js: langJavascript,
  ts: langTypescript,
  py: langPython,
  rb: langRuby,
  md: langMarkdown,
};

/**
 * Subset of bundledThemes — only github-dark and github-light.
 */
export const bundledThemes: Record<string, any> = {
  "github-dark": themeGithubDark,
  "github-light": themeGithubLight,
};

// Re-export createHighlighter from shiki/core
import { createdBundledHighlighter, createSingletonShorthands } from "shiki/core";
import { createOnigurumaEngine } from "shiki/engine/oniguruma";

export const createHighlighter = /* @__PURE__ */ createdBundledHighlighter({
  langs: bundledLanguages,
  themes: bundledThemes,
  engine: () => createOnigurumaEngine(import("shiki/wasm")),
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
