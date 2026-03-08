/**
 * Shiki Subset Module
 *
 * This module replaces the full `shiki` package entry point.
 * The original shiki/dist/index.mjs re-exports from:
 *   - ./bundle-full.mjs (createHighlighter using ALL bundledLanguages)
 *   - ./langs.mjs (327 language grammars from @shikijs/langs = 8.4MB)
 *   - ./themes.mjs (theme definitions)
 *   - @shikijs/core (core types and utilities)
 *   - @shikijs/engine-javascript
 *   - @shikijs/engine-oniguruma
 *
 * We replace ./langs.mjs with our own subset of ~29 languages,
 * and rebuild createHighlighter to use only those languages.
 *
 * All imports use shiki's own sub-path exports (shiki/core, shiki/themes, etc.)
 * which resolve correctly through pnpm's node_modules structure.
 */

// Re-export core types and utilities
export * from "shiki/core";

// Re-export engines
export { createJavaScriptRegexEngine, defaultJavaScriptRegexConstructor } from "shiki/engine/javascript";
export { createOnigurumaEngine, loadWasm } from "shiki/engine/oniguruma";

// Re-export themes (lazy-loaded, so keeping all is fine)
export { bundledThemes, bundledThemesInfo } from "shiki/themes";

// Import what we need to build createHighlighter
import { createdBundledHighlighter, createSingletonShorthands, guessEmbeddedLanguages } from "shiki/core";
import { bundledThemes } from "shiki/themes";

// ─── Language Subset (29 languages instead of 327) ──────────────────────────
// Each import resolves to shiki/dist/langs/<name>.mjs → @shikijs/langs/<name>
// Using the shiki ./* wildcard export: "./dist/*"

const bundledLanguagesInfo = [
  { id: "javascript", name: "JavaScript", import: () => import("shiki/dist/langs/javascript.mjs"), aliases: ["js"] },
  { id: "typescript", name: "TypeScript", import: () => import("shiki/dist/langs/typescript.mjs"), aliases: ["ts"] },
  { id: "tsx", name: "TSX", import: () => import("shiki/dist/langs/tsx.mjs") },
  { id: "jsx", name: "JSX", import: () => import("shiki/dist/langs/jsx.mjs") },
  { id: "json", name: "JSON", import: () => import("shiki/dist/langs/json.mjs") },
  { id: "yaml", name: "YAML", import: () => import("shiki/dist/langs/yaml.mjs"), aliases: ["yml"] },
  { id: "bash", name: "Bash", import: () => import("shiki/dist/langs/bash.mjs"), aliases: ["sh", "shell", "zsh"] },
  { id: "python", name: "Python", import: () => import("shiki/dist/langs/python.mjs"), aliases: ["py"] },
  { id: "html", name: "HTML", import: () => import("shiki/dist/langs/html.mjs") },
  { id: "css", name: "CSS", import: () => import("shiki/dist/langs/css.mjs") },
  { id: "xml", name: "XML", import: () => import("shiki/dist/langs/xml.mjs") },
  { id: "sql", name: "SQL", import: () => import("shiki/dist/langs/sql.mjs") },
  { id: "powershell", name: "PowerShell", import: () => import("shiki/dist/langs/powershell.mjs"), aliases: ["ps", "ps1"] },
  { id: "markdown", name: "Markdown", import: () => import("shiki/dist/langs/markdown.mjs"), aliases: ["md"] },
  { id: "diff", name: "Diff", import: () => import("shiki/dist/langs/diff.mjs") },
  { id: "ini", name: "INI", import: () => import("shiki/dist/langs/ini.mjs"), aliases: ["properties"] },
  { id: "toml", name: "TOML", import: () => import("shiki/dist/langs/toml.mjs") },
  { id: "ruby", name: "Ruby", import: () => import("shiki/dist/langs/ruby.mjs"), aliases: ["rb"] },
  { id: "go", name: "Go", import: () => import("shiki/dist/langs/go.mjs") },
  { id: "rust", name: "Rust", import: () => import("shiki/dist/langs/rust.mjs"), aliases: ["rs"] },
  { id: "java", name: "Java", import: () => import("shiki/dist/langs/java.mjs") },
  { id: "c", name: "C", import: () => import("shiki/dist/langs/c.mjs") },
  { id: "cpp", name: "C++", import: () => import("shiki/dist/langs/cpp.mjs"), aliases: ["c++"] },
  { id: "csharp", name: "C#", import: () => import("shiki/dist/langs/csharp.mjs"), aliases: ["cs", "c#"] },
  { id: "php", name: "PHP", import: () => import("shiki/dist/langs/php.mjs") },
  { id: "lua", name: "Lua", import: () => import("shiki/dist/langs/lua.mjs") },
  { id: "docker", name: "Docker", import: () => import("shiki/dist/langs/docker.mjs"), aliases: ["dockerfile"] },
  { id: "nginx", name: "Nginx", import: () => import("shiki/dist/langs/nginx.mjs") },
  { id: "http", name: "HTTP", import: () => import("shiki/dist/langs/http.mjs") },
];

const bundledLanguagesBase = Object.fromEntries(
  bundledLanguagesInfo.map((i) => [i.id, i.import])
);

const bundledLanguagesAlias = Object.fromEntries(
  bundledLanguagesInfo.flatMap((i) =>
    (i.aliases || []).map((a) => [a, i.import])
  )
);

const bundledLanguages = {
  ...bundledLanguagesBase,
  ...bundledLanguagesAlias,
};

export { bundledLanguages, bundledLanguagesAlias, bundledLanguagesBase, bundledLanguagesInfo };

// ─── Rebuild createHighlighter with our language subset ─────────────────────

const createHighlighter = /* @__PURE__ */ createdBundledHighlighter({
  langs: bundledLanguages,
  themes: bundledThemes,
  engine: () => import("shiki/wasm").then(m => m.default),
});

const {
  codeToHtml,
  codeToHast,
  codeToTokens,
  codeToTokensBase,
  codeToTokensWithThemes,
  getSingletonHighlighter,
  getLastGrammarState,
} = /* @__PURE__ */ createSingletonShorthands(createHighlighter, {
  guessEmbeddedLanguages,
});

export {
  createHighlighter,
  codeToHtml,
  codeToHast,
  codeToTokens,
  codeToTokensBase,
  codeToTokensWithThemes,
  getSingletonHighlighter,
  getLastGrammarState,
};
