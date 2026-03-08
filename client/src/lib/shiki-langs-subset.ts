/**
 * Shiki Language Subset
 *
 * This module re-exports only the languages we actually use in the dashboard.
 * The full shiki bundledLanguages includes 327+ language grammars (~8.4MB of @shikijs/langs),
 * but we only need ~15 for our security dashboard use case.
 *
 * This is used by the Vite alias in vite.config.ts to replace the full shiki import
 * with this subset, reducing the production bundle by ~8MB.
 */

// Re-export everything from shiki core
export * from "@shikijs/core";
export { createJavaScriptRegexEngine, defaultJavaScriptRegexConstructor } from "shiki/engine/javascript";

// Import only the language grammars we need
import type { LanguageRegistration } from "@shikijs/core";

type BundledLanguageImport = () => Promise<{ default: LanguageRegistration[] }>;

// Security dashboard languages: code blocks in LLM output, exploit code, configs
const bundledLanguagesInfo = [
  { id: "javascript", name: "JavaScript", import: (() => import("@shikijs/langs/javascript")) as unknown as BundledLanguageImport, aliases: ["js"] },
  { id: "typescript", name: "TypeScript", import: (() => import("@shikijs/langs/typescript")) as unknown as BundledLanguageImport, aliases: ["ts"] },
  { id: "tsx", name: "TSX", import: (() => import("@shikijs/langs/tsx")) as unknown as BundledLanguageImport },
  { id: "jsx", name: "JSX", import: (() => import("@shikijs/langs/jsx")) as unknown as BundledLanguageImport },
  { id: "json", name: "JSON", import: (() => import("@shikijs/langs/json")) as unknown as BundledLanguageImport },
  { id: "yaml", name: "YAML", import: (() => import("@shikijs/langs/yaml")) as unknown as BundledLanguageImport, aliases: ["yml"] },
  { id: "bash", name: "Bash", import: (() => import("@shikijs/langs/bash")) as unknown as BundledLanguageImport, aliases: ["sh", "shell", "zsh"] },
  { id: "python", name: "Python", import: (() => import("@shikijs/langs/python")) as unknown as BundledLanguageImport, aliases: ["py"] },
  { id: "html", name: "HTML", import: (() => import("@shikijs/langs/html")) as unknown as BundledLanguageImport },
  { id: "css", name: "CSS", import: (() => import("@shikijs/langs/css")) as unknown as BundledLanguageImport },
  { id: "xml", name: "XML", import: (() => import("@shikijs/langs/xml")) as unknown as BundledLanguageImport },
  { id: "sql", name: "SQL", import: (() => import("@shikijs/langs/sql")) as unknown as BundledLanguageImport },
  { id: "powershell", name: "PowerShell", import: (() => import("@shikijs/langs/powershell")) as unknown as BundledLanguageImport, aliases: ["ps", "ps1"] },
  { id: "markdown", name: "Markdown", import: (() => import("@shikijs/langs/markdown")) as unknown as BundledLanguageImport, aliases: ["md"] },
  { id: "diff", name: "Diff", import: (() => import("@shikijs/langs/diff")) as unknown as BundledLanguageImport },
  { id: "ini", name: "INI", import: (() => import("@shikijs/langs/ini")) as unknown as BundledLanguageImport, aliases: ["properties"] },
  { id: "toml", name: "TOML", import: (() => import("@shikijs/langs/toml")) as unknown as BundledLanguageImport },
  { id: "ruby", name: "Ruby", import: (() => import("@shikijs/langs/ruby")) as unknown as BundledLanguageImport, aliases: ["rb"] },
  { id: "go", name: "Go", import: (() => import("@shikijs/langs/go")) as unknown as BundledLanguageImport },
  { id: "rust", name: "Rust", import: (() => import("@shikijs/langs/rust")) as unknown as BundledLanguageImport, aliases: ["rs"] },
  { id: "java", name: "Java", import: (() => import("@shikijs/langs/java")) as unknown as BundledLanguageImport },
  { id: "c", name: "C", import: (() => import("@shikijs/langs/c")) as unknown as BundledLanguageImport },
  { id: "cpp", name: "C++", import: (() => import("@shikijs/langs/cpp")) as unknown as BundledLanguageImport, aliases: ["c++"] },
  { id: "csharp", name: "C#", import: (() => import("@shikijs/langs/csharp")) as unknown as BundledLanguageImport, aliases: ["cs", "c#"] },
  { id: "php", name: "PHP", import: (() => import("@shikijs/langs/php")) as unknown as BundledLanguageImport },
  { id: "lua", name: "Lua", import: (() => import("@shikijs/langs/lua")) as unknown as BundledLanguageImport },
  { id: "docker", name: "Docker", import: (() => import("@shikijs/langs/docker")) as unknown as BundledLanguageImport, aliases: ["dockerfile"] },
  { id: "nginx", name: "Nginx", import: (() => import("@shikijs/langs/nginx")) as unknown as BundledLanguageImport },
  { id: "http", name: "HTTP", import: (() => import("@shikijs/langs/http")) as unknown as BundledLanguageImport },
];

const bundledLanguagesBase: Record<string, BundledLanguageImport> = Object.fromEntries(
  bundledLanguagesInfo.map((i) => [i.id, i.import])
);

const bundledLanguagesAlias: Record<string, BundledLanguageImport> = Object.fromEntries(
  bundledLanguagesInfo.flatMap((i) =>
    (i.aliases || []).map((a: string) => [a, i.import])
  )
);

const bundledLanguages: Record<string, BundledLanguageImport> = {
  ...bundledLanguagesBase,
  ...bundledLanguagesAlias,
};

export { bundledLanguages, bundledLanguagesAlias, bundledLanguagesBase, bundledLanguagesInfo };

// Re-export themes (these are small, keep all of them)
export { bundledThemes, bundledThemesInfo } from "shiki/themes";

// Re-export the createHighlighter from shiki's bundle-full which includes the full API
export { createHighlighter, getSingletonHighlighter } from "@shikijs/core";
export { codeToHast, codeToHtml, codeToTokens, codeToTokensBase, codeToTokensWithThemes, getLastGrammarState } from "@shikijs/core";
