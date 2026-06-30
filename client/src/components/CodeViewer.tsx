import { useState, useCallback } from "react";
import { Highlight, themes } from "prism-react-renderer";
import { Button } from "@/components/ui/button";
import { Check, Copy, Download, WrapText } from "lucide-react";

type Language = "python" | "bash" | "javascript" | "typescript" | "json" | "yaml" | "powershell" | "ruby" | "go" | "c" | "cpp" | "java" | "php" | "sql" | "html" | "css" | "markdown" | "text";

interface CodeViewerProps {
  code: string;
  language?: Language;
  title?: string;
  filename?: string;
  showLineNumbers?: boolean;
  maxHeight?: string;
  className?: string;
}

function detectLanguage(code: string, filename?: string): Language {
  if (filename) {
    const ext = filename.split(".").pop()?.toLowerCase();
    const extMap: Record<string, Language> = {
      py: "python",
      sh: "bash",
      bash: "bash",
      js: "javascript",
      ts: "typescript",
      json: "json",
      yml: "yaml",
      yaml: "yaml",
      ps1: "powershell",
      rb: "ruby",
      go: "go",
      c: "c",
      cpp: "cpp",
      h: "c",
      java: "java",
      php: "php",
      sql: "sql",
      html: "html",
      css: "css",
      md: "markdown",
    };
    if (ext && extMap[ext]) return extMap[ext];
  }

  // Auto-detect from content
  if (code.includes("#!/usr/bin/env python") || code.includes("import ") && code.includes("def ")) return "python";
  if (code.includes("#!/bin/bash") || code.includes("#!/bin/sh")) return "bash";
  if (code.includes("function ") && (code.includes("const ") || code.includes("let "))) return "javascript";
  if (code.includes("import {") && code.includes("from ")) return "typescript";
  if (code.startsWith("{") || code.startsWith("[")) return "json";
  if (code.includes("---\n") && code.includes(":")) return "yaml";
  if (code.includes("$PSVersionTable") || code.includes("Invoke-")) return "powershell";
  if (code.includes("require '") || code.includes("def ") && code.includes("end")) return "ruby";
  if (code.includes("package main") || code.includes("func main")) return "go";
  if (code.includes("SELECT ") || code.includes("INSERT INTO")) return "sql";

  return "python"; // Default for exploit scripts
}

export function CodeViewer({
  code,
  language,
  title,
  filename,
  showLineNumbers = true,
  maxHeight = "500px",
  className = "",
}: CodeViewerProps) {
  const [copied, setCopied] = useState(false);
  const [wordWrap, setWordWrap] = useState(false);
  const detectedLang = language || detectLanguage(code, filename);

  const handleCopy = useCallback(async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [code]);

  const handleDownload = useCallback(() => {
    const ext = detectedLang === "python" ? "py" : detectedLang === "bash" ? "sh" : detectedLang === "javascript" ? "js" : detectedLang;
    const name = filename || `exploit.${ext}`;
    const blob = new Blob([code], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  }, [code, filename, detectedLang]);

  return (
    <div className={`rounded-lg border border-border overflow-hidden bg-[#1e1e2e] ${className}`}>
      {/* Header bar */}
      <div className="flex items-center justify-between px-4 py-2 bg-[#181825] border-b border-border/50">
        <div className="flex items-center gap-3">
          {/* Traffic light dots */}
          <div className="flex gap-1.5">
            <div className="w-3 h-3 rounded-full bg-red-500/80" />
            <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
            <div className="w-3 h-3 rounded-full bg-green-500/80" />
          </div>
          <span className="text-xs text-muted-foreground font-mono">
            {title || filename || `${detectedLang} exploit`}
          </span>
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-primary/10 text-primary font-mono uppercase">
            {detectedLang}
          </span>
        </div>
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="sm"
            className="h-7 w-7 p-0 text-muted-foreground hover:text-foreground"
            onClick={() => setWordWrap(!wordWrap)}
            title={wordWrap ? "Disable word wrap" : "Enable word wrap"}
          >
            <WrapText className={`h-3.5 w-3.5 ${wordWrap ? "text-primary" : ""}`} />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="h-7 w-7 p-0 text-muted-foreground hover:text-foreground"
            onClick={handleDownload}
            title="Download file"
          >
            <Download className="h-3.5 w-3.5" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="h-7 w-7 p-0 text-muted-foreground hover:text-foreground"
            onClick={handleCopy}
            title="Copy to clipboard"
          >
            {copied ? (
              <Check className="h-3.5 w-3.5 text-green-400" />
            ) : (
              <Copy className="h-3.5 w-3.5" />
            )}
          </Button>
        </div>
      </div>

      {/* Code content */}
      <div
        className="overflow-auto"
        style={{ maxHeight }}
      >
        <Highlight
          theme={themes.vsDark}
          code={code.trimEnd()}
          language={detectedLang as any}
        >
          {({ className: hlClassName, style, tokens, getLineProps, getTokenProps }) => (
            <pre
              className={`${hlClassName} text-sm leading-relaxed p-4 m-0`}
              style={{
                ...style,
                background: "transparent",
                whiteSpace: wordWrap ? "pre-wrap" : "pre",
                wordBreak: wordWrap ? "break-all" : "normal",
              }}
            >
              {tokens.map((line, i) => {
                const lineProps = getLineProps({ line, key: i });
                return (
                  <div
                    key={i}
                    {...lineProps}
                    className={`${lineProps.className || ""} table-row`}
                  >
                    {showLineNumbers && (
                      <span className="table-cell text-right pr-4 select-none text-muted-foreground/40 text-xs w-[3ch]">
                        {i + 1}
                      </span>
                    )}
                    <span className="table-cell">
                      {line.map((token, key) => (
                        <span key={key} {...getTokenProps({ token, key })} />
                      ))}
                    </span>
                  </div>
                );
              })}
            </pre>
          )}
        </Highlight>
      </div>
    </div>
  );
}

export default CodeViewer;
