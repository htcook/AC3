/**
 * Evidence Archive Generator
 * 
 * Bundles all raw scan outputs, tool results, and exploitation evidence
 * into a ZIP archive for client/auditor download. Includes a manifest.json
 * with SHA-256 checksums for chain of custody verification.
 */
import archiver from 'archiver';
import { createHash } from 'crypto';
import { doStoragePut } from '../s3-storage';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ArchiveAssetInput {
  hostname: string;
  toolResults?: Array<{
    tool: string;
    phase?: string;
    command?: string;
    rawOutput?: string;
    exitCode?: number | null;
    durationMs?: number | null;
    executedAt?: number | null;
    findingCount?: number;
    findings?: any[];
  }>;
  exploitAttempts?: Array<{
    module: string;
    success: boolean;
    output?: string;
    cve?: string;
    timestamp?: number;
  }>;
}

export interface NoExploitEvidenceInput {
  timestamp: string;
  scanCoverage: {
    assetsScanned: number;
    totalVulns: number;
    totalPendingVulns?: number;
  };
  reasons: string[];
  rawEvidenceItems?: Array<{
    source?: string;
    asset?: string;
    command?: string;
    output?: string;
    analysis?: string;
  }>;
  llmDecision?: {
    reasoning?: string;
  };
  perAssetEvidence?: Array<{
    hostname: string;
    vulnCount: number;
    highestSeverity: string;
    reason: string;
  }>;
}

export interface ArchiveInput {
  engagementId: string;
  engagementName: string;
  customerName: string;
  engagementType: string;
  reportId?: string;
  assets: ArchiveAssetInput[];
  noExploitEvidence?: NoExploitEvidenceInput;
  partialExploitNonTargetedEvidence?: Array<{
    hostname: string;
    reason: string;
    vulnDetails: Array<{ title: string; severity: string; cvss?: number }>;
    rawEvidence?: string;
  }>;
  generatedAt: string;
}

export interface ArchiveOutput {
  url: string;
  key: string;
  sizeBytes: number;
  fileCount: number;
  manifestChecksum: string;
}

interface ManifestEntry {
  path: string;
  sha256: string;
  sizeBytes: number;
  tool?: string;
  hostname?: string;
  phase?: string;
  executedAt?: string;
  evidenceId: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function sha256(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

function sanitizeFilename(name: string): string {
  return name.replace(/[^a-zA-Z0-9._-]/g, '_').substring(0, 100);
}

function generateEvidenceId(prefix: string, index: number): string {
  return `${prefix}-${String(index).padStart(4, '0')}`;
}

// ─── Main Generator ───────────────────────────────────────────────────────────

export async function generateEvidenceArchive(input: ArchiveInput): Promise<ArchiveOutput> {
  const manifest: ManifestEntry[] = [];
  let fileCount = 0;

  // Create archive in memory
  const archive = archiver('zip', { zlib: { level: 9 } });
  const chunks: Buffer[] = [];

  archive.on('data', (chunk: Buffer) => chunks.push(chunk));

  // ─── README.md ──────────────────────────────────────────────────────────
  const readme = `# Evidence Archive
## ${input.engagementName}

**Client:** ${input.customerName}
**Engagement Type:** ${input.engagementType}
**Generated:** ${input.generatedAt}
**Report ID:** ${input.reportId || 'N/A'}

---

## Contents

This archive contains the complete raw output from all security scanning tools
executed during this engagement. Each file is organized by tool type and target
hostname for easy navigation.

## Directory Structure

\`\`\`
evidence-archive/
├── README.md                    # This file
├── manifest.json                # SHA-256 checksums for all files (chain of custody)
├── scan-outputs/                # Raw tool output organized by tool
│   ├── nuclei/                  # Vulnerability scanner output
│   ├── httpx/                   # HTTP probing results
│   ├── naabu/                   # Port scan results
│   ├── zap/                     # DAST results
│   └── ...                      # Other tools
├── exploit-evidence/            # Exploitation attempt logs
├── no-exploit-evidence/         # Evidence for no-exploit determination (if applicable)
└── non-targeted-evidence/       # Per-asset non-exploitable evidence (if applicable)
\`\`\`

## Verification

To verify file integrity, compare SHA-256 checksums in manifest.json:

\`\`\`bash
# Linux/macOS
sha256sum -c <(jq -r '.entries[] | "\\(.sha256)  \\(.path)"' manifest.json)
\`\`\`

## Legal Notice

This archive contains confidential penetration testing evidence. Unauthorized
distribution is prohibited. All data was collected under authorized engagement
scope and rules of engagement.
`;
  archive.append(readme, { name: 'evidence-archive/README.md' });
  const readmeHash = sha256(readme);
  manifest.push({
    path: 'evidence-archive/README.md',
    sha256: readmeHash,
    sizeBytes: Buffer.byteLength(readme),
    evidenceId: 'META-0001',
  });
  fileCount++;

  // ─── Scan Outputs ───────────────────────────────────────────────────────
  let scanIndex = 0;
  for (const asset of input.assets) {
    for (const tr of asset.toolResults || []) {
      if (!tr.rawOutput || tr.rawOutput.length <= 10) continue;

      scanIndex++;
      const tool = sanitizeFilename(tr.tool || 'unknown');
      const hostname = sanitizeFilename(asset.hostname);
      const phase = tr.phase || 'unknown';
      const filename = `${hostname}_${phase}_${Date.now().toString(36)}_${scanIndex}.txt`;
      const filePath = `evidence-archive/scan-outputs/${tool}/${filename}`;

      // Build file content with metadata header
      const header = [
        `# Evidence ID: ${generateEvidenceId('SCAN', scanIndex)}`,
        `# Tool: ${tr.tool}`,
        `# Target: ${asset.hostname}`,
        `# Phase: ${phase}`,
        `# Command: ${tr.command || 'N/A'}`,
        `# Exit Code: ${tr.exitCode ?? 'N/A'}`,
        `# Duration: ${tr.durationMs ? `${(tr.durationMs / 1000).toFixed(1)}s` : 'N/A'}`,
        `# Executed At: ${tr.executedAt ? new Date(tr.executedAt).toISOString() : 'N/A'}`,
        `# Findings Count: ${tr.findingCount || (tr.findings || []).length}`,
        `# SHA-256 of raw output: ${sha256(tr.rawOutput)}`,
        '',
        '# ═══════════════════════════════════════════════════════════════════',
        '# RAW OUTPUT BEGINS BELOW',
        '# ═══════════════════════════════════════════════════════════════════',
        '',
      ].join('\n');

      const content = header + tr.rawOutput;
      archive.append(content, { name: filePath });

      const contentHash = sha256(content);
      manifest.push({
        path: filePath,
        sha256: contentHash,
        sizeBytes: Buffer.byteLength(content),
        tool: tr.tool,
        hostname: asset.hostname,
        phase,
        executedAt: tr.executedAt ? new Date(tr.executedAt).toISOString() : undefined,
        evidenceId: generateEvidenceId('SCAN', scanIndex),
      });
      fileCount++;
    }
  }

  // ─── Exploit Evidence ───────────────────────────────────────────────────
  let exploitIndex = 0;
  for (const asset of input.assets) {
    for (const ea of asset.exploitAttempts || []) {
      exploitIndex++;
      const hostname = sanitizeFilename(asset.hostname);
      const module = sanitizeFilename(ea.module || 'unknown');
      const filename = `${hostname}_${module}_${exploitIndex}.txt`;
      const filePath = `evidence-archive/exploit-evidence/${filename}`;

      const content = [
        `# Evidence ID: ${generateEvidenceId('EXPL', exploitIndex)}`,
        `# Module: ${ea.module}`,
        `# Target: ${asset.hostname}`,
        `# Success: ${ea.success}`,
        `# CVE: ${ea.cve || 'N/A'}`,
        `# Timestamp: ${ea.timestamp ? new Date(ea.timestamp).toISOString() : 'N/A'}`,
        '',
        '# ═══════════════════════════════════════════════════════════════════',
        '# EXPLOIT OUTPUT',
        '# ═══════════════════════════════════════════════════════════════════',
        '',
        ea.output || '(no output captured)',
      ].join('\n');

      archive.append(content, { name: filePath });
      manifest.push({
        path: filePath,
        sha256: sha256(content),
        sizeBytes: Buffer.byteLength(content),
        tool: ea.module,
        hostname: asset.hostname,
        evidenceId: generateEvidenceId('EXPL', exploitIndex),
      });
      fileCount++;
    }
  }

  // ─── No-Exploit Evidence ────────────────────────────────────────────────
  if (input.noExploitEvidence) {
    const ne = input.noExploitEvidence;

    // Summary file
    const summaryContent = [
      `# No Exploitable Vulnerabilities Determination`,
      `# Timestamp: ${ne.timestamp}`,
      `# Assets Scanned: ${ne.scanCoverage.assetsScanned}`,
      `# Total Vulnerabilities Identified: ${ne.scanCoverage.totalVulns}`,
      `# Pending Re-evaluation: ${ne.scanCoverage.totalPendingVulns || 0}`,
      '',
      '## Determination Reasons',
      '',
      ...ne.reasons.map((r, i) => `${i + 1}. ${r}`),
      '',
      '## LLM Decision Reasoning',
      '',
      ne.llmDecision?.reasoning || '(not available)',
      '',
      '## Per-Asset Assessment',
      '',
      ...(ne.perAssetEvidence || []).map(a =>
        `- ${a.hostname}: ${a.vulnCount} vulns (highest: ${a.highestSeverity}) — ${a.reason}`
      ),
    ].join('\n');

    archive.append(summaryContent, { name: 'evidence-archive/no-exploit-evidence/determination-summary.txt' });
    manifest.push({
      path: 'evidence-archive/no-exploit-evidence/determination-summary.txt',
      sha256: sha256(summaryContent),
      sizeBytes: Buffer.byteLength(summaryContent),
      evidenceId: 'NOEXPL-0001',
    });
    fileCount++;

    // Raw evidence items
    let neIndex = 0;
    for (const item of ne.rawEvidenceItems || []) {
      neIndex++;
      const content = [
        `# Evidence ID: ${generateEvidenceId('NOEXPL-RAW', neIndex)}`,
        `# Source: ${item.source || 'Unknown'}`,
        `# Asset: ${item.asset || 'N/A'}`,
        `# Command: ${item.command || 'N/A'}`,
        '',
        '## Analysis',
        '',
        item.analysis || '(none)',
        '',
        '## Raw Output',
        '',
        item.output || '(no output)',
      ].join('\n');

      const filename = `raw_${sanitizeFilename(item.source || 'unknown')}_${neIndex}.txt`;
      archive.append(content, { name: `evidence-archive/no-exploit-evidence/${filename}` });
      manifest.push({
        path: `evidence-archive/no-exploit-evidence/${filename}`,
        sha256: sha256(content),
        sizeBytes: Buffer.byteLength(content),
        evidenceId: generateEvidenceId('NOEXPL-RAW', neIndex),
      });
      fileCount++;
    }
  }

  // ─── Partial Exploit Non-Targeted Evidence ──────────────────────────────
  if (input.partialExploitNonTargetedEvidence && input.partialExploitNonTargetedEvidence.length > 0) {
    let ntIndex = 0;
    for (const asset of input.partialExploitNonTargetedEvidence) {
      ntIndex++;
      const content = [
        `# Evidence ID: ${generateEvidenceId('NONTGT', ntIndex)}`,
        `# Hostname: ${asset.hostname}`,
        `# Reason Not Targeted: ${asset.reason}`,
        '',
        '## Vulnerability Details',
        '',
        ...(asset.vulnDetails || []).map(v =>
          `- ${v.title} (${v.severity}${v.cvss ? `, CVSS ${v.cvss}` : ''})`
        ),
        '',
        '## Raw Evidence',
        '',
        asset.rawEvidence || '(no raw evidence captured)',
      ].join('\n');

      const filename = `${sanitizeFilename(asset.hostname)}_non_targeted_${ntIndex}.txt`;
      archive.append(content, { name: `evidence-archive/non-targeted-evidence/${filename}` });
      manifest.push({
        path: `evidence-archive/non-targeted-evidence/${filename}`,
        sha256: sha256(content),
        sizeBytes: Buffer.byteLength(content),
        hostname: asset.hostname,
        evidenceId: generateEvidenceId('NONTGT', ntIndex),
      });
      fileCount++;
    }
  }

  // ─── Finalize manifest and archive ──────────────────────────────────────
  const manifestJson = JSON.stringify({
    version: '1.0.0',
    generatedAt: input.generatedAt,
    engagementId: input.engagementId,
    engagementName: input.engagementName,
    customerName: input.customerName,
    reportId: input.reportId || null,
    totalFiles: fileCount,
    entries: manifest,
  }, null, 2);

  archive.append(manifestJson, { name: 'evidence-archive/manifest.json' });
  fileCount++;

  const manifestChecksum = sha256(manifestJson);

  // Finalize the archive
  await archive.finalize();

  // Collect all chunks into a single buffer
  const zipBuffer = Buffer.concat(chunks);

  // Upload to S3
  const archiveKey = `evidence-archives/${input.engagementId}/${input.reportId || 'manual'}-evidence-${Date.now()}.zip`;
  const { url, key } = await doStoragePut(archiveKey, zipBuffer, 'application/zip');

  return {
    url,
    key,
    sizeBytes: zipBuffer.length,
    fileCount,
    manifestChecksum,
  };
}
