import fs from 'fs';
import path from 'path';

// Each page: file, the line number of the main return's opening <div (or <>),
// and the line number of the closing } of the export default function
const pages = [
  // file, returnOpenDivLine (1-indexed), closingBraceLine (1-indexed)
  { file: 'CampaignArchetypes.tsx', returnLine: 83, openDiv: 84, closingBrace: 514 },
  { file: 'CampaignExecution.tsx', returnLine: 145, openDiv: 146, closingBrace: 472 },
  { file: 'DomainIntel.tsx', returnLine: 442, openDiv: 443, closingBrace: 1050 },
  { file: 'DomainIntelResults.tsx', returnLine: 253, openDiv: 254, closingBrace: 2295 },
  { file: 'KevDashboard.tsx', returnLine: 120, openDiv: 121, closingBrace: 652 },
  { file: 'PhishingOperations.tsx', returnLine: 1520, openDiv: 1521, closingBrace: 1603 },
  { file: 'RuleValidator.tsx', returnLine: 271, openDiv: 272, closingBrace: 575 },
  { file: 'ScanComparison.tsx', returnLine: 68, openDiv: 69, closingBrace: 563 },
  { file: 'TemplateGenerator.tsx', returnLine: 153, openDiv: 154, closingBrace: 646 },
  { file: 'TtpKnowledge.tsx', returnLine: 103, openDiv: 104, closingBrace: 560 },
];

const pagesDir = '/home/ubuntu/caldera-dashboard/client/src/pages';

for (const page of pages) {
  const filePath = path.join(pagesDir, page.file);
  let content = fs.readFileSync(filePath, 'utf-8');
  
  if (content.includes('AppShell')) {
    console.log(`${page.file}: Already has AppShell, skipping`);
    continue;
  }
  
  const lines = content.split('\n');
  
  // Step 1: Add import at line 0
  lines.splice(0, 0, 'import AppShell from "@/components/AppShell";');
  
  // All line indices shift by +1 now
  const openDivIdx = page.openDiv; // 0-indexed = page.openDiv (since we added 1 line)
  const closingBraceIdx = page.closingBrace; // 0-indexed = page.closingBrace
  
  // Step 2: Wrap the opening div/fragment with <AppShell>
  const openLine = lines[openDivIdx];
  // Insert <AppShell> before the opening element
  lines.splice(openDivIdx, 0, '    <AppShell>');
  
  // closingBraceIdx shifts by +1 (we added another line)
  const adjustedClosingBrace = closingBraceIdx + 1;
  
  // Step 3: Find the ");}" pattern at the end of the main function
  // The closing } is at adjustedClosingBrace. The line before it should be ");".
  // We need to insert </AppShell> before the closing of the return
  // Pattern: ...content... </div> ); }
  // We want: ...content... </div> </AppShell> ); }
  
  // Find the ");" line just before the closing brace
  let insertIdx = adjustedClosingBrace - 1; // line before closing }
  // That line should be "  );" — we insert </AppShell> before it
  
  // Verify
  const closingLine = lines[insertIdx].trim();
  if (closingLine === ');') {
    // Insert </AppShell> before );
    lines.splice(insertIdx, 0, '    </AppShell>');
    console.log(`${page.file}: AppShell added (closing before ); at line ${insertIdx})`);
  } else {
    console.log(`${page.file}: Expected '); at line ${insertIdx}, got '${closingLine}'. Trying nearby...`);
    // Search nearby for );
    let found = false;
    for (let i = insertIdx; i >= insertIdx - 3; i--) {
      if (lines[i] && lines[i].trim() === ');') {
        lines.splice(i, 0, '    </AppShell>');
        console.log(`${page.file}: AppShell added (closing before ); at line ${i})`);
        found = true;
        break;
      }
    }
    if (!found) {
      console.log(`${page.file}: FAILED - could not find closing );`);
      continue;
    }
  }
  
  fs.writeFileSync(filePath, lines.join('\n'));
}
