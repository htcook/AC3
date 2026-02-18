import fs from 'fs';
import path from 'path';

const pages = [
  { file: 'CampaignArchetypes.tsx', returnLine: 83 },
  { file: 'CampaignExecution.tsx', returnLine: 145 },
  { file: 'DomainIntel.tsx', returnLine: 442 },
  { file: 'DomainIntelResults.tsx', returnLine: 252 },
  { file: 'KevDashboard.tsx', returnLine: 120 },
  { file: 'PhishingOperations.tsx', returnLine: 1520 },
  { file: 'RuleValidator.tsx', returnLine: 271 },
  { file: 'ScanComparison.tsx', returnLine: 67 },
  { file: 'TemplateGenerator.tsx', returnLine: 153 },
  { file: 'TtpKnowledge.tsx', returnLine: 103 },
];

const pagesDir = '/home/ubuntu/caldera-dashboard/client/src/pages';

for (const page of pages) {
  const filePath = path.join(pagesDir, page.file);
  let content = fs.readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');
  
  // Check if already has AppShell
  if (content.includes('AppShell')) {
    console.log(`${page.file}: Already has AppShell, skipping`);
    continue;
  }
  
  // Add import at top (after first import line)
  const importLine = 'import AppShell from "@/components/AppShell";';
  lines.splice(0, 0, importLine);
  
  // Adjust returnLine for the inserted import
  const adjustedReturnLine = page.returnLine; // 0-indexed after splice = page.returnLine
  
  // Find the return ( line and the next <div line
  // The return line is at adjustedReturnLine (1-indexed in original, now shifted by 1)
  const returnIdx = adjustedReturnLine; // lines[adjustedReturnLine] should be "  return ("
  
  // Verify
  const returnContent = lines[returnIdx].trim();
  if (!returnContent.startsWith('return (')) {
    console.log(`${page.file}: Expected 'return (' at line ${returnIdx}, got '${returnContent}'. Searching...`);
    // Search nearby
    let found = false;
    for (let i = returnIdx - 2; i <= returnIdx + 2; i++) {
      if (lines[i] && lines[i].trim().startsWith('return (')) {
        console.log(`  Found at line ${i}: '${lines[i].trim()}'`);
        // Replace the div after this return
        const divIdx = i + 1;
        if (lines[divIdx].includes('<div')) {
          lines[divIdx] = lines[divIdx].replace('<div', '<AppShell>\n    <div');
        }
        // Find the matching closing at end of function
        found = true;
        break;
      }
    }
    if (!found) {
      console.log(`  Could not find return statement, skipping`);
      continue;
    }
  } else {
    // Replace the div after return (
    const divIdx = returnIdx + 1;
    if (lines[divIdx].includes('<div')) {
      lines[divIdx] = lines[divIdx].replace('<div', '<AppShell>\n    <div');
    }
  }
  
  // Now find the closing </div> and ); that ends the main return
  // We need to find the last ); before the closing } of the export default function
  // Strategy: find the last occurrence of "  );" before the end of the function
  
  // Find the end of the file or the next function definition
  let closingIdx = -1;
  let braceDepth = 0;
  let inReturn = false;
  
  for (let i = returnIdx; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim() === 'return (') {
      inReturn = true;
      braceDepth = 0;
      continue;
    }
    if (inReturn) {
      // Count parens
      for (const ch of line) {
        if (ch === '(') braceDepth++;
        if (ch === ')') braceDepth--;
      }
      if (braceDepth < 0) {
        // This line has the closing );
        closingIdx = i;
        break;
      }
    }
  }
  
  if (closingIdx === -1) {
    console.log(`${page.file}: Could not find closing of return statement`);
    continue;
  }
  
  // Insert </AppShell> before the closing );
  // The line at closingIdx should be "  );" — we need to add </AppShell> before the closing </div>
  // Actually, we need to close the div first, then close AppShell
  // The structure is: return ( <AppShell> <div>...</div> </AppShell> );
  // So we insert </AppShell> just before );
  
  // Find the </div> on the line before );
  const prevLine = lines[closingIdx - 1];
  if (prevLine.trim() === '</div>') {
    // Add </AppShell> after the closing </div>
    lines.splice(closingIdx, 0, '    </AppShell>');
  } else {
    // The ); might be on same line as </div>
    lines[closingIdx] = lines[closingIdx].replace(');', '</AppShell>\n  );');
  }
  
  fs.writeFileSync(filePath, lines.join('\n'));
  console.log(`${page.file}: AppShell added successfully`);
}
