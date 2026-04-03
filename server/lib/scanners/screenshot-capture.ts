/**
 * Screenshot Capture Module
 * 
 * Captures browser screenshots of web vulnerabilities as evidence.
 * Uses Puppeteer/Chromium on the scan server to render pages and capture
 * visual proof of exploitation.
 * 
 * Evidence types captured:
 * - Reflected XSS: Screenshot showing injected content rendered
 * - SQL injection: Screenshot showing error messages or data leaks
 * - Authentication bypass: Screenshot showing unauthorized access
 * - Information disclosure: Screenshot showing sensitive data exposed
 * - Default credentials: Screenshot showing authenticated dashboard
 */

import { executeRawCommand } from "../scan-server-executor";

export interface ScreenshotRequest {
  url: string;
  engagementId: number;
  findingId?: string;
  findingTitle: string;
  severity: string;
  /** Optional: inject payload into URL params before capture */
  payload?: string;
  /** Optional: specific element selector to highlight */
  highlightSelector?: string;
  /** Optional: wait for specific content before capture */
  waitForText?: string;
  /** Optional: HTTP headers to include */
  headers?: Record<string, string>;
  /** Optional: cookies to set before navigation */
  cookies?: Array<{ name: string; value: string; domain: string }>;
  /** Timeout in ms for page load (default: 15000) */
  timeout?: number;
}

export interface ScreenshotResult {
  success: boolean;
  screenshotPath?: string;
  screenshotBase64?: string;
  pageTitle?: string;
  finalUrl?: string;
  httpStatus?: number;
  consoleErrors?: string[];
  networkRequests?: number;
  error?: string;
  capturedAt: number;
}

/**
 * Generate a Puppeteer script that captures a screenshot with evidence metadata.
 * The script runs on the scan server where Chromium is installed.
 */
function buildScreenshotScript(req: ScreenshotRequest): string {
  const timeout = req.timeout || 15000;
  const outputPath = `/tmp/evidence-screenshot-${req.engagementId}-${Date.now()}.png`;
  const metadataPath = outputPath.replace('.png', '.json');

  // Build cookie injection code
  const cookieCode = req.cookies && req.cookies.length > 0
    ? `
    // Set cookies before navigation
    await page.setCookie(${JSON.stringify(req.cookies.map(c => ({
      name: c.name,
      value: c.value,
      domain: c.domain,
      path: '/',
    })))});`
    : '';

  // Build header injection code
  const headerCode = req.headers
    ? `await page.setExtraHTTPHeaders(${JSON.stringify(req.headers)});`
    : '';

  // Build highlight code
  const highlightCode = req.highlightSelector
    ? `
    // Highlight the vulnerable element
    try {
      await page.evaluate((sel) => {
        const el = document.querySelector(sel);
        if (el) {
          el.style.border = '3px solid red';
          el.style.boxShadow = '0 0 10px rgba(255,0,0,0.5)';
          el.style.backgroundColor = 'rgba(255,0,0,0.1)';
        }
      }, ${JSON.stringify(req.highlightSelector)});
    } catch (e) { /* element not found */ }`
    : '';

  // Build wait-for-text code
  const waitCode = req.waitForText
    ? `
    // Wait for specific text to appear (evidence of vuln)
    try {
      await page.waitForFunction(
        (text) => document.body.innerText.includes(text),
        { timeout: 5000 },
        ${JSON.stringify(req.waitForText)}
      );
    } catch (e) { /* text not found within timeout */ }`
    : '';

  return `
const puppeteer = require('puppeteer');
const fs = require('fs');

(async () => {
  const metadata = {
    success: false,
    screenshotPath: '${outputPath}',
    pageTitle: '',
    finalUrl: '',
    httpStatus: 0,
    consoleErrors: [],
    networkRequests: 0,
    capturedAt: Date.now(),
  };

  let browser;
  try {
    browser = await puppeteer.launch({
      headless: 'new',
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--window-size=1920,1080',
      ],
      timeout: ${timeout},
    });

    const page = await browser.newPage();
    await page.setViewport({ width: 1920, height: 1080 });
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

    // Track console errors
    page.on('console', msg => {
      if (msg.type() === 'error') {
        metadata.consoleErrors.push(msg.text().slice(0, 200));
      }
    });

    // Track network requests
    let reqCount = 0;
    page.on('request', () => { reqCount++; });

    ${cookieCode}
    ${headerCode}

    // Navigate to the target URL
    const targetUrl = ${JSON.stringify(req.url)};
    const response = await page.goto(targetUrl, {
      waitUntil: 'networkidle2',
      timeout: ${timeout},
    });

    metadata.httpStatus = response ? response.status() : 0;
    metadata.finalUrl = page.url();
    metadata.pageTitle = await page.title();
    metadata.networkRequests = reqCount;

    ${waitCode}
    ${highlightCode}

    // Add evidence watermark overlay
    await page.evaluate((info) => {
      const watermark = document.createElement('div');
      watermark.style.cssText = 'position:fixed;bottom:0;left:0;right:0;background:rgba(0,0,0,0.85);color:#fff;padding:8px 16px;font-family:monospace;font-size:12px;z-index:999999;display:flex;justify-content:space-between;';
      watermark.innerHTML = \`
        <span>AC3 Evidence Capture | \${info.title}</span>
        <span>\${info.severity.toUpperCase()} | \${new Date().toISOString()} | \${info.url}</span>
      \`;
      document.body.appendChild(watermark);
    }, {
      title: ${JSON.stringify(req.findingTitle)},
      severity: ${JSON.stringify(req.severity)},
      url: targetUrl,
    });

    // Wait a moment for watermark to render
    await new Promise(r => setTimeout(r, 500));

    // Take the screenshot
    await page.screenshot({
      path: '${outputPath}',
      fullPage: false,
      type: 'png',
    });

    metadata.success = true;
  } catch (err) {
    metadata.error = err.message;
  } finally {
    if (browser) await browser.close();
  }

  // Write metadata
  fs.writeFileSync('${metadataPath}', JSON.stringify(metadata, null, 2));
  
  // Output metadata to stdout for parsing
  console.log('SCREENSHOT_METADATA_START');
  console.log(JSON.stringify(metadata));
  console.log('SCREENSHOT_METADATA_END');
})();
`;
}

/**
 * Capture a screenshot of a web vulnerability as evidence.
 * Runs Puppeteer on the scan server via SSH.
 */
export async function captureScreenshot(
  req: ScreenshotRequest
): Promise<ScreenshotResult> {
  const script = buildScreenshotScript(req);
  const scriptPath = `/tmp/screenshot-script-${req.engagementId}-${Date.now()}.js`;
  const escapedScript = script.replace(/'/g, "'\\'");

  try {
    // Upload the script to the scan server via executeRawCommand
    const uploadResult = await executeRawCommand(
      `cat > ${scriptPath} << 'SCREENSHOT_SCRIPT_EOF'
${script}
SCREENSHOT_SCRIPT_EOF
chmod +x ${scriptPath}`,
      15
    );

    if (uploadResult.exitCode !== 0) {
      return {
        success: false,
        error: `Failed to upload screenshot script: ${uploadResult.stderr}`,
        capturedAt: Date.now(),
      };
    }

    // Execute the screenshot script
    const timeoutSec = Math.ceil(((req.timeout || 15000) + 10000) / 1000);
    const execResult = await executeRawCommand(
      `cd /tmp && node ${scriptPath} 2>&1`,
      timeoutSec
    );

    // Parse metadata from stdout
    const metadataMatch = execResult.stdout?.match(
      /SCREENSHOT_METADATA_START\n([\s\S]*?)\nSCREENSHOT_METADATA_END/
    );

    if (metadataMatch) {
      try {
        const metadata = JSON.parse(metadataMatch[1]);
        return {
          ...metadata,
          capturedAt: metadata.capturedAt || Date.now(),
        };
      } catch {
        // Fallback
      }
    }

    // If we can't parse metadata, check if screenshot file exists
    const checkResult = await executeRawCommand(
      `ls -la /tmp/evidence-screenshot-${req.engagementId}-*.png 2>/dev/null | tail -1`,
      5
    );

    if (checkResult.stdout?.includes('.png')) {
      return {
        success: true,
        screenshotPath: checkResult.stdout.trim().split(/\s+/).pop(),
        capturedAt: Date.now(),
      };
    }

    return {
      success: false,
      error: `Screenshot capture failed: ${execResult.stderr || 'Unknown error'}`,
      capturedAt: Date.now(),
    };
  } catch (err: any) {
    return {
      success: false,
      error: `Screenshot capture error: ${err.message}`,
      capturedAt: Date.now(),
    };
  } finally {
    // Cleanup script file
    try {
      await executeRawCommand(`rm -f ${scriptPath}`, 5);
    } catch { /* best effort cleanup */ }
  }
}

/**
 * Capture screenshots for multiple findings in batch.
 * Limits concurrency to avoid overwhelming the scan server.
 */
export async function captureScreenshotBatch(
  requests: ScreenshotRequest[],
  options?: { maxConcurrency?: number; onProgress?: (completed: number, total: number) => void }
): Promise<Map<string, ScreenshotResult>> {
  const maxConcurrency = options?.maxConcurrency || 3;
  const results = new Map<string, ScreenshotResult>();
  let completed = 0;

  // Process in batches
  for (let i = 0; i < requests.length; i += maxConcurrency) {
    const batch = requests.slice(i, i + maxConcurrency);
    const batchResults = await Promise.allSettled(
      batch.map(req => captureScreenshot(req))
    );

    for (let j = 0; j < batch.length; j++) {
      const key = batch[j].findingId || batch[j].findingTitle;
      const batchResult = batchResults[j];
      if (batchResult.status === 'fulfilled') {
        results.set(key, batchResult.value);
      } else {
        results.set(key, {
          success: false,
          error: batchResult.reason?.message || 'Unknown error',
          capturedAt: Date.now(),
        });
      }
      completed++;
      options?.onProgress?.(completed, requests.length);
    }
  }

  return results;
}

/**
 * Determine which findings should have screenshots captured.
 * Prioritizes high/critical web vulns with exploitable URLs.
 */
export function selectFindingsForScreenshot(
  vulns: Array<{
    id?: string;
    title: string;
    severity: string;
    endpoint?: string;
    url?: string;
    source?: string;
    corroborationTier?: string;
  }>,
  maxScreenshots: number = 20
): Array<{ findingTitle: string; findingId?: string; url: string; severity: string }> {
  // Filter to web-accessible findings with URLs
  const webFindings = vulns
    .filter(v => {
      const url = v.endpoint || v.url;
      if (!url || !url.startsWith('http')) return false;
      // Prioritize confirmed/verified findings
      if (v.corroborationTier === 'false_positive') return false;
      return true;
    })
    .map(v => ({
      findingTitle: v.title,
      findingId: v.id,
      url: v.endpoint || v.url || '',
      severity: v.severity,
      corroborationTier: v.corroborationTier,
    }));

  // Sort by severity (critical > high > medium > low)
  const severityOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  webFindings.sort((a, b) => {
    const aSev = severityOrder[a.severity?.toLowerCase()] || 0;
    const bSev = severityOrder[b.severity?.toLowerCase()] || 0;
    if (aSev !== bSev) return bSev - aSev;
    // Prefer confirmed findings
    if (a.corroborationTier === 'confirmed' && b.corroborationTier !== 'confirmed') return -1;
    if (b.corroborationTier === 'confirmed' && a.corroborationTier !== 'confirmed') return 1;
    return 0;
  });

  return webFindings.slice(0, maxScreenshots);
}
