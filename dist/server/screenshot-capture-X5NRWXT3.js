import {
  executeRawCommand,
  init_scan_server_executor
} from "./chunk-ULFB3FXL.js";
import "./chunk-P5N75WOE.js";
import "./chunk-ENQ6TOJL.js";
import "./chunk-V7U4LYHE.js";
import {
  doStoragePut,
  init_do_storage
} from "./chunk-CTBPXKB3.js";
import "./chunk-SD56WPOS.js";
import "./chunk-NRYVRXXR.js";
import "./chunk-IG2G4XDA.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/scanners/screenshot-capture.ts
function buildScreenshotScript(req) {
  const timeout = req.timeout || 15e3;
  const outputPath = `/tmp/evidence-screenshot-${req.engagementId}-${Date.now()}.png`;
  const metadataPath = outputPath.replace(".png", ".json");
  const cookieCode = req.cookies && req.cookies.length > 0 ? `
    // Set cookies before navigation
    await page.setCookie(${JSON.stringify(req.cookies.map((c) => ({
    name: c.name,
    value: c.value,
    domain: c.domain,
    path: "/"
  })))});` : "";
  const headerCode = req.headers ? `await page.setExtraHTTPHeaders(${JSON.stringify(req.headers)});` : "";
  const highlightCode = req.highlightSelector ? `
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
    } catch (e) { /* element not found */ }` : "";
  const waitCode = req.waitForText ? `
    // Wait for specific text to appear (evidence of vuln)
    try {
      await page.waitForFunction(
        (text) => document.body.innerText.includes(text),
        { timeout: 5000 },
        ${JSON.stringify(req.waitForText)}
      );
    } catch (e) { /* text not found within timeout */ }` : "";
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
async function captureScreenshot(req) {
  const script = buildScreenshotScript(req);
  const scriptPath = `/tmp/screenshot-script-${req.engagementId}-${Date.now()}.js`;
  const escapedScript = script.replace(/'/g, "'\\'");
  try {
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
        capturedAt: Date.now()
      };
    }
    const timeoutSec = Math.ceil(((req.timeout || 15e3) + 1e4) / 1e3);
    const execResult = await executeRawCommand(
      `bash -c 'cd /tmp && NODE_PATH=/usr/lib/node_modules node ${scriptPath} 2>&1'`,
      timeoutSec
    );
    const metadataMatch = execResult.stdout?.match(
      /SCREENSHOT_METADATA_START\n([\s\S]*?)\nSCREENSHOT_METADATA_END/
    );
    if (metadataMatch) {
      try {
        const metadata = JSON.parse(metadataMatch[1]);
        if (metadata.success && metadata.screenshotPath) {
          try {
            const s3Url = await uploadScreenshotToS3(
              metadata.screenshotPath,
              req.engagementId,
              req.findingTitle
            );
            if (s3Url) {
              metadata.screenshotPath = s3Url;
            }
          } catch (uploadErr) {
            console.warn(`[ScreenshotCapture] S3 upload failed for ${req.findingTitle}:`, uploadErr.message);
          }
        }
        return {
          ...metadata,
          capturedAt: metadata.capturedAt || Date.now()
        };
      } catch {
      }
    }
    const checkResult = await executeRawCommand(
      `ls -la /tmp/evidence-screenshot-${req.engagementId}-*.png 2>/dev/null | tail -1`,
      5
    );
    if (checkResult.stdout?.includes(".png")) {
      const localPath = checkResult.stdout.trim().split(/\s+/).pop() || "";
      let finalPath = localPath;
      try {
        const s3Url = await uploadScreenshotToS3(localPath, req.engagementId, req.findingTitle);
        if (s3Url) finalPath = s3Url;
      } catch {
      }
      return {
        success: true,
        screenshotPath: finalPath,
        capturedAt: Date.now()
      };
    }
    return {
      success: false,
      error: `Screenshot capture failed: ${execResult.stderr || execResult.stdout || "Unknown error"}`,
      capturedAt: Date.now()
    };
  } catch (err) {
    return {
      success: false,
      error: `Screenshot capture error: ${err.message}`,
      capturedAt: Date.now()
    };
  } finally {
    try {
      await executeRawCommand(`rm -f ${scriptPath}`, 5);
    } catch {
    }
  }
}
async function captureScreenshotBatch(requests, options) {
  const maxConcurrency = options?.maxConcurrency || 3;
  const results = /* @__PURE__ */ new Map();
  let completed = 0;
  for (let i = 0; i < requests.length; i += maxConcurrency) {
    const batch = requests.slice(i, i + maxConcurrency);
    const batchResults = await Promise.allSettled(
      batch.map((req) => captureScreenshot(req))
    );
    for (let j = 0; j < batch.length; j++) {
      const key = batch[j].findingId || batch[j].findingTitle;
      const batchResult = batchResults[j];
      if (batchResult.status === "fulfilled") {
        results.set(key, batchResult.value);
      } else {
        results.set(key, {
          success: false,
          error: batchResult.reason?.message || "Unknown error",
          capturedAt: Date.now()
        });
      }
      completed++;
      options?.onProgress?.(completed, requests.length);
    }
  }
  return results;
}
function selectFindingsForScreenshot(vulns, maxScreenshots = 20) {
  const webFindings = vulns.filter((v) => {
    const url = v.endpoint || v.url;
    if (!url || !url.startsWith("http")) return false;
    if (v.corroborationTier === "false_positive") return false;
    return true;
  }).map((v) => ({
    findingTitle: v.title,
    findingId: v.id,
    url: v.endpoint || v.url || "",
    severity: v.severity,
    corroborationTier: v.corroborationTier
  }));
  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  webFindings.sort((a, b) => {
    const aSev = severityOrder[a.severity?.toLowerCase()] || 0;
    const bSev = severityOrder[b.severity?.toLowerCase()] || 0;
    if (aSev !== bSev) return bSev - aSev;
    if (a.corroborationTier === "confirmed" && b.corroborationTier !== "confirmed") return -1;
    if (b.corroborationTier === "confirmed" && a.corroborationTier !== "confirmed") return 1;
    return 0;
  });
  return webFindings.slice(0, maxScreenshots);
}
async function uploadScreenshotToS3(remotePath, engagementId, findingTitle) {
  const readResult = await executeRawCommand(
    `bash -c 'base64 -w0 ${remotePath} 2>/dev/null'`,
    10
  );
  if (readResult.exitCode !== 0 || !readResult.stdout?.trim()) {
    console.warn(`[ScreenshotCapture] Failed to read screenshot from scan server: ${readResult.stderr}`);
    return null;
  }
  const base64Data = readResult.stdout.trim();
  const buffer = Buffer.from(base64Data, "base64");
  if (buffer.length < 100) {
    console.warn(`[ScreenshotCapture] Screenshot too small (${buffer.length} bytes), skipping upload`);
    return null;
  }
  const safeTitle = findingTitle.replace(/[^a-zA-Z0-9-_]/g, "-").replace(/-+/g, "-").slice(0, 60);
  const timestamp = Date.now();
  const fileKey = `evidence/engagement-${engagementId}/${safeTitle}-${timestamp}.png`;
  try {
    const { url } = await doStoragePut(fileKey, buffer, "image/png");
    console.log(`[ScreenshotCapture] Uploaded screenshot to S3: ${url} (${buffer.length} bytes)`);
    await executeRawCommand(`rm -f ${remotePath}`, 5).catch(() => {
    });
    return url;
  } catch (err) {
    console.warn(`[ScreenshotCapture] S3 upload failed: ${err.message}`);
    return null;
  }
}
var init_screenshot_capture = __esm({
  "server/lib/scanners/screenshot-capture.ts"() {
    init_scan_server_executor();
    init_do_storage();
  }
});
init_screenshot_capture();
export {
  captureScreenshot,
  captureScreenshotBatch,
  selectFindingsForScreenshot
};
