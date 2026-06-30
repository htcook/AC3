/**
 * Documentation Version Tracker Router
 *
 * tRPC procedures for:
 * - Taking platform snapshots
 * - Comparing snapshots to detect changes
 * - Generating doc update reports
 * - Listing doc manifest sections
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import * as fs from "fs";
import * as path from "path";
import {
  DOC_MANIFEST,
  buildSnapshotFromFileList,
  diffSnapshots,
  generateDocUpdateReport,
  formatReportAsMarkdown,
  type PlatformSnapshot,
} from "../lib/doc-version-tracker";

const SNAPSHOT_DIR = path.join(process.cwd(), "docs", "snapshots");

function ensureSnapshotDir() {
  if (!fs.existsSync(SNAPSHOT_DIR)) {
    fs.mkdirSync(SNAPSHOT_DIR, { recursive: true });
  }
}

function saveSnapshot(snapshot: PlatformSnapshot) {
  ensureSnapshotDir();
  const filename = `snapshot-${snapshot.version.replace(/[:.]/g, "-")}.json`;
  fs.writeFileSync(path.join(SNAPSHOT_DIR, filename), JSON.stringify(snapshot, null, 2));
  // Also save as "latest"
  fs.writeFileSync(path.join(SNAPSHOT_DIR, "latest.json"), JSON.stringify(snapshot, null, 2));
}

function loadLatestSnapshot(): PlatformSnapshot | null {
  const latestPath = path.join(SNAPSHOT_DIR, "latest.json");
  if (!fs.existsSync(latestPath)) return null;
  return JSON.parse(fs.readFileSync(latestPath, "utf-8"));
}

function listSnapshots(): string[] {
  ensureSnapshotDir();
  return fs
    .readdirSync(SNAPSHOT_DIR)
    .filter(f => f.startsWith("snapshot-") && f.endsWith(".json"))
    .sort()
    .reverse();
}

/**
 * Scans the project filesystem to build a current platform snapshot.
 */
function scanPlatformState(): PlatformSnapshot {
  const projectRoot = process.cwd();

  // 1. Scan routes from App.tsx
  const appTsxPath = path.join(projectRoot, "client", "src", "App.tsx");
  const appTsx = fs.existsSync(appTsxPath) ? fs.readFileSync(appTsxPath, "utf-8") : "";
  const routeRegex = /path=["']([^"']+)["']/g;
  const routes: Array<{ path: string; component: string; protected: boolean }> = [];
  let match;
  while ((match = routeRegex.exec(appTsx)) !== null) {
    routes.push({
      path: match[1],
      component: "", // Would need deeper parsing
      protected: false,
    });
  }

  // 2. Scan router files
  const routerDir = path.join(projectRoot, "server", "routers");
  const routers: Array<{ file: string; lineCount: number; lastModified: number }> = [];
  if (fs.existsSync(routerDir)) {
    for (const file of fs.readdirSync(routerDir).filter(f => f.endsWith(".ts") && !f.endsWith(".test.ts"))) {
      const filePath = path.join(routerDir, file);
      const stat = fs.statSync(filePath);
      const content = fs.readFileSync(filePath, "utf-8");
      routers.push({
        file,
        lineCount: content.split("\n").length,
        lastModified: stat.mtimeMs,
      });
    }
  }

  // 3. Scan schema tables
  const schemaPath = path.join(projectRoot, "drizzle", "schema.ts");
  const schemaTables: Array<{ name: string; columns: string[] }> = [];
  if (fs.existsSync(schemaPath)) {
    const schema = fs.readFileSync(schemaPath, "utf-8");
    const tableRegex = /export\s+const\s+(\w+)\s*=\s*mysqlTable\(/g;
    while ((match = tableRegex.exec(schema)) !== null) {
      schemaTables.push({ name: match[1], columns: [] });
    }
  }

  // 4. Scan server libs
  const libDir = path.join(projectRoot, "server", "lib");
  const serverLibs: Array<{ file: string; lineCount: number; lastModified: number }> = [];
  if (fs.existsSync(libDir)) {
    for (const file of fs.readdirSync(libDir).filter(f => f.endsWith(".ts") && !f.endsWith(".test.ts"))) {
      const filePath = path.join(libDir, file);
      const stat = fs.statSync(filePath);
      const content = fs.readFileSync(filePath, "utf-8");
      serverLibs.push({
        file,
        lineCount: content.split("\n").length,
        lastModified: stat.mtimeMs,
      });
    }
  }

  // 5. Scan page files
  const pagesDir = path.join(projectRoot, "client", "src", "pages");
  const pages: Array<{ file: string; route: string; lineCount: number; lastModified: number }> = [];
  if (fs.existsSync(pagesDir)) {
    for (const file of fs.readdirSync(pagesDir).filter(f => f.endsWith(".tsx"))) {
      const filePath = path.join(pagesDir, file);
      const stat = fs.statSync(filePath);
      const content = fs.readFileSync(filePath, "utf-8");
      pages.push({
        file,
        route: "",
        lineCount: content.split("\n").length,
        lastModified: stat.mtimeMs,
      });
    }
  }

  return buildSnapshotFromFileList({ routes, routers, schemaTables, serverLibs, pages });
}

export const docTrackerRouter = router({
  /**
   * Get the documentation manifest — all tracked doc sections and their coverage
   */
  getManifest: protectedProcedure.query(() => {
    return {
      sections: DOC_MANIFEST,
      totalSections: DOC_MANIFEST.length,
      byGuide: {
        admin: DOC_MANIFEST.filter(s => s.guide === "admin").length,
        user: DOC_MANIFEST.filter(s => s.guide === "user").length,
        "msp-mssp": DOC_MANIFEST.filter(s => s.guide === "msp-mssp").length,
        "ember-design": DOC_MANIFEST.filter(s => s.guide === "ember-design").length,
      },
    };
  }),

  /**
   * Take a new platform snapshot (captures current state of all routes, routers, schema, libs, pages)
   */
  takeSnapshot: protectedProcedure.mutation(() => {
    const snapshot = scanPlatformState();
    saveSnapshot(snapshot);
    return {
      version: snapshot.version,
      stats: {
        routes: snapshot.routes.length,
        routers: snapshot.routers.length,
        schemaTables: snapshot.schemaTables.length,
        serverLibs: snapshot.serverLibs.length,
        pages: snapshot.pages.length,
      },
    };
  }),

  /**
   * Get the latest snapshot
   */
  getLatestSnapshot: protectedProcedure.query(() => {
    const snapshot = loadLatestSnapshot();
    if (!snapshot) return null;
    return {
      version: snapshot.version,
      timestamp: snapshot.timestamp,
      stats: {
        routes: snapshot.routes.length,
        routers: snapshot.routers.length,
        schemaTables: snapshot.schemaTables.length,
        serverLibs: snapshot.serverLibs.length,
        pages: snapshot.pages.length,
      },
    };
  }),

  /**
   * List all saved snapshots
   */
  listSnapshots: protectedProcedure.query(() => {
    return listSnapshots();
  }),

  /**
   * Compare current platform state against the latest snapshot and generate a doc update report
   */
  generateReport: protectedProcedure.mutation(() => {
    const previousSnapshot = loadLatestSnapshot();
    const currentSnapshot = scanPlatformState();

    if (!previousSnapshot) {
      // First snapshot — save it and return "all up to date"
      saveSnapshot(currentSnapshot);
      return {
        report: null,
        markdown: "# Documentation Update Report\n\n**First snapshot taken.** No previous state to compare against. Run again after platform changes to detect doc updates needed.",
        isFirstSnapshot: true,
        currentStats: {
          routes: currentSnapshot.routes.length,
          routers: currentSnapshot.routers.length,
          schemaTables: currentSnapshot.schemaTables.length,
          serverLibs: currentSnapshot.serverLibs.length,
          pages: currentSnapshot.pages.length,
        },
      };
    }

    const report = generateDocUpdateReport(previousSnapshot, currentSnapshot);
    const markdown = formatReportAsMarkdown(report);

    // Save the new snapshot as latest
    saveSnapshot(currentSnapshot);

    return {
      report,
      markdown,
      isFirstSnapshot: false,
      currentStats: {
        routes: currentSnapshot.routes.length,
        routers: currentSnapshot.routers.length,
        schemaTables: currentSnapshot.schemaTables.length,
        serverLibs: currentSnapshot.serverLibs.length,
        pages: currentSnapshot.pages.length,
      },
    };
  }),

  /**
   * Diff two specific snapshots by filename
   */
  diffSnapshots: protectedProcedure
    .input(z.object({ from: z.string(), to: z.string() }))
    .query(({ input }) => {
      const fromPath = path.join(SNAPSHOT_DIR, input.from);
      const toPath = path.join(SNAPSHOT_DIR, input.to);
      if (!fs.existsSync(fromPath) || !fs.existsSync(toPath)) {
        return { error: "Snapshot not found" };
      }
      const fromSnapshot: PlatformSnapshot = JSON.parse(fs.readFileSync(fromPath, "utf-8"));
      const toSnapshot: PlatformSnapshot = JSON.parse(fs.readFileSync(toPath, "utf-8"));
      const diff = diffSnapshots(fromSnapshot, toSnapshot);
      return { diff };
    }),
});
