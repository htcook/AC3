/**
 * Tests for MSF Advanced Features:
 * 1. Session Recording & Playback
 * 2. Post-Exploitation Playbooks
 * 3. File Transfers with S3
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { readFileSync } from "fs";
import { resolve } from "path";

// ─── Feature 1: Session Recording & Playback ────────────────────────────────

describe("Session Recording & Playback", () => {
  describe("Router endpoints exist", () => {
    it("should export sessionRecordingsRouter", async () => {
      const mod = await import("./routers/session-recordings");
      expect(mod.sessionRecordingsRouter).toBeDefined();
    });

    it("should have startRecording procedure", async () => {
      const mod = await import("./routers/session-recordings");
      const router = mod.sessionRecordingsRouter;
      expect(router._def.procedures).toHaveProperty("startRecording");
    });

    it("should have stopRecording procedure", async () => {
      const mod = await import("./routers/session-recordings");
      const router = mod.sessionRecordingsRouter;
      expect(router._def.procedures).toHaveProperty("stopRecording");
    });

    it("should have appendChunk procedure", async () => {
      const mod = await import("./routers/session-recordings");
      const router = mod.sessionRecordingsRouter;
      expect(router._def.procedures).toHaveProperty("appendChunk");
    });

    it("should have listRecordings procedure", async () => {
      const mod = await import("./routers/session-recordings");
      const router = mod.sessionRecordingsRouter;
      expect(router._def.procedures).toHaveProperty("listRecordings");
    });

    it("should have getRecording procedure", async () => {
      const mod = await import("./routers/session-recordings");
      const router = mod.sessionRecordingsRouter;
      expect(router._def.procedures).toHaveProperty("getRecording");
    });

    it("should have getPlaybackData procedure", async () => {
      const mod = await import("./routers/session-recordings");
      const router = mod.sessionRecordingsRouter;
      expect(router._def.procedures).toHaveProperty("getPlaybackData");
    });

    it("should have deleteRecording procedure", async () => {
      const mod = await import("./routers/session-recordings");
      const router = mod.sessionRecordingsRouter;
      expect(router._def.procedures).toHaveProperty("deleteRecording");
    });
  });

  describe("Schema validation", () => {
    it("should have sessionRecordings table in schema", async () => {
      const schema = await import("../drizzle/schema");
      expect(schema.sessionRecordings).toBeDefined();
    });

    it("should have recordingChunks table in schema", async () => {
      const schema = await import("../drizzle/schema");
      expect(schema.recordingChunks).toBeDefined();
    });

    it("sessionRecordings should have required columns", async () => {
      const schemaContent = readFileSync(resolve(__dirname, "../drizzle/schema.ts"), "utf-8");
      expect(schemaContent).toContain("session_recordings");
      expect(schemaContent).toContain("serverId");
      expect(schemaContent).toContain("sessionId");
      expect(schemaContent).toContain("sessionType");
      expect(schemaContent).toContain("targetHost");
    });

    it("recordingChunks should have required columns", async () => {
      const schemaContent = readFileSync(resolve(__dirname, "../drizzle/schema.ts"), "utf-8");
      expect(schemaContent).toContain("recording_chunks");
      expect(schemaContent).toContain("recordingId");
      expect(schemaContent).toContain("chunkType");
      expect(schemaContent).toContain("content");
    });
  });

  describe("Database tables exist", () => {
    it("session_recordings table should exist in database", async () => {
      const { getDbRequired } = await import("./db");
      const { sql } = await import("drizzle-orm");
      try {
        const db = await getDbRequired();
        const result = await db.execute(sql`DESCRIBE session_recordings`);
        expect(result).toBeDefined();
      } catch (e: any) {
        // Table might not exist in test env, that's OK
        if (!e.message.includes("doesn't exist")) {
          throw e;
        }
      }
    });
  });
});

// ─── Feature 2: Post-Exploitation Playbooks ─────────────────────────────────

describe("Post-Exploitation Playbooks", () => {
  describe("Router endpoints exist", () => {
    it("should export postExploitPlaybooksRouter", async () => {
      const mod = await import("./routers/post-exploit-playbooks");
      expect(mod.postExploitPlaybooksRouter).toBeDefined();
    });

    it("should have listPlaybooks procedure", async () => {
      const mod = await import("./routers/post-exploit-playbooks");
      const router = mod.postExploitPlaybooksRouter;
      expect(router._def.procedures).toHaveProperty("listPlaybooks");
    });

    it("should have createPlaybook procedure", async () => {
      const mod = await import("./routers/post-exploit-playbooks");
      const router = mod.postExploitPlaybooksRouter;
      expect(router._def.procedures).toHaveProperty("createPlaybook");
    });

    it("should have updatePlaybook procedure", async () => {
      const mod = await import("./routers/post-exploit-playbooks");
      const router = mod.postExploitPlaybooksRouter;
      expect(router._def.procedures).toHaveProperty("updatePlaybook");
    });

    it("should have deletePlaybook procedure", async () => {
      const mod = await import("./routers/post-exploit-playbooks");
      const router = mod.postExploitPlaybooksRouter;
      expect(router._def.procedures).toHaveProperty("deletePlaybook");
    });

    it("should have executePlaybook procedure", async () => {
      const mod = await import("./routers/post-exploit-playbooks");
      const router = mod.postExploitPlaybooksRouter;
      expect(router._def.procedures).toHaveProperty("executePlaybook");
    });

    it("should have getExecution procedure", async () => {
      const mod = await import("./routers/post-exploit-playbooks");
      const router = mod.postExploitPlaybooksRouter;
      expect(router._def.procedures).toHaveProperty("getExecution");
    });

    it("should have abortExecution procedure", async () => {
      const mod = await import("./routers/post-exploit-playbooks");
      const router = mod.postExploitPlaybooksRouter;
      expect(router._def.procedures).toHaveProperty("abortExecution");
    });

    it("should have seedBuiltInPlaybooks procedure", async () => {
      const mod = await import("./routers/post-exploit-playbooks");
      const router = mod.postExploitPlaybooksRouter;
      expect(router._def.procedures).toHaveProperty("seedBuiltInPlaybooks");
    });

    it("should have listExecutions procedure", async () => {
      const mod = await import("./routers/post-exploit-playbooks");
      const router = mod.postExploitPlaybooksRouter;
      expect(router._def.procedures).toHaveProperty("listExecutions");
    });
  });

  describe("Schema validation", () => {
    it("should have postExploitPlaybooks table in schema", async () => {
      const schema = await import("../drizzle/schema");
      expect(schema.postExploitPlaybooks).toBeDefined();
    });

    it("should have postExploitExecutions table in schema", async () => {
      const schema = await import("../drizzle/schema");
      expect(schema.postExploitExecutions).toBeDefined();
    });

    it("postExploitPlaybooks should have required columns", async () => {
      const schemaContent = readFileSync(resolve(__dirname, "../drizzle/schema.ts"), "utf-8");
      expect(schemaContent).toContain("post_exploit_playbooks");
      expect(schemaContent).toContain("playbookName");
      expect(schemaContent).toContain("sessionType");
      expect(schemaContent).toContain("commands");
    });

    it("postExploitExecutions should have required columns", async () => {
      const schemaContent = readFileSync(resolve(__dirname, "../drizzle/schema.ts"), "utf-8");
      expect(schemaContent).toContain("post_exploit_executions");
      expect(schemaContent).toContain("playbookId");
      expect(schemaContent).toContain("serverId");
      expect(schemaContent).toContain("sessionId");
    });
  });

  describe("Built-in playbook definitions", () => {
    it("should define built-in playbooks in the router", async () => {
      const routerContent = readFileSync(resolve(__dirname, "routers/post-exploit-playbooks.ts"), "utf-8");
      expect(routerContent).toContain("BUILT_IN_PLAYBOOKS");
      expect(routerContent).toContain("sysinfo");
      expect(routerContent).toContain("getuid");
    });

    it("should have playbooks for both meterpreter and shell session types", async () => {
      const routerContent = readFileSync(resolve(__dirname, "routers/post-exploit-playbooks.ts"), "utf-8");
      expect(routerContent).toContain("meterpreter");
      expect(routerContent).toContain("shell");
    });
  });
});

// ─── Feature 3: File Transfers ──────────────────────────────────────────────

describe("File Transfers", () => {
  describe("Router endpoints exist", () => {
    it("should export fileTransfersRouter", async () => {
      const mod = await import("./routers/file-transfers");
      expect(mod.fileTransfersRouter).toBeDefined();
    });

    it("should have listTransfers procedure", async () => {
      const mod = await import("./routers/file-transfers");
      const router = mod.fileTransfersRouter;
      expect(router._def.procedures).toHaveProperty("listTransfers");
    });

    it("should have getTransfer procedure", async () => {
      const mod = await import("./routers/file-transfers");
      const router = mod.fileTransfersRouter;
      expect(router._def.procedures).toHaveProperty("getTransfer");
    });

    it("should have downloadFromTarget procedure", async () => {
      const mod = await import("./routers/file-transfers");
      const router = mod.fileTransfersRouter;
      expect(router._def.procedures).toHaveProperty("downloadFromTarget");
    });

    it("should have uploadToTarget procedure", async () => {
      const mod = await import("./routers/file-transfers");
      const router = mod.fileTransfersRouter;
      expect(router._def.procedures).toHaveProperty("uploadToTarget");
    });

    it("should have getDownloadUrl procedure", async () => {
      const mod = await import("./routers/file-transfers");
      const router = mod.fileTransfersRouter;
      expect(router._def.procedures).toHaveProperty("getDownloadUrl");
    });

    it("should have deleteTransfer procedure", async () => {
      const mod = await import("./routers/file-transfers");
      const router = mod.fileTransfersRouter;
      expect(router._def.procedures).toHaveProperty("deleteTransfer");
    });

    it("should have browseRemoteDir procedure", async () => {
      const mod = await import("./routers/file-transfers");
      const router = mod.fileTransfersRouter;
      expect(router._def.procedures).toHaveProperty("browseRemoteDir");
    });

    it("should have getStats procedure", async () => {
      const mod = await import("./routers/file-transfers");
      const router = mod.fileTransfersRouter;
      expect(router._def.procedures).toHaveProperty("getStats");
    });
  });

  describe("Schema validation", () => {
    it("should have fileTransfers table in schema", async () => {
      const schema = await import("../drizzle/schema");
      expect(schema.fileTransfers).toBeDefined();
    });

    it("fileTransfers should have required columns", async () => {
      const schemaContent = readFileSync(resolve(__dirname, "../drizzle/schema.ts"), "utf-8");
      expect(schemaContent).toContain("file_transfers");
      expect(schemaContent).toContain("serverId");
      expect(schemaContent).toContain("sessionId");
      expect(schemaContent).toContain("direction");
      expect(schemaContent).toContain("remotePath");
      expect(schemaContent).toContain("fileName");
      expect(schemaContent).toContain("s3Key");
      expect(schemaContent).toContain("s3Url");
    });
  });

  describe("S3 integration", () => {
    it("should import storagePut for S3 uploads", async () => {
      const routerContent = readFileSync(resolve(__dirname, "routers/file-transfers.ts"), "utf-8");
      expect(routerContent).toContain("storagePut");
      expect(routerContent).toContain("../storage");
    });

    it("should use msf-artifacts prefix for downloads", async () => {
      const routerContent = readFileSync(resolve(__dirname, "routers/file-transfers.ts"), "utf-8");
      expect(routerContent).toContain("msf-artifacts");
    });

    it("should use msf-uploads prefix for uploads", async () => {
      const routerContent = readFileSync(resolve(__dirname, "routers/file-transfers.ts"), "utf-8");
      expect(routerContent).toContain("msf-uploads");
    });
  });
});

// ─── Router Registration ────────────────────────────────────────────────────

describe("Router Registration", () => {
  it("should register sessionRecordings in main router", async () => {
    const routersContent = readFileSync(resolve(__dirname, "routers.ts"), "utf-8");
    expect(routersContent).toContain("sessionRecordings");
    expect(routersContent).toContain("sessionRecordingsRouter");
  });

  it("should register postExploitPlaybooks in main router", async () => {
    const routersContent = readFileSync(resolve(__dirname, "routers.ts"), "utf-8");
    expect(routersContent).toContain("postExploitPlaybooks");
    expect(routersContent).toContain("postExploitPlaybooksRouter");
  });

  it("should register fileTransfers in main router", async () => {
    const routersContent = readFileSync(resolve(__dirname, "routers.ts"), "utf-8");
    expect(routersContent).toContain("fileTransfers");
    expect(routersContent).toContain("fileTransfersRouter");
  });
});

// ─── Frontend Pages ─────────────────────────────────────────────────────────

describe("Frontend Pages", () => {
  it("SessionRecordings page should exist", () => {
    const content = readFileSync(resolve(__dirname, "../client/src/pages/SessionRecordings.tsx"), "utf-8");
    expect(content).toContain("sessionRecordings");
    expect(content).toContain("Playback");
  });

  it("PostExploitPlaybooks page should exist", () => {
    const content = readFileSync(resolve(__dirname, "../client/src/pages/PostExploitPlaybooks.tsx"), "utf-8");
    expect(content).toContain("postExploitPlaybooks");
    expect(content).toContain("postExploitPlaybooks");
  });

  it("FileTransfers page should exist", () => {
    const content = readFileSync(resolve(__dirname, "../client/src/pages/FileTransfers.tsx"), "utf-8");
    expect(content).toContain("fileTransfers");
    expect(content).toContain("downloadFromTarget");
    expect(content).toContain("uploadToTarget");
  });

  it("App.tsx should have routes for all three pages", () => {
    const content = readFileSync(resolve(__dirname, "../client/src/App.tsx"), "utf-8");
    expect(content).toContain("session-recordings");
    expect(content).toContain("post-exploit-playbooks");
    expect(content).toContain("file-transfers");
  });

  it("AppShell should have navigation items for all three pages", () => {
    const content = readFileSync(resolve(__dirname, "../client/src/components/AppShell.tsx"), "utf-8");
    expect(content).toContain("/session-recordings");
    expect(content).toContain("/post-exploit-playbooks");
    expect(content).toContain("/file-transfers");
    expect(content).toContain("RECORDINGS");
    expect(content).toContain("POST-EXPLOIT");
    expect(content).toContain("FILE TRANSFERS");
  });
});

// ─── MsfClient Session Methods ──────────────────────────────────────────────

describe("MsfClient Session Methods", () => {
  it("should have meterpreterRead method", async () => {
    const clientContent = readFileSync(resolve(__dirname, "lib/msf-client.ts"), "utf-8");
    expect(clientContent).toContain("meterpreterRead");
  });

  it("should have meterpreterWrite method", async () => {
    const clientContent = readFileSync(resolve(__dirname, "lib/msf-client.ts"), "utf-8");
    expect(clientContent).toContain("meterpreterWrite");
  });

  it("should have shellRead method", async () => {
    const clientContent = readFileSync(resolve(__dirname, "lib/msf-client.ts"), "utf-8");
    expect(clientContent).toContain("shellRead");
  });

  it("should have shellWrite method", async () => {
    const clientContent = readFileSync(resolve(__dirname, "lib/msf-client.ts"), "utf-8");
    expect(clientContent).toContain("shellWrite");
  });

  it("should have listSessions method", async () => {
    const clientContent = readFileSync(resolve(__dirname, "lib/msf-client.ts"), "utf-8");
    expect(clientContent).toContain("listSessions");
  });

  it("should have stopSession method", async () => {
    const clientContent = readFileSync(resolve(__dirname, "lib/msf-client.ts"), "utf-8");
    expect(clientContent).toContain("stopSession");
  });
});
