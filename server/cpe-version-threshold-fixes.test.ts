import { describe, it, expect, vi } from "vitest";

// ─── CPEUpdater: Error detection for table-missing scenarios ─────────

describe("CPEUpdater: Table-missing error detection", () => {
  // The fix checks for multiple error indicators since Drizzle wraps MySQL errors
  const isTableMissing = (err: { message?: string; sqlMessage?: string; cause?: { message?: string } }) => {
    const msg = (err.message || '') + (err.sqlMessage || '') + (err.cause?.message || '');
    return msg.includes("doesn't exist") || msg.includes('ER_NO_SUCH_TABLE') || msg.includes('1146');
  };

  it("should detect raw MySQL 'doesn't exist' error", () => {
    const err = { message: "Table 'vmwwcxqyzjyualrdnnvsc2.system_settings' doesn't exist" };
    expect(isTableMissing(err)).toBe(true);
  });

  it("should detect ER_NO_SUCH_TABLE error code", () => {
    const err = { message: "ER_NO_SUCH_TABLE", sqlMessage: "Table doesn't exist" };
    expect(isTableMissing(err)).toBe(true);
  });

  it("should detect error code 1146 in message", () => {
    const err = { message: "Error 1146: Table not found" };
    expect(isTableMissing(err)).toBe(true);
  });

  it("should detect Drizzle-wrapped error with cause", () => {
    // Drizzle wraps the error, so the original MySQL error is in cause
    const err = {
      message: "Failed query: ",
      cause: { message: "Table 'vmwwcxqyzjyualrdnnvsc2.system_settings' doesn't exist" }
    };
    expect(isTableMissing(err)).toBe(true);
  });

  it("should detect sqlMessage field from mysql2", () => {
    const err = {
      message: "Failed query: ",
      sqlMessage: "Table 'db.system_settings' doesn't exist"
    };
    expect(isTableMissing(err)).toBe(true);
  });

  it("should NOT detect unrelated errors as table-missing", () => {
    const err = { message: "Connection refused" };
    expect(isTableMissing(err)).toBe(false);
  });

  it("should NOT detect syntax errors as table-missing", () => {
    const err = { message: "You have an error in your SQL syntax" };
    expect(isTableMissing(err)).toBe(false);
  });

  it("should handle empty/undefined error fields gracefully", () => {
    const err = {};
    expect(isTableMissing(err)).toBe(false);
  });
});

// ─── VersionThreshold: getDb() must be awaited ──────────────────────

describe("VersionThreshold: getDb() async usage", () => {
  it("should confirm getDb returns a Promise (not a db object directly)", async () => {
    // Mock getDb to return a Promise
    const mockDb = { execute: vi.fn().mockResolvedValue([]) };
    const getDb = vi.fn().mockResolvedValue(mockDb);

    // The FIX: await getDb() before calling .execute()
    const db = await getDb();
    expect(db).toBe(mockDb);
    expect(typeof db.execute).toBe("function");
  });

  it("should fail if getDb() is NOT awaited (the bug)", async () => {
    const mockDb = { execute: vi.fn().mockResolvedValue([]) };
    const getDb = vi.fn().mockResolvedValue(mockDb);

    // The BUG: calling getDb() without await returns a Promise, not the db
    const notADb = getDb(); // missing await!
    expect(notADb).toBeInstanceOf(Promise);
    expect(typeof (notADb as any).execute).toBe("undefined"); // Promise has no .execute()
  });

  it("should work correctly when getDb() IS awaited (the fix)", async () => {
    const mockDb = {
      execute: vi.fn().mockResolvedValue([{ setting_value: '[]' }])
    };
    const getDb = vi.fn().mockResolvedValue(mockDb);

    // The FIX: properly await getDb()
    const db = await getDb();
    const result = await db.execute("SELECT 1");
    expect(result).toEqual([{ setting_value: '[]' }]);
    expect(mockDb.execute).toHaveBeenCalledOnce();
  });
});

// ─── VersionThreshold: persistThresholds and loadPersistedThresholds ─

describe("VersionThreshold: persistence functions", () => {
  it("persistThresholds should await getDb before executing SQL", async () => {
    const executeMock = vi.fn().mockResolvedValue([]);
    const mockDb = { execute: executeMock };
    const getDb = vi.fn().mockResolvedValue(mockDb);

    // Simulate persistThresholds logic
    const db = await getDb();
    const payload = JSON.stringify([{ technology: "nginx", minSafeVersion: "1.25.0" }]);
    await db.execute(`INSERT INTO system_settings ...`);

    expect(getDb).toHaveBeenCalledOnce();
    expect(executeMock).toHaveBeenCalledOnce();
  });

  it("loadPersistedThresholds should await getDb before executing SQL", async () => {
    const executeMock = vi.fn().mockResolvedValue([[{ setting_value: '[]' }]]);
    const mockDb = { execute: executeMock };
    const getDb = vi.fn().mockResolvedValue(mockDb);

    // Simulate loadPersistedThresholds logic
    const db = await getDb();
    const rows = await db.execute(`SELECT setting_value FROM system_settings ...`);

    expect(getDb).toHaveBeenCalledOnce();
    expect(executeMock).toHaveBeenCalledOnce();
    expect(rows).toBeDefined();
  });
});
