/**
 * SSH Key Management Router
 *
 * Provides CRUD operations for SSH keys used in exploit server tunnel connections.
 * Supports key generation, upload, rotation, and association with exploit servers.
 */

import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, adminProcedure, router } from "../_core/trpc";
import crypto from "crypto";

export const sshKeysRouter = router({
  // ─── List all SSH keys ─────────────────────────────────────────────────────
  list: protectedProcedure.query(async () => {
    const { sshKeys } = await import("../../drizzle/schema");
    const { getDbRequired } = await import("../db");
    const { sql } = await import("drizzle-orm");
    const dbConn = await getDbRequired();

    const keys = await dbConn.select({
      id: sshKeys.id,
      name: sshKeys.name,
      fingerprint: sshKeys.fingerprint,
      publicKey: sshKeys.publicKey,
      keyType: sshKeys.keyType,
      bitLength: sshKeys.bitLength,
      isDefault: sshKeys.isDefault,
      associatedServerId: sshKeys.associatedServerId,
      createdBy: sshKeys.createdBy,
      lastUsedAt: sshKeys.lastUsedAt,
      createdAt: sshKeys.createdAt,
    }).from(sshKeys).orderBy(sql`${sshKeys.createdAt} DESC`);

    return keys;
  }),

  // ─── Get a single SSH key ──────────────────────────────────────────────────
  get: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const { sshKeys } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const dbConn = await getDbRequired();

      const [key] = await dbConn.select({
        id: sshKeys.id,
        name: sshKeys.name,
        fingerprint: sshKeys.fingerprint,
        publicKey: sshKeys.publicKey,
        keyType: sshKeys.keyType,
        bitLength: sshKeys.bitLength,
        isDefault: sshKeys.isDefault,
        associatedServerId: sshKeys.associatedServerId,
        createdBy: sshKeys.createdBy,
        lastUsedAt: sshKeys.lastUsedAt,
        createdAt: sshKeys.createdAt,
      }).from(sshKeys).where(eq(sshKeys.id, input.id)).limit(1);

      if (!key) throw new TRPCError({ code: "NOT_FOUND", message: "SSH key not found" });
      return key;
    }),

  // ─── Generate a new SSH key pair ───────────────────────────────────────────
  generate: adminProcedure
    .input(z.object({
      name: z.string().min(1).max(255),
      keyType: z.enum(["ed25519", "rsa", "ecdsa"]).default("ed25519"),
      bitLength: z.number().optional(),
      passphrase: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { sshKeys } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { generateKeyPairSync } = await import("crypto");
      const dbConn = await getDbRequired();

      let publicKey: string;
      let privateKey: string;
      let actualBitLength: number | null = null;

      if (input.keyType === "ed25519") {
        const pair = generateKeyPairSync("ed25519", {
          publicKeyEncoding: { type: "spki", format: "pem" },
          privateKeyEncoding: {
            type: "pkcs8",
            format: "pem",
            ...(input.passphrase ? { cipher: "aes-256-cbc", passphrase: input.passphrase } : {}),
          },
        });
        publicKey = pair.publicKey;
        privateKey = pair.privateKey;
        actualBitLength = 256;
      } else if (input.keyType === "rsa") {
        const bits = input.bitLength || 4096;
        const pair = generateKeyPairSync("rsa", {
          modulusLength: bits,
          publicKeyEncoding: { type: "spki", format: "pem" },
          privateKeyEncoding: {
            type: "pkcs8",
            format: "pem",
            ...(input.passphrase ? { cipher: "aes-256-cbc", passphrase: input.passphrase } : {}),
          },
        });
        publicKey = pair.publicKey;
        privateKey = pair.privateKey;
        actualBitLength = bits;
      } else {
        // ECDSA
        const pair = generateKeyPairSync("ec", {
          namedCurve: "P-256",
          publicKeyEncoding: { type: "spki", format: "pem" },
          privateKeyEncoding: {
            type: "pkcs8",
            format: "pem",
            ...(input.passphrase ? { cipher: "aes-256-cbc", passphrase: input.passphrase } : {}),
          },
        });
        publicKey = pair.publicKey;
        privateKey = pair.privateKey;
        actualBitLength = 256;
      }

      // Convert PEM public key to OpenSSH format for display and server injection
      const opensshPublicKey = convertPemToOpenSSH(publicKey, input.keyType, input.name);

      // Generate fingerprint from public key
      const fingerprint = generateFingerprint(publicKey);

      // FIPS 140-3: Encrypt private key at rest
      const { encryptSSHPrivateKey, encryptServerCredential } = await import("../lib/credential-crypto");
      const encryptedPrivateKey = JSON.stringify(encryptSSHPrivateKey(privateKey));
      const encryptedPassphrase = input.passphrase ? JSON.stringify(encryptServerCredential(input.passphrase)) : null;

      const [result] = await dbConn.insert(sshKeys).values({
        name: input.name,
        fingerprint,
        publicKey: opensshPublicKey,
        privateKey: encryptedPrivateKey,
        keyType: input.keyType,
        bitLength: actualBitLength,
        passphrase: encryptedPassphrase,
        isDefault: false,
        createdBy: ctx.user?.openId || null,
      }).$returningId();

      return {
        id: result.id,
        name: input.name,
        fingerprint,
        publicKey: opensshPublicKey,
        keyType: input.keyType,
        bitLength: actualBitLength,
        message: "SSH key pair generated successfully",
      };
    }),

  // ─── Upload an existing SSH key ────────────────────────────────────────────
  upload: adminProcedure
    .input(z.object({
      name: z.string().min(1).max(255),
      publicKey: z.string().min(10),
      privateKey: z.string().min(10),
      keyType: z.enum(["ed25519", "rsa", "ecdsa"]).default("ed25519"),
      passphrase: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { sshKeys } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const dbConn = await getDbRequired();

      const fingerprint = generateFingerprint(input.publicKey);

      // FIPS 140-3: Encrypt private key at rest
      const { encryptSSHPrivateKey, encryptServerCredential } = await import("../lib/credential-crypto");
      const encryptedPrivateKey = JSON.stringify(encryptSSHPrivateKey(input.privateKey));
      const encryptedPassphrase = input.passphrase ? JSON.stringify(encryptServerCredential(input.passphrase)) : null;

      const [result] = await dbConn.insert(sshKeys).values({
        name: input.name,
        fingerprint,
        publicKey: input.publicKey,
        privateKey: encryptedPrivateKey,
        keyType: input.keyType,
        passphrase: encryptedPassphrase,
        isDefault: false,
        createdBy: ctx.user?.openId || null,
      }).$returningId();

      return {
        id: result.id,
        name: input.name,
        fingerprint,
        message: "SSH key uploaded successfully",
      };
    }),

  // ─── Delete an SSH key ─────────────────────────────────────────────────────
  delete: adminProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { sshKeys } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const dbConn = await getDbRequired();

      const [key] = await dbConn.select().from(sshKeys).where(eq(sshKeys.id, input.id)).limit(1);
      if (!key) throw new TRPCError({ code: "NOT_FOUND", message: "SSH key not found" });

      await dbConn.delete(sshKeys).where(eq(sshKeys.id, input.id));
      return { success: true, message: `SSH key "${key.name}" deleted` };
    }),

  // ─── Set a key as default ──────────────────────────────────────────────────
  setDefault: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { sshKeys } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const dbConn = await getDbRequired();

      // Unset all defaults
      await dbConn.update(sshKeys).set({ isDefault: false });
      // Set the selected key as default
      await dbConn.update(sshKeys).set({ isDefault: true }).where(eq(sshKeys.id, input.id));

      return { success: true, message: "Default SSH key updated" };
    }),

  // ─── Associate a key with an exploit server ────────────────────────────────────
  associateWithServer: protectedProcedure
    .input(z.object({
      keyId: z.number(),
      serverId: z.number(),
    }))
    .mutation(async ({ input }) => {
      const { sshKeys, metasploitServers } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const dbConn = await getDbRequired();

      const [key] = await dbConn.select().from(sshKeys).where(eq(sshKeys.id, input.keyId)).limit(1);
      if (!key) throw new TRPCError({ code: "NOT_FOUND", message: "SSH key not found" });

      const [server] = await dbConn.select().from(metasploitServers).where(eq(metasploitServers.id, input.serverId)).limit(1);
      if (!server) throw new TRPCError({ code: "NOT_FOUND", message: "Exploit server not found" });

      // Update the key's association
      await dbConn.update(sshKeys).set({ associatedServerId: input.serverId }).where(eq(sshKeys.id, input.keyId));

      // Store the private key content in a temp file path for the tunnel manager
      // The tunnel manager will read the key content directly from the DB
      await dbConn.update(metasploitServers)
        .set({ sshKeyPath: `db:ssh_key:${input.keyId}` })
        .where(eq(metasploitServers.id, input.serverId));

      return { success: true, message: `Key "${key.name}" associated with server "${server.name}"` };
    }),

  // ─── Rotate a key (generate new, replace old) ─────────────────────────────
  rotate: adminProcedure
    .input(z.object({
      id: z.number(),
      keyType: z.enum(["ed25519", "rsa", "ecdsa"]).default("ed25519"),
    }))
    .mutation(async ({ input, ctx }) => {
      const { sshKeys } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const { generateKeyPairSync } = await import("crypto");
      const dbConn = await getDbRequired();

      const [existingKey] = await dbConn.select().from(sshKeys).where(eq(sshKeys.id, input.id)).limit(1);
      if (!existingKey) throw new TRPCError({ code: "NOT_FOUND", message: "SSH key not found" });

      // Generate new key pair
      let publicKey: string;
      let privateKey: string;

      if (input.keyType === "ed25519") {
        const pair = generateKeyPairSync("ed25519", {
          publicKeyEncoding: { type: "spki", format: "pem" },
          privateKeyEncoding: { type: "pkcs8", format: "pem" },
        });
        publicKey = pair.publicKey;
        privateKey = pair.privateKey;
      } else if (input.keyType === "rsa") {
        const pair = generateKeyPairSync("rsa", {
          modulusLength: 4096,
          publicKeyEncoding: { type: "spki", format: "pem" },
          privateKeyEncoding: { type: "pkcs8", format: "pem" },
        });
        publicKey = pair.publicKey;
        privateKey = pair.privateKey;
      } else {
        const pair = generateKeyPairSync("ec", {
          namedCurve: "P-256",
          publicKeyEncoding: { type: "spki", format: "pem" },
          privateKeyEncoding: { type: "pkcs8", format: "pem" },
        });
        publicKey = pair.publicKey;
        privateKey = pair.privateKey;
      }

      const opensshPublicKey = convertPemToOpenSSH(publicKey, input.keyType, existingKey.name);
      const fingerprint = generateFingerprint(publicKey);

      // FIPS 140-3: Encrypt rotated private key at rest
      const { encryptSSHPrivateKey } = await import("../lib/credential-crypto");
      const encryptedPrivateKey = JSON.stringify(encryptSSHPrivateKey(privateKey));

      await dbConn.update(sshKeys).set({
        publicKey: opensshPublicKey,
        privateKey: encryptedPrivateKey,
        fingerprint,
        keyType: input.keyType,
      }).where(eq(sshKeys.id, input.id));

      return {
        id: input.id,
        name: existingKey.name,
        fingerprint,
        publicKey: opensshPublicKey,
        keyType: input.keyType,
        message: "SSH key rotated successfully. Remember to update the public key on associated servers.",
      };
    }),

  // ─── Inject key into a DigitalOcean droplet ────────────────────────────────
  injectToDroplet: protectedProcedure
    .input(z.object({
      keyId: z.number(),
      serverId: z.number(),
    }))
    .mutation(async ({ input }) => {
      const { sshKeys, metasploitServers } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const { ENV } = await import("../_core/env");
      const dbConn = await getDbRequired();

      const [key] = await dbConn.select().from(sshKeys).where(eq(sshKeys.id, input.keyId)).limit(1);
      if (!key) throw new TRPCError({ code: "NOT_FOUND", message: "SSH key not found" });

      const [server] = await dbConn.select().from(metasploitServers).where(eq(metasploitServers.id, input.serverId)).limit(1);
      if (!server) throw new TRPCError({ code: "NOT_FOUND", message: "Exploit server not found" });

      if (!ENV.DIGITALOCEAN_ACCESS_TOKEN) {
        throw new TRPCError({ code: "PRECONDITION_FAILED", message: "DigitalOcean token not configured" });
      }

      // Add the SSH key to DigitalOcean
      const doResp = await fetch("https://api.digitalocean.com/v2/account/keys", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${ENV.DIGITALOCEAN_ACCESS_TOKEN}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          name: `caldera-${key.name}-${Date.now()}`,
          public_key: key.publicKey,
        }),
        signal: AbortSignal.timeout(15000),
      });

      if (!doResp.ok) {
        const errText = await doResp.text().catch(() => "unknown");
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: `DigitalOcean API error: ${errText}` });
      }

      return { success: true, message: `Public key injected to DigitalOcean. You may need to add it to the server's authorized_keys manually if the droplet is already running.` };
    }),

  // ─── Get the private key content (for download) ───────────────────────────
  getPrivateKey: adminProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const { sshKeys } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const dbConn = await getDbRequired();

      const [key] = await dbConn.select().from(sshKeys).where(eq(sshKeys.id, input.id)).limit(1);
      if (!key) throw new TRPCError({ code: "NOT_FOUND", message: "SSH key not found" });

      return { privateKey: key.privateKey, name: key.name, keyType: key.keyType };
    }),
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

function generateFingerprint(publicKeyPem: string): string {
  const hash = crypto.createHash("sha256").update(publicKeyPem).digest("base64");
  return `SHA256:${hash.replace(/=+$/, "")}`;
}

function convertPemToOpenSSH(pemPublicKey: string, keyType: string, comment: string): string {
  try {
    // Extract the base64 content from PEM
    const lines = pemPublicKey.split("\n").filter(l => !l.startsWith("-----") && l.trim());
    const derB64 = lines.join("");
    const derBuffer = Buffer.from(derB64, "base64");

    // For display purposes, return a simplified format
    const typeMap: Record<string, string> = {
      ed25519: "ssh-ed25519",
      rsa: "ssh-rsa",
      ecdsa: "ecdsa-sha2-nistp256",
    };

    const sshType = typeMap[keyType] || "ssh-unknown";
    return `${sshType} ${derBuffer.toString("base64")} ${comment}`;
  } catch {
    // Fallback: return PEM as-is
    return pemPublicKey;
  }
}
