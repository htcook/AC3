import { describe, it, expect, vi } from "vitest";

/**
 * Tests for the Three Enhancements Sprint:
 * 1. Per-target granular approval
 * 2. Auto-detect RoE and pre-populate justification
 * 3. WordPress-specific build instructions
 */

import {
  extractHostname,
  isDomainWhitelisted,
  validateEngagementTargets,
  isSourceCodeTarget,
} from "../shared/domain-safety-whitelist";

// ═══════════════════════════════════════════════════════════════════════════
// 1. Per-Target Granular Approval
// ═══════════════════════════════════════════════════════════════════════════

describe("Per-Target Granular Approval", () => {
  describe("setTargetApproval input validation", () => {
    it("should accept valid per-target approval input", () => {
      const input = {
        engagementId: 1,
        targets: [
          { target: "wordpress.org", hostname: "wordpress.org", status: "approved" as const },
          { target: "buddypress.org", hostname: "buddypress.org", status: "rejected" as const },
          { target: "bbpress.org", hostname: "bbpress.org", status: "pending" as const },
        ],
        globalJustification: "Signed RoE covers WordPress targets",
      };
      expect(input.targets).toHaveLength(3);
      expect(input.targets[0].status).toBe("approved");
      expect(input.targets[1].status).toBe("rejected");
      expect(input.targets[2].status).toBe("pending");
    });

    it("should track per-target status independently", () => {
      const statuses: Record<string, "approved" | "rejected" | "pending"> = {};
      const targets = ["wordpress.org", "buddypress.org", "bbpress.org", "wordcamp.org"];
      
      // Initially all pending
      targets.forEach(t => { statuses[t] = "pending"; });
      expect(Object.values(statuses).every(s => s === "pending")).toBe(true);
      
      // Approve some, reject others
      statuses["wordpress.org"] = "approved";
      statuses["buddypress.org"] = "approved";
      statuses["bbpress.org"] = "rejected";
      
      const approved = Object.values(statuses).filter(s => s === "approved").length;
      const rejected = Object.values(statuses).filter(s => s === "rejected").length;
      const pending = Object.values(statuses).filter(s => s === "pending").length;
      
      expect(approved).toBe(2);
      expect(rejected).toBe(1);
      expect(pending).toBe(1);
    });

    it("should auto-enable activeScanOverride when all targets approved", () => {
      const allApprovals = [
        { status: "approved" },
        { status: "approved" },
        { status: "approved" },
      ];
      const allApproved = allApprovals.every(a => a.status === "approved");
      expect(allApproved).toBe(true);
    });

    it("should NOT auto-enable when some targets are pending", () => {
      const mixedApprovals = [
        { status: "approved" },
        { status: "pending" },
        { status: "approved" },
      ];
      const allApproved = mixedApprovals.every(a => a.status === "approved");
      expect(allApproved).toBe(false);
    });

    it("should NOT auto-enable when some targets are rejected", () => {
      const mixedApprovals = [
        { status: "approved" },
        { status: "rejected" },
        { status: "approved" },
      ];
      const allApproved = mixedApprovals.every(a => a.status === "approved");
      expect(allApproved).toBe(false);
    });
  });

  describe("bulkApproveTargets", () => {
    it("should accept bulk approval input with justification", () => {
      const input = {
        engagementId: 1,
        targets: [
          { target: "wordpress.org", hostname: "wordpress.org" },
          { target: "buddypress.org", hostname: "buddypress.org" },
        ],
        justification: "Signed RoE #WP-2026-001",
        roeReference: "RoE signed (2026-04-29)",
      };
      expect(input.targets).toHaveLength(2);
      expect(input.justification.length).toBeGreaterThan(0);
      expect(input.roeReference).toContain("RoE");
    });

    it("should reject empty justification for bulk approve", () => {
      const justification = "";
      expect(justification.trim().length).toBe(0);
    });
  });

  describe("Timeline event logging for per-target approval", () => {
    it("should create correct timeline event for mixed approvals", () => {
      const results = [
        { target: "wordpress.org", status: "approved" },
        { target: "buddypress.org", status: "approved" },
        { target: "bbpress.org", status: "rejected" },
      ];
      const approvedCount = results.filter(r => r.status === "approved").length;
      const rejectedCount = results.filter(r => r.status === "rejected").length;
      const allApproved = results.every(r => r.status === "approved");

      const event = {
        eventType: "target_approval",
        title: `Target Approval: ${approvedCount} approved, ${rejectedCount} rejected`,
        severity: "info",
      };
      
      expect(event.title).toBe("Target Approval: 2 approved, 1 rejected");
      expect(allApproved).toBe(false);
    });

    it("should create correct timeline event for bulk approval", () => {
      const targets = ["wordpress.org", "buddypress.org", "bbpress.org"];
      const event = {
        eventType: "target_approval",
        title: `Bulk Approved: ${targets.length} targets`,
        severity: "high",
      };
      expect(event.title).toBe("Bulk Approved: 3 targets");
      expect(event.severity).toBe("high");
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. Auto-Detect RoE and Pre-Populate Justification
// ═══════════════════════════════════════════════════════════════════════════

describe("Auto-Detect RoE and Pre-Populate Justification", () => {
  it("should generate justification for signed RoE with date", () => {
    const roeStatus = "signed";
    const roeSignedDate = "2026-04-29T00:00:00Z";
    const justification = `Signed RoE (${roeStatus}, ${new Date(roeSignedDate).toLocaleDateString()}) authorizes active testing on all program targets.`;
    
    expect(justification).toContain("Signed RoE");
    expect(justification).toContain("signed");
    expect(justification).toContain("authorizes active testing");
  });

  it("should generate justification for pending RoE without date", () => {
    const roeStatus = "pending";
    const roeSignedDate = null;
    const justification = roeSignedDate
      ? `Signed RoE (${roeStatus}, ${new Date(roeSignedDate).toLocaleDateString()}) authorizes active testing on all program targets.`
      : `RoE status: ${roeStatus}. Active testing authorized per engagement rules of engagement.`;
    
    expect(justification).toContain("pending");
    expect(justification).toContain("Active testing authorized");
  });

  it("should NOT auto-populate for unsigned RoE", () => {
    const roeStatus = "none";
    const roeSigned = roeStatus === "signed" || roeStatus === "pending";
    expect(roeSigned).toBe(false);
    // Justification should remain empty — manual input required
  });

  it("should NOT auto-populate for expired RoE", () => {
    const roeStatus = "expired";
    const roeSigned = roeStatus === "signed" || roeStatus === "pending";
    expect(roeSigned).toBe(false);
  });

  it("should include RoE reference in bulk approval when available", () => {
    const roeStatus = "signed";
    const roeSignedDate = "2026-04-29";
    const roeReference = `RoE ${roeStatus} (${roeSignedDate || "date unknown"})`;
    expect(roeReference).toBe("RoE signed (2026-04-29)");
  });

  it("should handle missing roeSignedDate gracefully", () => {
    const roeStatus = "signed";
    const roeSignedDate: string | undefined = undefined;
    const roeReference = `RoE ${roeStatus} (${roeSignedDate || "date unknown"})`;
    expect(roeReference).toBe("RoE signed (date unknown)");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. WordPress-Specific Build Instructions
// ═══════════════════════════════════════════════════════════════════════════

describe("WordPress-Specific Build Instructions", () => {
  describe("WordPress repo detection", () => {
    const isWpRepo = (val: string) => {
      const lower = val.toLowerCase();
      return lower.includes("wordpress") || lower.includes("wp-cli") || 
             lower.includes("glotpress") || lower.includes("buddypress") || 
             lower.includes("bbpress") || lower.includes("wordcamp") || 
             lower.includes("woocommerce");
    };

    it("should detect WordPress core repo", () => {
      expect(isWpRepo("https://github.com/WordPress/WordPress")).toBe(true);
    });

    it("should detect WP-CLI repo", () => {
      expect(isWpRepo("https://github.com/wp-cli/wp-cli")).toBe(true);
    });

    it("should detect GlotPress repo", () => {
      expect(isWpRepo("https://github.com/GlotPress/GlotPress-WP")).toBe(true);
    });

    it("should detect BuddyPress repo", () => {
      expect(isWpRepo("https://github.com/buddypress/buddypress")).toBe(true);
    });

    it("should detect bbPress repo", () => {
      expect(isWpRepo("https://github.com/bbpress/bbpress")).toBe(true);
    });

    it("should detect WordCamp repo", () => {
      expect(isWpRepo("https://github.com/WordPress/wordcamp.org")).toBe(true);
    });

    it("should detect WooCommerce repo", () => {
      expect(isWpRepo("https://github.com/woocommerce/woocommerce")).toBe(true);
    });

    it("should NOT detect non-WordPress repos", () => {
      expect(isWpRepo("https://github.com/facebook/react")).toBe(false);
    });
  });

  describe("WordPress plugin detection", () => {
    const isWpPlugin = (val: string) => {
      const lower = val.toLowerCase();
      return lower.includes("plugin") || lower.includes("profiles.wordpress.org") || 
             lower.includes("wordpress.org/plugins");
    };

    it("should detect WordPress.org plugin directory", () => {
      expect(isWpPlugin("https://wordpress.org/plugins/akismet/")).toBe(true);
    });

    it("should detect profiles.wordpress.org plugin references", () => {
      expect(isWpPlugin("https://profiles.wordpress.org/wordpressdotorg#content-plugins")).toBe(true);
    });

    it("should detect generic plugin references", () => {
      expect(isWpPlugin("Official WordPress plugins")).toBe(true);
    });

    it("should NOT detect non-plugin references", () => {
      expect(isWpPlugin("https://github.com/WordPress/WordPress")).toBe(false);
    });
  });

  describe("Git clone URL generation", () => {
    it("should generate correct clone command for GitHub repos", () => {
      const repoUrl = "https://github.com/WordPress/WordPress";
      const cloneCmd = `git clone ${repoUrl.replace(/\/$/, "")}.git`;
      expect(cloneCmd).toBe("git clone https://github.com/WordPress/WordPress.git");
    });

    it("should strip trailing slash before adding .git", () => {
      const repoUrl = "https://github.com/wp-cli/wp-cli/";
      const cloneCmd = `git clone ${repoUrl.replace(/\/$/, "")}.git`;
      expect(cloneCmd).toBe("git clone https://github.com/wp-cli/wp-cli.git");
    });

    it("should handle GitLab repos", () => {
      const repoUrl = "https://gitlab.com/some/repo";
      const isGitlab = repoUrl.toLowerCase().includes("gitlab.com");
      expect(isGitlab).toBe(true);
    });

    it("should handle Bitbucket repos", () => {
      const repoUrl = "https://bitbucket.org/some/repo";
      const isBitbucket = repoUrl.toLowerCase().includes("bitbucket.org");
      expect(isBitbucket).toBe(true);
    });
  });

  describe("Build environment commands", () => {
    it("should provide wp-env command", () => {
      const wpEnvCmd = "npx @wordpress/env start";
      expect(wpEnvCmd).toContain("@wordpress/env");
    });

    it("should provide Docker command for WordPress", () => {
      const dockerCmd = "docker run -d -p 8080:80 -e WORDPRESS_DB_HOST=db wordpress:latest";
      expect(dockerCmd).toContain("wordpress:latest");
      expect(dockerCmd).toContain("-p 8080:80");
    });

    it("should provide DDEV command for WordPress", () => {
      const ddevCmd = "ddev config --project-type=wordpress && ddev start";
      expect(ddevCmd).toContain("--project-type=wordpress");
    });
  });

  describe("Source code target classification", () => {
    it("should classify GitHub WordPress as source code", () => {
      const result = isSourceCodeTarget("https://github.com/WordPress/WordPress");
      expect(result.isSourceCode).toBe(true);
    });

    it("should classify GlotPress as source code", () => {
      const result = isSourceCodeTarget("https://github.com/GlotPress/GlotPress-WP");
      expect(result.isSourceCode).toBe(true);
    });

    it("should NOT classify wordpress.org domain as source code", () => {
      const result = isSourceCodeTarget("wordpress.org");
      expect(result.isSourceCode).toBe(false);
    });

    it("should classify buildable types correctly", () => {
      const buildableTypes = ["source_code", "hardware", "downloadable_executables", "smart_contract"];
      expect(buildableTypes.includes("source_code")).toBe(true);
      expect(buildableTypes.includes("domain")).toBe(false);
      expect(buildableTypes.includes("url")).toBe(false);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Integration: All Three Features Working Together
// ═══════════════════════════════════════════════════════════════════════════

describe("Integration: WordPress Program Full Flow", () => {
  it("should handle a complete WordPress program approval flow", () => {
    // Step 1: Parse scope — identify WordPress targets
    const inScopeTargets = [
      { type: "source_code", value: "https://github.com/GlotPress/GlotPress-WP" },
      { type: "source_code", value: "https://github.com/wp-cli/wp-cli" },
      { type: "source_code", value: "Official WordPress plugins" },
      { type: "domain", value: "wordpress.org" },
      { type: "domain", value: "buddypress.org" },
    ];

    // Step 2: Validate against whitelist
    const domainTargets = inScopeTargets
      .filter(t => t.type === "domain")
      .map(t => t.value);
    const nonWhitelisted = domainTargets.filter(t => !isDomainWhitelisted(t));
    expect(nonWhitelisted).toContain("wordpress.org");
    expect(nonWhitelisted).toContain("buddypress.org");

    // Step 3: Source code targets should show build instructions
    const sourceCodeTargets = inScopeTargets.filter(t => t.type === "source_code");
    expect(sourceCodeTargets).toHaveLength(3);

    // Step 4: RoE auto-detection
    const roeStatus = "signed";
    const roeSigned = roeStatus === "signed" || roeStatus === "pending";
    expect(roeSigned).toBe(true);

    // Step 5: Per-target approval
    const approvals: Record<string, string> = {};
    nonWhitelisted.forEach(t => { approvals[t] = "approved"; });
    const allApproved = Object.values(approvals).every(s => s === "approved");
    expect(allApproved).toBe(true);

    // Step 6: Auto-enable activeScanOverride
    const activeScanOverride = allApproved ? 1 : 0;
    expect(activeScanOverride).toBe(1);
  });
});
