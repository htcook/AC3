import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import {
  generateTestPlan,
  testPlanToMarkdown,
  type TestPlanInput,
} from "../lib/test-plan-generator";
import {
  TEST_PLAN_CSS,
  TEST_PLAN_HEADER_HTML,
  TEST_PLAN_FOOTER_HTML,
  TEST_PLAN_TEMPLATE_CONTENT,
} from "../lib/test-plan-template";
import {
  THREAT_ACTORS,
  matchThreatActors,
  generateAptTable,
  generateExternalScenarios,
  generateInternalScenarios,
  darkenColor,
  lightenColor,
} from "../lib/threat-actor-matching";

export const testPlanGeneratorRouter = router({
  /**
   * Generate a PTES/NIST-structured test plan from DI scan results.
   *
   * Called from the DomainIntelResults page after a completed scan.
   * The frontend sends the scan data + pipeline output; we map it
   * into the TestPlanInput shape expected by the generator lib.
   */
  generate: protectedProcedure
    .input(
      z.object({
        scanId: z.number(),
        domain: z.string(),
        orgName: z.string().optional(),
        planType: z
          .enum(["penetration_test", "red_team_exercise"])
          .default("penetration_test"),
        assets: z
          .array(
            z.object({
              hostname: z.string(),
              ip: z.string().optional(),
              ports: z.array(z.number()).optional(),
              technologies: z.array(z.string()).optional(),
              hybridRiskScore: z.number().optional(),
              carverScores: z
                .object({
                  criticality: z.number().optional(),
                  accessibility: z.number().optional(),
                  recuperability: z.number().optional(),
                  vulnerability: z.number().optional(),
                  effect: z.number().optional(),
                  recognizability: z.number().optional(),
                })
                .optional(),
              missionFunction: z.string().optional(),
              essentialService: z.string().optional(),
              type: z.string().optional(),
              services: z
                .array(
                  z.object({
                    port: z.number(),
                    service: z.string(),
                    version: z.string().optional(),
                  })
                )
                .optional(),
              cloudProvider: z.string().optional(),
              wafDetected: z.string().optional(),
              certificates: z
                .array(
                  z.object({
                    subject: z.string(),
                    issuer: z.string().optional(),
                    validTo: z.string().optional(),
                  })
                )
                .optional(),
            })
          )
          .optional(),
        observations: z
          .array(
            z.object({
              category: z.string(),
              severity: z.string().optional(),
              title: z.string().optional(),
              description: z.string().optional(),
              evidence: z.any().optional(),
              tags: z.array(z.string()).optional(),
            })
          )
          .optional(),
        domainHealthData: z.any().optional(),
        wafNgfwData: z.any().optional(),
        breachData: z.any().optional(),
        threatActorData: z.any().optional(),
        dnsAssessmentData: z.any().optional(),
        llmAnalysis: z.any().optional(),
        carverFeedback: z.any().optional(),
        passiveRecon: z.any().optional(),
      })
    )
    .mutation(async ({ input, ctx }) => {
      // Derive org name from domain if not provided
      const orgName =
        input.orgName ||
        input.domain.replace(/^www\./, "").split(".")[0].replace(/-/g, " ");

      // Map assets to the lib's expected format
      const mappedAssets = (input.assets || []).map((a) => ({
        hostname: a.hostname,
        ip: a.ip,
        type: a.type || "web_server",
        services: a.services || (a.ports || []).map((p) => ({ port: p, service: `port-${p}` })),
        technologies: a.technologies || [],
        cloudProvider: a.cloudProvider,
        wafDetected: a.wafDetected,
        certificates: a.certificates || [],
      }));

      // Build passive recon summary per asset
      const passiveReconResults: Record<string, any> = {};
      for (const asset of mappedAssets) {
        passiveReconResults[asset.hostname] = {
          subdomains: [],
          ipAddresses: asset.ip ? [asset.ip] : [],
          technologies: asset.technologies || [],
          services: asset.services || [],
          wafDetected: asset.wafDetected,
          cloudProvider: asset.cloudProvider,
          certificates: asset.certificates || [],
          riskSignals: [],
        };
      }

      // Merge in connector-level passive recon if available
      if (input.passiveRecon?.connectorResults) {
        for (const cr of input.passiveRecon.connectorResults) {
          if (cr.connector === "dehashed" && cr.data?.totalResults) {
            for (const key of Object.keys(passiveReconResults)) {
              passiveReconResults[key].breachExposure = {
                count: cr.data.totalResults,
                sources: (cr.data.entries || [])
                  .map((e: any) => e.database_name)
                  .filter(Boolean)
                  .slice(0, 10),
              };
            }
          }
        }
      }

      const testPlanInput: TestPlanInput = {
        engagementId: input.scanId,
        engagementName: `DI Scan — ${input.domain}`,
        planType: input.planType,
        engagementType: input.planType === "red_team_exercise" ? "red_team" : "pentest",
        organizationName: orgName,
        systemName: input.domain,
        dataSensitivity: "moderate",
        roe: {
          status: "pending",
          authorizedDomains: [input.domain],
          authorizedIps: mappedAssets
            .map((a) => a.ip)
            .filter(Boolean) as string[],
          excludedTargets: [],
          testingWindows: ["Business hours (0800-1800 EST)"],
          escalationContacts: [],
          emergencyProcedure:
            "Stop testing immediately and contact client POC",
          dataHandling:
            "All data encrypted at rest and in transit. Destroyed within 30 days of engagement completion.",
        },
        passiveReconResults,
        assets: mappedAssets,
        dnsAssessmentData: input.dnsAssessmentData,
        operatorName: ctx.user.name || "AceofCloud Operator",
        assessorOrganization: "AceofCloud",
      };

      const plan = await generateTestPlan(testPlanInput);
      const markdown = testPlanToMarkdown(plan);

      return {
        plan,
        markdown,
        generatedAt: new Date().toISOString(),
        generatedBy: ctx.user.name || ctx.user.openId,
      };
    }),

  /**
   * Export a previously generated test plan to markdown
   */
  toMarkdown: protectedProcedure
    .input(z.object({ plan: z.any() }))
    .mutation(({ input }) => {
      return { markdown: testPlanToMarkdown(input.plan) };
    }),

  /**
   * Generate a FedRAMP-aligned Red Team Test Plan & ROE document.
   * Uses the formatted HTML template with cover page, threat actor matching,
   * and DI scan data auto-population.
   *
   * Called by the operator after DI scans complete on a customer's in-scope assets.
   */
  generateFedRAMP: protectedProcedure
    .input(z.object({
      // Data sources
      engagementId: z.number().optional(),
      diScanId: z.number().optional(),
      // Client info
      clientName: z.string(),
      clientPocName: z.string(),
      clientPocTitle: z.string(),
      clientLogoUrl: z.string().optional(),
      platformName: z.string().optional(),
      complianceFramework: z.string().default("FedRAMP High | DoD IL-5"),
      cloudEnvironment: z.string().default("AWS GovCloud"),
      targetSector: z.string().default("government saas defense dib"),
      sensitiveDataType: z.string().default("CUI"),
      // Assessor info
      assessorName: z.string().default("Harrison Cook"),
      assessorTitle: z.string().default("Director, Red Team & Penetration Testing"),
      assessorCompany: z.string().default("Ace of Cloud"),
      // Access model
      initialAccessModel: z.enum(["assumed_breach", "phishing", "external_exploit"]).default("assumed_breach"),
      // Color scheme
      primaryColor: z.string().default("#2b5797"),
      // Additional personnel
      additionalPersonnel: z.array(z.object({
        name: z.string(),
        role: z.string(),
        phone: z.string().optional(),
        email: z.string().optional(),
        organization: z.string().optional(),
      })).optional(),
      // Test site
      testSiteDescription: z.string().optional(),
      // Exclusions
      outOfScope: z.array(z.string()).optional(),
      // Save as template
      saveAsTemplate: z.boolean().default(true),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");

      // Fetch DI scan data if provided
      let discoveredAssets: any[] = [];
      if (input.diScanId) {
        const { domainIntelScans, discoveredAssets: assetsTable } = await import("../../drizzle/schema");
        const scan = await db.select().from(domainIntelScans).where(eq(domainIntelScans.id, input.diScanId));
        if (scan[0]) {
          discoveredAssets = await db.select().from(assetsTable).where(eq(assetsTable.scanId, input.diScanId)).limit(100);
        }
      }

      // Match threat actors based on sector
      const matchedActors = matchThreatActors(input.targetSector);

      // Build in-scope assets table
      let inScopeAssetsTable = `<table><thead><tr><th>Asset / Domain</th><th>Type</th><th>IP Address(es)</th><th>Services</th></tr></thead><tbody>`;
      if (discoveredAssets.length > 0) {
        for (const asset of discoveredAssets.slice(0, 20)) {
          const ips = (asset.ipAddresses as string[])?.join(', ') || asset.ipAddress || 'N/A';
          const services = (asset.openPorts as any[])?.map((p: any) => `${p.port}/${p.service || 'unknown'}`).join(', ') || 'See scan results';
          inScopeAssetsTable += `<tr><td>${asset.hostname}</td><td>${asset.assetType || 'subdomain'}</td><td>${ips}</td><td>${services}</td></tr>`;
        }
      } else {
        inScopeAssetsTable += `<tr><td colspan="4" style="text-align: center; font-style: italic;">Assets will be populated from DI scan results</td></tr>`;
      }
      inScopeAssetsTable += `</tbody></table>`;

      // Build discovered services table
      let discoveredServicesTable = `<table><thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Technology</th><th>Status</th></tr></thead><tbody>`;
      if (discoveredAssets.length > 0) {
        for (const asset of discoveredAssets.filter((a: any) => (a.openPorts as any[])?.length > 0).slice(0, 15)) {
          for (const port of ((asset.openPorts as any[]) || []).slice(0, 5)) {
            discoveredServicesTable += `<tr><td>${asset.hostname}</td><td>${port.port}</td><td>${port.service || port.protocol || 'unknown'}</td><td>${port.product || port.version || '-'}</td><td>Open</td></tr>`;
          }
        }
      } else {
        discoveredServicesTable += `<tr><td colspan="5" style="text-align: center; font-style: italic;">Service discovery results will be populated after DI scan completion</td></tr>`;
      }
      discoveredServicesTable += `</tbody></table>`;

      // Build personnel table
      const defaultPersonnel = [
        { name: input.assessorName, role: "Red Team Exercise Lead", phone: "(571) 320-0132", email: "Harrison.Cook@aceofcloud.com" },
        { name: "Nathaniel Cook", role: "Project Manager / Red Team Operator", phone: "(804) 997-9197", email: "Nathaniel.Cook@aceofcloud.com" },
        { name: input.clientPocName, role: `${input.clientPocTitle} — ${input.clientName}`, phone: "", email: "" },
      ];
      const allPersonnel = [...defaultPersonnel, ...(input.additionalPersonnel || []).map(p => ({ name: p.name, role: p.role, phone: p.phone || '', email: p.email || '' }))];
      let personnelTable = `<table><thead><tr><th>Name</th><th>Role</th><th>Phone</th><th>Email</th></tr></thead><tbody>`;
      for (const p of allPersonnel) {
        personnelTable += `<tr><td>${p.name}</td><td>${p.role}</td><td>${p.phone}</td><td>${p.email}</td></tr>`;
      }
      personnelTable += `</tbody></table>`;

      // Build schedule table
      const accessLabel = input.initialAccessModel === 'assumed_breach' ? 'Assumed Breach' : input.initialAccessModel === 'phishing' ? 'Phishing Campaign' : 'External Exploitation';
      const scheduleTable = `<table><thead><tr><th>Task</th><th>Estimated Start</th><th>Estimated End</th><th>Duration</th></tr></thead><tbody>
        <tr><td>Documentation Development</td><td>TBD</td><td>TBD</td><td>2 Weeks</td></tr>
        <tr><td>Phase I — Reconnaissance and Enumeration</td><td>TBD</td><td>TBD</td><td>2 Weeks</td></tr>
        <tr><td>Phase II — Active Testing (${accessLabel})</td><td>TBD</td><td>TBD</td><td>2 Weeks</td></tr>
        <tr><td>Draft Report</td><td>After Testing</td><td></td><td>2 Days</td></tr>
        <tr><td>Receive Comments</td><td></td><td></td><td>1 Week</td></tr>
        <tr><td>Final Report</td><td></td><td></td><td>1 Day</td></tr>
      </tbody></table>`;

      // Build test equipment table
      const testEquipmentTable = `<table><thead><tr><th>IP Address / Hostname</th><th>MAC Address</th><th>Role / Function</th><th>Comments</th></tr></thead><tbody>
        <tr><td>TBD / Hanzo</td><td>7C-5C-F8-14-36-F1</td><td>Red Team Workstation 1</td><td>Caldera/Test Tools box</td></tr>
        <tr><td>TBD / Ogami</td><td>B4-8C-9D-90-AA-BB</td><td>Red Team Workstation 2</td><td>Primary laptop — ${input.assessorName}</td></tr>
        <tr><td>52.55.246.40</td><td>N/A — AWS Hosted</td><td>C2 Server</td><td>MITRE Caldera Server</td></tr>
        <tr><td>54.159.118.192</td><td>N/A — AWS Hosted</td><td>ScanForge Server</td><td>Automated scanning and enumeration</td></tr>
      </tbody></table>`;

      // Communications recipients table
      const communicationsTable = `<table><thead><tr><th>Name</th><th>Role</th><th>Phone</th><th>Email</th></tr></thead><tbody>
        <tr><td>${input.clientPocName}</td><td>${input.clientPocTitle}</td><td></td><td></td></tr>
        ${(input.additionalPersonnel || []).filter(p => p.role?.toLowerCase().includes('cto') || p.role?.toLowerCase().includes('isso') || p.role?.toLowerCase().includes('security')).map(p => `<tr><td>${p.name}</td><td>${p.role}</td><td>${p.phone || ''}</td><td>${p.email || ''}</td></tr>`).join('')}
      </tbody></table>`;

      // Out of scope list
      const defaultExclusions = [
        "Denial of Service (DoS/DDoS) attacks against production systems",
        "Physical security testing or social engineering of non-IT personnel",
        "Testing of third-party systems not owned by " + input.clientName,
        "Mobile device testing",
        "Modification or destruction of production data",
      ];
      const exclusions = input.outOfScope && input.outOfScope.length > 0 ? input.outOfScope : defaultExclusions;
      const outOfScopeList = `<ul>${exclusions.map(e => `<li>${e}</li>`).join('')}</ul>`;

      // Initial access descriptions
      const accessModelDescriptions: Record<string, { description: string; method: string }> = {
        assumed_breach: {
          description: `This engagement will utilize an <strong>Assumed Breach</strong> model. In lieu of a phishing campaign, the Red Team will begin the internal testing phase with stolen tenant credentials provided by ${input.clientName} security personnel. This simulates a scenario where an adversary has obtained valid user credentials through credential theft, breach data, or social engineering — consistent with the initial access methods employed by the threat actors modeled in this exercise.`,
          method: "Leverage stolen tenant credentials (assumed breach) to gain authenticated access to the environment.",
        },
        phishing: {
          description: `This engagement will include a targeted phishing campaign against ${input.clientName} personnel to simulate real-world initial access techniques used by the modeled threat actors.`,
          method: "Conduct targeted spearphishing campaign to harvest credentials or deliver initial payload.",
        },
        external_exploit: {
          description: `This engagement will attempt to gain initial access through exploitation of externally-facing services and applications, simulating an adversary with no prior internal access.`,
          method: "Exploit vulnerabilities in public-facing applications to establish initial foothold.",
        },
      };
      const accessDesc = accessModelDescriptions[input.initialAccessModel];

      // Color variants
      const primaryDark = darkenColor(input.primaryColor);
      const primaryLight = lightenColor(input.primaryColor);

      // Build variables map
      const variables: Record<string, string> = {
        client_name: input.clientName,
        client_poc_name: input.clientPocName,
        client_poc_title: input.clientPocTitle,
        client_logo_url: input.clientLogoUrl || '',
        platform_name: input.platformName || `${input.clientName} Platform`,
        compliance_framework: input.complianceFramework,
        cloud_environment: input.cloudEnvironment,
        target_sector: input.targetSector,
        sensitive_data_type: input.sensitiveDataType,
        assessor_name: input.assessorName,
        assessor_title: input.assessorTitle,
        assessor_company: input.assessorCompany,
        primary_color: input.primaryColor,
        primary_dark: primaryDark,
        primary_light: primaryLight,
        initial_access_model: accessLabel,
        initial_access_description: accessDesc.description,
        initial_access_method: accessDesc.method,
        lateral_movement_methods: "stolen credentials, cloud service account tokens, and IAM role assumptions",
        credential_sources: "cloud secrets managers, environment variables, and metadata services",
        persistence_mechanisms: "modified cloud IAM policies, scheduled tasks, and backdoor accounts",
        privilege_escalation_targets: "RBAC configurations, container runtime, and IAM policies",
        in_scope_assets_table: inScopeAssetsTable,
        discovered_services_table: discoveredServicesTable,
        out_of_scope_list: outOfScopeList,
        personnel_table: personnelTable,
        schedule_table: scheduleTable,
        test_equipment_table: testEquipmentTable,
        communications_recipients_table: communicationsTable,
        test_site_description: input.testSiteDescription || `${input.assessorName} will be based in Virginia for this engagement and understands that all work will be done in coordination with ${input.clientName}. Remote testing will be performed from a secure lab in Mechanicsville, VA. VPN access to the ${input.clientName} internal environment will be provided by ${input.clientName} security personnel for the internal testing phase.`,
        apt_groups_table: generateAptTable(matchedActors),
        external_testing_scenarios: generateExternalScenarios(matchedActors, discoveredAssets.map((a: any) => a.hostname)),
        internal_testing_scenarios: generateInternalScenarios(matchedActors, input.initialAccessModel),
        additional_framework: input.complianceFramework.includes('DoD') ? 'CMMC 2.0' : 'SOC 2',
        additional_control: input.complianceFramework.includes('DoD') ? 'CA.L2-3.12.1' : 'CC7.1',
        additional_requirement: input.complianceFramework.includes('DoD') ? 'Security Assessment' : 'System Monitoring',
      };

      // Render the template by replacing all {{variable}} placeholders
      let renderedContent = TEST_PLAN_TEMPLATE_CONTENT;
      let renderedCss = TEST_PLAN_CSS;
      let renderedHeader = TEST_PLAN_HEADER_HTML;
      let renderedFooter = TEST_PLAN_FOOTER_HTML;

      for (const [key, value] of Object.entries(variables)) {
        const regex = new RegExp(`\\{\\{\\s*${key}\\s*\\}\\}`, 'g');
        renderedContent = renderedContent.replace(regex, value);
        renderedCss = renderedCss.replace(regex, value);
        renderedHeader = renderedHeader.replace(regex, value);
        renderedFooter = renderedFooter.replace(regex, value);
      }

      const fullHtml = `<!DOCTYPE html><html><head><meta charset="utf-8"><style>${renderedCss}</style></head><body>${renderedHeader}${renderedContent}${renderedFooter}</body></html>`;

      // Save as a report template if requested
      let templateId: number | null = null;
      if (input.saveAsTemplate) {
        const { reportTemplates } = await import("../../drizzle/schema");
        const templateResult = await db.insert(reportTemplates).values({
          rtName: `Red Team Test Plan & ROE — ${input.clientName}`,
          rtDescription: `FedRAMP-aligned Red Team Exercise Test Plan & ROE for ${input.clientName}. ${input.complianceFramework} with ${matchedActors.length} matched threat actors (${matchedActors.map(a => a.name.split(' (')[0]).join(', ')}).`,
          rtType: 'engagement',
          rtContent: TEST_PLAN_TEMPLATE_CONTENT,
          rtHeaderHtml: TEST_PLAN_HEADER_HTML,
          rtFooterHtml: TEST_PLAN_FOOTER_HTML,
          rtCssOverrides: TEST_PLAN_CSS,
          rtLogoUrl: input.clientLogoUrl || null,
          rtPrimaryColor: input.primaryColor,
          rtCreatedBy: String(ctx.user.id),
        });
        templateId = templateResult[0].insertId;
      }

      return {
        templateId,
        renderedHtml: fullHtml,
        matchedActors: matchedActors.map(a => ({ name: a.name, origin: a.origin, motivation: a.motivation, ttpCount: a.ttps.length })),
        variables,
        diScanUsed: discoveredAssets.length > 0,
        assetsDiscovered: discoveredAssets.length,
        generatedAt: new Date().toISOString(),
        generatedBy: ctx.user.name || ctx.user.openId,
      };
    }),

  /**
   * List available threat actors for preview/selection
   */
  listThreatActors: protectedProcedure
    .input(z.object({ sector: z.string().optional() }))
    .query(({ input }) => {
      if (input.sector) {
        const matched = matchThreatActors(input.sector, 6);
        return matched.map(a => ({
          name: a.name,
          aliases: a.aliases,
          origin: a.origin,
          motivation: a.motivation,
          targetSectors: a.targetSectors,
          ttpCount: a.ttps.length,
        }));
      }
      return Object.values(THREAT_ACTORS).map(a => ({
        name: a.name,
        aliases: a.aliases,
        origin: a.origin,
        motivation: a.motivation,
        targetSectors: a.targetSectors,
        ttpCount: a.ttps.length,
      }));
    }),
});
