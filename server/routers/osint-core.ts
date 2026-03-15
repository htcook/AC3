import { notifyOwner } from "../_core/notification";
import { fetchGophishAPI } from "../lib/api-helpers";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../_core/trpc";
import { z } from "zod";
import * as db from "../db";
import { invokeLLM } from "../_core/llm";
import { and, max, min, not, or } from "drizzle-orm";
import * as schema from "../../drizzle/schema";

export const osintRouter = router({
    // Start a full domain recon scan for an engagement
    startRecon: protectedProcedure
      .input(z.object({
        engagementId: z.number(),
        domain: z.string().min(3),
      }))
      .mutation(async ({ input, ctx }) => {
        const { runFullRecon } = await import('../osint');
        const { invokeLLM } = await import('../_core/llm');

        // Create recon record in pending state
        const reconId = await db.createDomainRecon({
          engagementId: input.engagementId,
          domain: input.domain,
          scanStatus: 'running',
          scanStartedAt: new Date(),
        });

        // Run the recon (async but we await it)
        try {
          const result = await runFullRecon(input.domain);

          // Generate LLM spoofability analysis
          let spoofAnalysis = '';
          try {
            const llmResponse = await invokeLLM({ _caller: "osint-core", _priority: 'bulk',
              messages: [
                {
                  role: 'system',
                  content: 'You are a red team email security analyst. Analyze the DNS/email security configuration and provide a concise tactical assessment for a phishing engagement. Be specific about what attacks are possible.'
                },
                {
                  role: 'user',
                  content: `Domain: ${input.domain}\nSPF: ${result.dns.spfRecord || 'NONE'}\nDMARC: ${result.dns.dmarcRecord || 'NONE'}\nDKIM Found: ${result.dns.dkimFound}\nMX Records: ${JSON.stringify(result.dns.mxRecords)}\nSpoof Score: ${result.spoofability.score}/100\n\nProvide a 3-4 sentence tactical assessment: Can we spoof this domain directly? What email security gaps exist? What approach do you recommend for a phishing campaign?`
                }
              ]
            });
            spoofAnalysis = (llmResponse?.choices?.[0]?.message?.content as string) || '';
          } catch { /* LLM optional */ }

          // Store findings in DB
          await db.updateDomainRecon(reconId, {
            mxRecords: result.dns.mxRecords as any,
            spfRecord: result.dns.spfRecord,
            dmarcRecord: result.dns.dmarcRecord,
            nsRecords: result.dns.nsRecords as any,
            aRecords: result.dns.aRecords as any,
            subdomains: result.subdomains as any,
            spoofable: result.spoofability.spoofable,
            spoofScore: result.spoofability.score,
            spoofAnalysis,
            scanStatus: 'completed',
            scanCompletedAt: new Date(),
          });

          // Create OSINT findings for notable items
          const findings: any[] = [];

          // DNS misconfigurations
          for (const factor of result.spoofability.factors) {
            if (factor.impact === 'critical' || factor.impact === 'high') {
              findings.push({
                engagementId: input.engagementId,
                reconId,
                category: 'dns_misconfiguration',
                severity: factor.impact === 'critical' ? 'critical' : 'high',
                title: factor.factor,
                description: factor.detail,
                source: 'dns_analysis',
              });
            }
          }

          // Subdomains as findings
          if (result.subdomains.length > 0) {
            findings.push({
              engagementId: input.engagementId,
              reconId,
              category: 'subdomain',
              severity: 'info',
              title: `${result.subdomains.length} subdomains discovered via Certificate Transparency`,
              description: `Subdomains found: ${result.subdomains.slice(0, 20).join(', ')}${result.subdomains.length > 20 ? '...' : ''}`,
              rawData: result.subdomains as any,
              source: 'crt.sh',
            });
          }

          if (findings.length > 0) {
            await db.bulkCreateOsintFindings(findings);
          }

          // Store typosquat candidates
          if (result.typosquats.length > 0) {
            const typosquatRecords = result.typosquats.slice(0, 200).map(t => ({
              engagementId: input.engagementId,
              reconId,
              originalDomain: input.domain,
              permutedDomain: t.domain,
              permutationType: t.type,
            }));
            await db.bulkCreateTyposquatDomains(typosquatRecords);
          }

          await db.logActivity({
            userId: ctx.user.id,
            action: 'osint_recon_completed',
            details: `Domain recon completed for ${input.domain} (engagement ${input.engagementId}). Score: ${result.spoofability.score}/100, ${result.subdomains.length} subdomains, ${result.typosquats.length} typosquats`,
          });

          return {
            reconId,
            spoofScore: result.spoofability.score,
            spoofable: result.spoofability.spoofable,
            subdomainCount: result.subdomains.length,
            typosquatCount: result.typosquats.length,
          };
        } catch (err: any) {
          await db.updateDomainRecon(reconId, {
            scanStatus: 'failed',
            scanCompletedAt: new Date(),
          });
          throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: err.message });
        }
      }),

    // Get recon results for an engagement
    getRecon: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        return db.getDomainReconByEngagement(input.engagementId);
      }),

    // Get single recon by ID
    getReconById: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        return db.getDomainReconById(input.id);
      }),

    // Get typosquat domains for an engagement
    getTyposquats: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        return db.getTyposquatsByEngagement(input.engagementId);
      }),

    // Check DNS resolution for a specific typosquat domain
    checkTyposquat: protectedProcedure
      .input(z.object({ id: z.number(), domain: z.string() }))
      .mutation(async ({ input }) => {
        const { checkDomainRegistration } = await import('../osint');
        const result = await checkDomainRegistration(input.domain);
        await db.updateTyposquatDomain(input.id, {
          isRegistered: result.resolved,
          dnsResolved: result.resolved,
          resolvedIp: result.ip,
          mxRecords: result.mx as any,
        });
        return result;
      }),

    // Batch check typosquat domains (check top N)
    batchCheckTyposquats: protectedProcedure
      .input(z.object({ reconId: z.number(), limit: z.number().min(1).max(50).default(20) }))
      .mutation(async ({ input }) => {
        const { checkDomainRegistration } = await import('../osint');
        const domains = await db.getTyposquatsByRecon(input.reconId);
        const toCheck = domains.slice(0, input.limit);
        const results: Array<{ id: number; domain: string; resolved: boolean; ip: string | null }> = [];

        for (const d of toCheck) {
          try {
            const result = await checkDomainRegistration(d.permutedDomain);
            await db.updateTyposquatDomain(d.id, {
              isRegistered: result.resolved,
              dnsResolved: result.resolved,
              resolvedIp: result.ip,
              mxRecords: result.mx as any,
            });
            results.push({ id: d.id, domain: d.permutedDomain, resolved: result.resolved, ip: result.ip });
          } catch {
            results.push({ id: d.id, domain: d.permutedDomain, resolved: false, ip: null });
          }
        }
        return results;
      }),

    // Update typosquat domain status (purchased, configured, etc.)
    updateTyposquatStatus: protectedProcedure
      .input(z.object({
        id: z.number(),
        status: z.enum(['discovered', 'recommended', 'purchased', 'configured', 'in_use', 'transferred', 'released']),
        registrar: z.string().optional(),
        annualCost: z.string().optional(),
        notes: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const { id, ...updates } = input;
        await db.updateTyposquatDomain(id, updates);
        await db.logActivity({
          userId: ctx.user.id,
          action: 'typosquat_status_updated',
          details: `Updated typosquat domain ID ${id} to status: ${input.status}`,
        });
        return { success: true };
      }),

    // Get OSINT findings for an engagement
    getFindings: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        return db.getOsintFindingsByEngagement(input.engagementId);
      }),

    // Auto-design campaign from OSINT findings using LLM
    autoCampaignDesign: protectedProcedure
      .input(z.object({ engagementId: z.number(), reconId: z.number() }))
      .mutation(async ({ input }) => {
        const { invokeLLM } = await import('../_core/llm');
        const recon = await db.getDomainReconById(input.reconId);
        const findings = await db.getOsintFindingsByRecon(input.reconId);

        if (!recon) throw new TRPCError({ code: 'NOT_FOUND', message: 'Recon not found' });

        const prompt = `You are a red team campaign designer for an MSP cybersecurity assessment. Based on the following OSINT reconnaissance data, design 3 phishing campaign strategies.

Target Domain: ${recon.domain}
Spoof Score: ${recon.spoofScore}/100 (${recon.spoofable ? 'SPOOFABLE' : 'NOT EASILY SPOOFABLE'})
SPF: ${recon.spfRecord || 'NONE'}
DMARC: ${recon.dmarcRecord || 'NONE'}
Subdomains Found: ${(recon.subdomains as any[])?.length || 0}
Key Findings:
${findings.map(f => `- [${f.severity?.toUpperCase()}] ${f.title}: ${f.description}`).join('\n')}

For each campaign, provide:
1. Campaign Name
2. Attack Vector (direct spoof, lookalike domain, or compromised subdomain)
3. Phishing Pretext (what the email pretends to be)
4. Recommended Template Type (password reset, IT helpdesk, invoice, etc.)
5. Target Audience (all employees, IT staff, executives, etc.)
6. Landing Page Strategy (credential harvest, malware download, etc.)
7. Recommended Sending Domain (spoof original or use typosquat)
8. Risk Level (low/medium/high detection risk)

Respond in JSON format as an array of 3 campaign objects.`;

        try {
          const response = await invokeLLM({ _caller: "osint-core", _priority: 'bulk',
            messages: [
              { role: 'system', content: 'You are an expert red team campaign designer. Always respond with valid JSON.' },
              { role: 'user', content: prompt },
            ],
            response_format: {
              type: 'json_schema',
              json_schema: {
                name: 'campaign_designs',
                strict: true,
                schema: {
                  type: 'object',
                  properties: {
                    campaigns: {
                      type: 'array',
                      items: {
                        type: 'object',
                        properties: {
                          name: { type: 'string' },
                          attackVector: { type: 'string' },
                          pretext: { type: 'string' },
                          templateType: { type: 'string' },
                          targetAudience: { type: 'string' },
                          landingPageStrategy: { type: 'string' },
                          sendingDomain: { type: 'string' },
                          riskLevel: { type: 'string' },
                        },
                        required: ['name', 'attackVector', 'pretext', 'templateType', 'targetAudience', 'landingPageStrategy', 'sendingDomain', 'riskLevel'],
                        additionalProperties: false,
                      },
                    },
                  },
                  required: ['campaigns'],
                  additionalProperties: false,
                },
              },
            },
          });

          const content = (response?.choices?.[0]?.message?.content as string) || '{"campaigns":[]}';
          return JSON.parse(content);
        } catch (err: any) {
          throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: 'Failed to generate campaign designs: ' + err.message });
        }
      }),
  });

export const whoisRouter = router({
    lookup: protectedProcedure
      .input(z.object({ domain: z.string().min(3) }))
      .query(async ({ input }) => {
        const { whoisLookup } = await import('../osint');
        return whoisLookup(input.domain);
      }),

    checkAvailability: protectedProcedure
      .input(z.object({ domain: z.string().min(3) }))
      .query(async ({ input }) => {
        const { checkDomainRegistration } = await import('../osint');
        return checkDomainRegistration(input.domain);
      }),

    batchCheck: protectedProcedure
      .input(z.object({ domains: z.array(z.string()).max(50) }))
      .mutation(async ({ input }) => {
        const { batchWhoisCheck } = await import('../osint');
        return batchWhoisCheck(input.domains);
      }),

    // Update a typosquat domain status after purchase/configuration
    updateTyposquatStatus: protectedProcedure
      .input(z.object({
        id: z.number(),
        status: z.enum(['discovered', 'recommended', 'purchased', 'configured', 'in_use', 'transferred', 'released']),
        registrar: z.string().optional(),
        annualCost: z.string().optional(),
        notes: z.string().optional(),
      }))
      .mutation(async ({ input }) => {
        const { id, ...updates } = input;
        await db.updateTyposquatDomain(id, updates as any);
        return { success: true };
      }),
  });

export const typosquatRouter = router({
    // Generate top-10 most effective typosquat variants for a target domain
    generateVariants: protectedProcedure
      .input(z.object({
        targetDomain: z.string().min(3),
        engagementId: z.number().optional(),
        maxVariants: z.number().min(5).max(30).default(10),
        checkAvailability: z.boolean().default(true),
      }))
      .mutation(async ({ input, ctx }) => {
        const { generateTyposquatVariants } = await import('../lib/typosquat');
        const result = await generateTyposquatVariants(input.targetDomain, {
          checkAvailability: input.checkAvailability,
          maxVariants: input.maxVariants,
          includeAllTechniques: false,
        });

        // If engagement provided, store recommended variants in DB
        if (input.engagementId) {
          const reconRecords = await db.getDomainReconByEngagement(input.engagementId);
          const reconId = reconRecords?.[0]?.id;
          if (reconId) {
            for (const v of result.recommendedVariants) {
              try {
                await db.bulkCreateTyposquatDomains([{
                  engagementId: input.engagementId,
                  reconId,
                  originalDomain: input.targetDomain,
                  permutedDomain: v.domain,
                  permutationType: v.technique,
                  isRegistered: v.available === false,
                  dnsResolved: v.available === false,
                  status: 'recommended',
                }]);
              } catch { /* duplicate */ }
            }
          }
        }

        await db.logActivity({
          userId: ctx.user.id,
          action: 'typosquat_variants_generated',
          details: `Generated ${result.recommendedVariants.length} typosquat variants for ${input.targetDomain}. Spoofability: ${result.spoofabilityScore}/100`,
        });

        return result;
      }),

    // Configure a purchased domain's DNS via DigitalOcean
    configureDns: protectedProcedure
      .input(z.object({
        domain: z.string().min(3),
        typosquatId: z.number(),
        mailServerIp: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const { configureDomainForEmail, addDomainToDO } = await import('../lib/typosquat');
        try {
          const config = await configureDomainForEmail(
            input.domain,
            input.mailServerIp || '137.184.7.224'
          );

          // Update typosquat record
          await db.updateTyposquatDomain(input.typosquatId, {
            status: 'configured',
            notes: `DNS configured via DigitalOcean. MX: mail.${input.domain}, SPF: ${config.spfRecord}`,
          } as any);

          await db.logActivity({
            userId: ctx.user.id,
            action: 'typosquat_dns_configured',
            details: `Configured DNS for ${input.domain} via DigitalOcean (MX, SPF, DMARC)`,
          });

          return {
            success: true,
            config,
            nameservers: ['ns1.digitalocean.com', 'ns2.digitalocean.com', 'ns3.digitalocean.com'],
            instructions: `Domain DNS configured. Update nameservers at your registrar to: ns1.digitalocean.com, ns2.digitalocean.com, ns3.digitalocean.com`,
          };
        } catch (err: any) {
          throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: `DNS configuration failed: ${err.message}` });
        }
      }),

    // Auto-create GoPhish sending profile for a purchased typosquat domain
    createSendingProfile: protectedProcedure
      .input(z.object({
        domain: z.string().min(3),
        typosquatId: z.number(),
        fromName: z.string().default('IT Support'),
        fromAddress: z.string().optional(),
        smtpHost: z.string().default('137.184.7.224'),
        smtpPort: z.number().default(25),
        engagementId: z.number().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const fromAddr = input.fromAddress || `noreply@${input.domain}`;
        const profileName = `AC3 - ${input.domain}`;

        // Create sending profile in GoPhish
        const profile = await fetchGophishAPI('/api/smtp/', 'POST', {
          name: profileName,
          from_address: `${input.fromName} <${fromAddr}>`,
          host: `${input.smtpHost}:${input.smtpPort}`,
          ignore_cert_errors: true,
          interface_type: 'SMTP',
        });

        // Update typosquat record to 'in_use'
        await db.updateTyposquatDomain(input.typosquatId, {
          status: 'in_use',
          notes: `GoPhish sending profile created: ${profileName} (ID: ${profile?.id || 'unknown'})`,
        } as any);

        await db.logActivity({
          userId: ctx.user.id,
          action: 'typosquat_gophish_profile_created',
          details: `Created GoPhish sending profile '${profileName}' for ${input.domain}`,
        });

        return {
          success: true,
          profileId: profile?.id,
          profileName,
          fromAddress: fromAddr,
          smtpHost: input.smtpHost,
          smtpPort: input.smtpPort,
        };
      }),

    // Full auto-integration: configure DNS + create GoPhish profile in one step
    autoIntegrate: protectedProcedure
      .input(z.object({
        domain: z.string().min(3),
        typosquatId: z.number(),
        engagementId: z.number().optional(),
        fromName: z.string().default('IT Support'),
        mailServerIp: z.string().default('137.184.7.224'),
      }))
      .mutation(async ({ input, ctx }) => {
        const steps: Array<{ step: string; status: 'success' | 'failed' | 'skipped'; detail: string }> = [];

        // Step 1: Configure DNS via DigitalOcean
        let dnsConfig: any = null;
        try {
          const { configureDomainForEmail } = await import('../lib/typosquat');
          dnsConfig = await configureDomainForEmail(input.domain, input.mailServerIp);
          steps.push({ step: 'Configure DNS', status: 'success', detail: `MX, SPF, DMARC records created for ${input.domain}` });
        } catch (err: any) {
          steps.push({ step: 'Configure DNS', status: 'failed', detail: err.message });
        }

        // Step 2: Create GoPhish sending profile
        let profileResult: any = null;
        try {
          const fromAddr = `noreply@${input.domain}`;
          const profileName = `AC3 - ${input.domain}`;
          profileResult = await fetchGophishAPI('/api/smtp/', 'POST', {
            name: profileName,
            from_address: `${input.fromName} <${fromAddr}>`,
            host: `${input.mailServerIp}:25`,
            ignore_cert_errors: true,
            interface_type: 'SMTP',
          });
          steps.push({ step: 'Create GoPhish Sending Profile', status: 'success', detail: `Profile '${profileName}' created (ID: ${profileResult?.id})` });
        } catch (err: any) {
          steps.push({ step: 'Create GoPhish Sending Profile', status: 'failed', detail: err.message });
        }

        // Step 3: Update typosquat record
        const allSuccess = steps.every(s => s.status === 'success');
        await db.updateTyposquatDomain(input.typosquatId, {
          status: allSuccess ? 'in_use' : 'purchased',
          notes: steps.map(s => `[${s.status.toUpperCase()}] ${s.step}: ${s.detail}`).join('\n'),
        } as any);
        steps.push({ step: 'Update Records', status: 'success', detail: `Typosquat domain status updated to ${allSuccess ? 'in_use' : 'purchased'}` });

        await db.logActivity({
          userId: ctx.user.id,
          action: 'typosquat_auto_integrated',
          details: `Auto-integrated ${input.domain}: ${steps.filter(s => s.status === 'success').length}/${steps.length} steps succeeded`,
        });

        return {
          success: allSuccess,
          domain: input.domain,
          steps,
          dnsConfig,
          gophishProfile: profileResult ? {
            id: profileResult.id,
            name: profileResult.name,
            fromAddress: profileResult.from_address,
          } : null,
          nameservers: dnsConfig ? ['ns1.digitalocean.com', 'ns2.digitalocean.com', 'ns3.digitalocean.com'] : null,
        };
      }),

    // Mark a domain as purchased (manual step after buying at registrar)
    markPurchased: protectedProcedure
      .input(z.object({
        typosquatId: z.number(),
        registrar: z.string().default('manual'),
        annualCost: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        await db.updateTyposquatDomain(input.typosquatId, {
          status: 'purchased',
          registrar: input.registrar,
          annualCost: input.annualCost,
          purchaseDate: new Date(),
        } as any);

        await db.logActivity({
          userId: ctx.user.id,
          action: 'typosquat_purchased',
          details: `Marked typosquat domain ID ${input.typosquatId} as purchased via ${input.registrar}`,
        });

        return { success: true };
      }),

    // List managed DigitalOcean domains
    listDODomains: protectedProcedure.query(async () => {
      try {
        const { listDODomains } = await import('../lib/typosquat');
        return await listDODomains();
      } catch (err: any) {
        return [];
      }
    }),

    // Get DNS records for a managed domain
    getDnsRecords: protectedProcedure
      .input(z.object({ domain: z.string().min(3) }))
      .query(async ({ input }) => {
        try {
          const { getDomainRecords } = await import('../lib/typosquat');
          return await getDomainRecords(input.domain);
        } catch (err: any) {
          return [];
        }
      }),
  });

export const monitorRouter = router({
    create: protectedProcedure
      .input(z.object({
        domain: z.string().min(3),
        engagementId: z.number().optional(),
        clientType: z.enum(['msp', 'enterprise', 'saas', 'paas', 'iaas', 'mixed_hosting', 'other']).default('enterprise'),
        intervalHours: z.number().min(1).max(720).default(24),
        notifyOnChange: z.boolean().default(true),
        notifyEmail: z.string().email().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        // Run initial baseline scan
        const { runFullRecon } = await import('../osint');
        const recon = await runFullRecon(input.domain);
        const baseline = {
          mxRecords: recon.dns.mxRecords,
          spfRecord: recon.dns.spfRecord,
          dmarcRecord: recon.dns.dmarcRecord,
          dkimFound: recon.dns.dkimFound,
          nsRecords: recon.dns.nsRecords,
          aRecords: recon.dns.aRecords,
          subdomainCount: recon.subdomains.length,
          spoofScore: recon.spoofability.score,
          scannedAt: new Date().toISOString(),
        };

        const id = await db.createOsintMonitor({
          domain: input.domain,
          engagementId: input.engagementId ?? null,
          clientType: input.clientType,
          intervalHours: input.intervalHours,
          notifyOnChange: input.notifyOnChange,
          notifyEmail: input.notifyEmail ?? null,
          baselineSnapshot: baseline,
          lastScanAt: new Date(),
          totalScans: 1,
          createdBy: ctx.user.id,
        });
        return { id, baseline };
      }),

    list: protectedProcedure.query(async () => {
      return db.getOsintMonitors();
    }),

    get: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        const monitor = await db.getOsintMonitorById(input.id);
        if (!monitor) throw new TRPCError({ code: 'NOT_FOUND', message: 'Monitor not found' });
        const changes = await db.getMonitorChanges(input.id);
        return { monitor, changes };
      }),

    update: protectedProcedure
      .input(z.object({
        id: z.number(),
        enabled: z.boolean().optional(),
        intervalHours: z.number().min(1).max(720).optional(),
        notifyOnChange: z.boolean().optional(),
        notifyEmail: z.string().email().optional().nullable(),
        clientType: z.enum(['msp', 'enterprise', 'saas', 'paas', 'iaas', 'mixed_hosting', 'other']).optional(),
      }))
      .mutation(async ({ input }) => {
        const { id, ...updates } = input;
        await db.updateOsintMonitor(id, updates as any);
        return { success: true };
      }),

    delete: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        await db.deleteOsintMonitor(input.id);
        return { success: true };
      }),

    // Run a scan now (compare against baseline)
    scanNow: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        const monitor = await db.getOsintMonitorById(input.id);
        if (!monitor) throw new TRPCError({ code: 'NOT_FOUND', message: 'Monitor not found' });

        const { runFullRecon, detectDomainChanges } = await import('../osint');
        const recon = await runFullRecon(monitor.domain);

        const currentSnapshot = {
          mxRecords: recon.dns.mxRecords,
          spfRecord: recon.dns.spfRecord,
          dmarcRecord: recon.dns.dmarcRecord,
          dkimFound: recon.dns.dkimFound,
          nsRecords: recon.dns.nsRecords,
          aRecords: recon.dns.aRecords,
          subdomainCount: recon.subdomains.length,
          spoofScore: recon.spoofability.score,
          scannedAt: new Date().toISOString(),
        };

        // Detect changes against baseline using the previous recon data
        const baseline = (monitor.baselineSnapshot as any) || {};
        const changeReport = await detectDomainChanges(monitor.domain, {
          spfRecord: baseline.spfRecord,
          dmarcRecord: baseline.dmarcRecord,
          mxRecords: baseline.mxRecords,
          nsRecords: baseline.nsRecords,
          aRecords: baseline.aRecords,
          subdomains: baseline.subdomains,
        });
        const changes = changeReport.changes;

        // Store changes in DB
        if (changes.length > 0) {
          await db.bulkCreateMonitorChanges(
            changes.map((c) => ({
              monitorId: monitor.id,
              domain: monitor.domain,
              changeType: c.type,
              severity: c.severity,
              previousValue: c.previousValue,
              currentValue: c.currentValue,
              description: c.description,
            }))
          );

          // Notify owner if enabled
          if (monitor.notifyOnChange) {
            try {
              const { notifyOwner } = await import('../_core/notification');
              await notifyOwner({
                title: `OSINT Alert: ${changes.length} change(s) detected on ${monitor.domain}`,
                content: changes.map((c) => `[${c.severity.toUpperCase()}] ${c.description}`).join('\n'),
              });
            } catch (e) { /* notification failure is non-fatal */ }
          }
        }

        // Update monitor
        await db.updateOsintMonitor(monitor.id, {
          lastScanAt: new Date(),
          totalScans: (monitor.totalScans || 0) + 1,
          totalChangesDetected: (monitor.totalChangesDetected || 0) + changes.length,
          baselineSnapshot: currentSnapshot,
          ...(changes.length > 0 ? { lastChangeDetectedAt: new Date() } : {}),
        });

        return { changes, currentSnapshot };
      }),

    // Get unacknowledged changes across all monitors
    alerts: protectedProcedure.query(async () => {
      return db.getUnacknowledgedChanges();
    }),

    acknowledgeChange: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input, ctx }) => {
        await db.acknowledgeChange(input.id, ctx.user.id);
        return { success: true };
      }),

    // ─── Automated Scan Scheduler ──────────────────────────────────────
    schedulerStatus: protectedProcedure.query(async () => {
      const { getSchedulerStatus } = await import('../lib/scan-scheduler');
      const status = getSchedulerStatus();
      const monitors = await db.getEnabledMonitors();
      return {
        ...status,
        activeMonitors: monitors.length,
        monitors: monitors.map(m => ({
          id: m.id,
          domain: m.domain,
          intervalHours: m.intervalHours,
          lastScanAt: m.lastScanAt,
          totalScans: m.totalScans,
          totalChangesDetected: m.totalChangesDetected,
          nextScanDue: m.lastScanAt
            ? new Date(new Date(m.lastScanAt).getTime() + (m.intervalHours || 24) * 60 * 60 * 1000).toISOString()
            : 'now',
          isDue: !m.lastScanAt || Date.now() >= new Date(m.lastScanAt).getTime() + (m.intervalHours || 24) * 60 * 60 * 1000,
        })),
      };
    }),

    forceSchedulerCheck: protectedProcedure.mutation(async () => {
      const { forceSchedulerCheck } = await import('../lib/scan-scheduler');
      return forceSchedulerCheck();
    }),
  });
