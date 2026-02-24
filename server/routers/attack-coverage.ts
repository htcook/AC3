/**
 * ATT&CK Coverage Router
 * 
 * Unified ATT&CK coverage heatmap that aggregates technique coverage
 * from all integrated tools: Caldera, Atomic Red Team, ZAP, Nuclei,
 * Sliver C2, Metasploit, and GoPhish.
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";

// MITRE ATT&CK Enterprise tactics in kill chain order
const TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance', shortName: 'recon' },
  { id: 'TA0042', name: 'Resource Development', shortName: 'resource-dev' },
  { id: 'TA0001', name: 'Initial Access', shortName: 'initial-access' },
  { id: 'TA0002', name: 'Execution', shortName: 'execution' },
  { id: 'TA0003', name: 'Persistence', shortName: 'persistence' },
  { id: 'TA0004', name: 'Privilege Escalation', shortName: 'priv-esc' },
  { id: 'TA0005', name: 'Defense Evasion', shortName: 'defense-evasion' },
  { id: 'TA0006', name: 'Credential Access', shortName: 'cred-access' },
  { id: 'TA0007', name: 'Discovery', shortName: 'discovery' },
  { id: 'TA0008', name: 'Lateral Movement', shortName: 'lateral-movement' },
  { id: 'TA0009', name: 'Collection', shortName: 'collection' },
  { id: 'TA0011', name: 'Command and Control', shortName: 'c2' },
  { id: 'TA0010', name: 'Exfiltration', shortName: 'exfiltration' },
  { id: 'TA0040', name: 'Impact', shortName: 'impact' },
];

// Tool-to-tactic coverage mapping
const TOOL_COVERAGE: Record<string, {
  tool: string;
  label: string;
  tactics: string[];
  techniqueCount: number;
  color: string;
}> = {
  caldera: {
    tool: 'caldera',
    label: 'Adversary Emulation Platform',
    tactics: ['TA0043', 'TA0001', 'TA0002', 'TA0003', 'TA0004', 'TA0005', 'TA0006', 'TA0007', 'TA0008', 'TA0009', 'TA0011', 'TA0010', 'TA0040'],
    techniqueCount: 180,
    color: '#ef4444',
  },
  atomic_red_team: {
    tool: 'atomic_red_team',
    label: 'Adversary Validation Tests',
    tactics: ['TA0043', 'TA0042', 'TA0001', 'TA0002', 'TA0003', 'TA0004', 'TA0005', 'TA0006', 'TA0007', 'TA0008', 'TA0009', 'TA0011', 'TA0010', 'TA0040'],
    techniqueCount: 1400,
    color: '#f97316',
  },
  zap: {
    tool: 'zap',
    label: 'DAST Scanner',
    tactics: ['TA0043', 'TA0001', 'TA0002', 'TA0007'],
    techniqueCount: 45,
    color: '#3b82f6',
  },
  nuclei: {
    tool: 'nuclei',
    label: 'Template Scanner',
    tactics: ['TA0043', 'TA0001', 'TA0002', 'TA0007', 'TA0005'],
    techniqueCount: 120,
    color: '#8b5cf6',
  },
  sliver: {
    tool: 'sliver',
    label: 'C2 Framework',
    tactics: ['TA0001', 'TA0002', 'TA0003', 'TA0004', 'TA0005', 'TA0006', 'TA0007', 'TA0008', 'TA0009', 'TA0011', 'TA0010'],
    techniqueCount: 85,
    color: '#10b981',
  },
  metasploit: {
    tool: 'metasploit',
    label: 'Exploit Framework',
    tactics: ['TA0001', 'TA0002', 'TA0003', 'TA0004', 'TA0005', 'TA0006', 'TA0007', 'TA0008', 'TA0009', 'TA0011', 'TA0010', 'TA0040'],
    techniqueCount: 200,
    color: '#06b6d4',
  },
  gophish: {
    tool: 'gophish',
    label: 'Phishing Engine',
    tactics: ['TA0043', 'TA0042', 'TA0001'],
    techniqueCount: 15,
    color: '#ec4899',
  },
};

export const attackCoverageRouter = router({
  /**
   * Get the full ATT&CK coverage heatmap data.
   */
  getHeatmap: protectedProcedure.query(() => {
    const heatmap = TACTICS.map(tactic => {
      const coveringTools = Object.values(TOOL_COVERAGE)
        .filter(t => t.tactics.includes(tactic.id));

      return {
        tacticId: tactic.id,
        tacticName: tactic.name,
        shortName: tactic.shortName,
        toolsCovering: coveringTools.length,
        tools: coveringTools.map(t => ({
          tool: t.tool,
          label: t.label,
          color: t.color,
        })),
        coverageLevel: coveringTools.length >= 5 ? 'high' :
                        coveringTools.length >= 3 ? 'medium' :
                        coveringTools.length >= 1 ? 'low' : 'none',
      };
    });

    return {
      tactics: heatmap,
      tools: Object.values(TOOL_COVERAGE),
      summary: {
        totalTactics: TACTICS.length,
        coveredTactics: heatmap.filter(h => h.toolsCovering > 0).length,
        totalTechniques: Object.values(TOOL_COVERAGE).reduce((sum, t) => sum + t.techniqueCount, 0),
        averageToolsPerTactic: Math.round(heatmap.reduce((sum, h) => sum + h.toolsCovering, 0) / TACTICS.length * 10) / 10,
      },
    };
  }),

  /**
   * Get coverage for a specific tool.
   */
  getToolCoverage: protectedProcedure
    .input(z.object({ tool: z.string() }))
    .query(({ input }) => {
      const coverage = TOOL_COVERAGE[input.tool];
      if (!coverage) throw new Error(`Tool ${input.tool} not found`);

      return {
        ...coverage,
        tacticDetails: coverage.tactics.map(tid => {
          const tactic = TACTICS.find(t => t.id === tid);
          return { id: tid, name: tactic?.name || 'Unknown', shortName: tactic?.shortName || 'unknown' };
        }),
      };
    }),

  /**
   * Get coverage gaps — tactics with low or no coverage.
   */
  getCoverageGaps: protectedProcedure.query(() => {
    const gaps = TACTICS.map(tactic => {
      const coveringTools = Object.values(TOOL_COVERAGE)
        .filter(t => t.tactics.includes(tactic.id));
      return {
        tacticId: tactic.id,
        tacticName: tactic.name,
        toolsCovering: coveringTools.length,
        tools: coveringTools.map(t => t.tool),
        gap: coveringTools.length < 3,
        recommendation: coveringTools.length === 0
          ? 'No tools cover this tactic — consider adding dedicated tooling'
          : coveringTools.length < 3
          ? `Only ${coveringTools.length} tool(s) cover this tactic — consider additional validation`
          : 'Adequate coverage',
      };
    }).filter(g => g.gap);

    return gaps;
  }),

  /**
   * Get tactic list for reference.
   */
  getTactics: protectedProcedure.query(() => TACTICS),
});
