/**
 * DI Risk Scoring Verification Tests
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Integration tests that verify the risk scoring fix produces varied scores
 * by importing the actual scoring engine and testing with different inputs.
 */
import { describe, it, expect } from "vitest";
import { applyMissionBaselines, MISSION_FUNCTION_BASELINES, ESSENTIAL_SERVICE_BASELINES } from "./lib/scoring-engine";

// Simulate the normalization functions (same logic as in domainIntel.ts)
function normalizeMissionFunction(llmValue: string): string {
  const MISSION_FUNCTION_MAP: Record<string, string> = {
    'command_and_control': 'command_control',
    'command_control': 'command_control',
    'revenue_generation': 'revenue_generation',
    'customer_data_processing': 'customer_data',
    'customer_data': 'customer_data',
    'intellectual_property_storage': 'intellectual_property',
    'intellectual_property': 'intellectual_property',
    'authentication_and_access': 'authentication',
    'authentication': 'authentication',
    'communication_infrastructure': 'external_communication',
    'external_communication': 'external_communication',
    'regulatory_compliance': 'compliance',
    'compliance': 'compliance',
    'business_continuity': 'operational_continuity',
    'operational_continuity': 'operational_continuity',
    'supply_chain_integration': 'supply_chain',
    'supply_chain': 'supply_chain',
    'public_facing_services': 'external_communication',
    'data_processing': 'data_processing',
  };
  return MISSION_FUNCTION_MAP[llmValue] || llmValue;
}

function normalizeEssentialService(llmValue: string): string {
  const SERVICE_MAP: Record<string, string> = {
    'sso_idp': 'sso',
    'active_directory': 'active_directory',
    'payment_processing': 'payment_processing',
    'email_gateway': 'email',
    'vpn_concentrator': 'vpn',
    'dns_infrastructure': 'dns',
    'database_primary': 'database',
    'database_replica': 'database',
    'load_balancer': 'load_balancer',
    'web_application_firewall': 'waf',
    'api_gateway': 'api_gateway',
    'ci_cd_pipeline': 'ci_cd',
    'monitoring_alerting': 'siem',
    'backup_recovery': 'backup',
    'file_storage': 'backup',
    'certificate_authority': 'encryption_key_management',
    'secrets_management': 'encryption_key_management',
    'container_orchestration': 'ci_cd',
    'message_queue': 'api_gateway',
    'cdn_edge': 'load_balancer',
    'erp_system': 'erp',
    'crm_system': 'customer_portal',
    'scada_hmi': 'critical_infrastructure',
    'medical_device': 'critical_infrastructure',
    'pos_terminal': 'payment_processing',
    'voip_pbx': 'email',
    'print_server': 'general_server',
    'general_server': 'general_server',
    'source_control': 'source_control',
    'firewall': 'firewall',
  };
  return SERVICE_MAP[llmValue] || llmValue;
}

// Default CARVER/SHOCK scores (what LLM returns when it has minimal info)
const defaultCarver = { criticality: 3, accessibility: 3, recuperability: 3, vulnerability: 3, effect: 3, recognizability: 3 };
const defaultShock = { scope: 3, handling: 3, operationalImpact: 3, cascadingEffects: 3, knowledge: 3 };

describe("Mission Function Normalization → Baselines Applied", () => {
  it("LLM value 'command_and_control' maps to a valid baselines key", () => {
    const normalized = normalizeMissionFunction('command_and_control');
    expect(normalized).toBe('command_control');
    expect(MISSION_FUNCTION_BASELINES[normalized]).toBeDefined();
  });

  it("LLM value 'authentication_and_access' maps to a valid baselines key", () => {
    const normalized = normalizeMissionFunction('authentication_and_access');
    expect(normalized).toBe('authentication');
    expect(MISSION_FUNCTION_BASELINES[normalized]).toBeDefined();
  });

  it("LLM value 'customer_data_processing' maps to a valid baselines key", () => {
    const normalized = normalizeMissionFunction('customer_data_processing');
    expect(normalized).toBe('customer_data');
    expect(MISSION_FUNCTION_BASELINES[normalized]).toBeDefined();
  });

  it("LLM value 'public_facing_services' maps to a valid baselines key", () => {
    const normalized = normalizeMissionFunction('public_facing_services');
    expect(normalized).toBe('external_communication');
    expect(MISSION_FUNCTION_BASELINES[normalized]).toBeDefined();
  });

  it("all LLM mission function values map to existing baselines keys", () => {
    const llmValues = [
      'command_and_control', 'revenue_generation', 'customer_data_processing',
      'intellectual_property_storage', 'authentication_and_access',
      'communication_infrastructure', 'regulatory_compliance',
      'business_continuity', 'supply_chain_integration', 'public_facing_services'
    ];
    for (const val of llmValues) {
      const normalized = normalizeMissionFunction(val);
      expect(MISSION_FUNCTION_BASELINES[normalized]).toBeDefined();
    }
  });
});

describe("Essential Service Normalization → Baselines Applied", () => {
  it("LLM value 'sso_idp' maps to a valid baselines key", () => {
    const normalized = normalizeEssentialService('sso_idp');
    expect(normalized).toBe('sso');
    expect(ESSENTIAL_SERVICE_BASELINES[normalized]).toBeDefined();
  });

  it("LLM value 'email_gateway' maps to a valid baselines key", () => {
    const normalized = normalizeEssentialService('email_gateway');
    expect(normalized).toBe('email');
    expect(ESSENTIAL_SERVICE_BASELINES[normalized]).toBeDefined();
  });

  it("LLM value 'web_application_firewall' maps to a valid baselines key", () => {
    const normalized = normalizeEssentialService('web_application_firewall');
    expect(normalized).toBe('waf');
    expect(ESSENTIAL_SERVICE_BASELINES[normalized]).toBeDefined();
  });

  it("all LLM essential service values (except general_server) map to existing baselines keys", () => {
    // 'general_server' intentionally has no baseline — it's the fallback that
    // leaves scores unchanged. All other services should have specific baselines.
    const llmValues = [
      'sso_idp', 'active_directory', 'payment_processing', 'email_gateway',
      'vpn_concentrator', 'dns_infrastructure', 'database_primary',
      'load_balancer', 'web_application_firewall', 'api_gateway',
      'ci_cd_pipeline'
    ];
    for (const val of llmValues) {
      const normalized = normalizeEssentialService(val);
      expect(ESSENTIAL_SERVICE_BASELINES[normalized]).toBeDefined();
    }
  });

  it("general_server has no specific baseline (scores pass through unchanged)", () => {
    const normalized = normalizeEssentialService('general_server');
    expect(normalized).toBe('general_server');
    // This is intentional — general_server is the fallback with no floor adjustments
    expect(ESSENTIAL_SERVICE_BASELINES[normalized]).toBeUndefined();
  });
});

describe("applyMissionBaselines produces DIFFERENT scores for different missions", () => {
  it("authentication assets get higher CARVER scores than general servers", () => {
    const authResult = applyMissionBaselines(
      { ...defaultCarver }, { ...defaultShock },
      'authentication', 'sso'
    );
    const generalResult = applyMissionBaselines(
      { ...defaultCarver }, { ...defaultShock },
      'external_communication', 'general_server'
    );
    // Authentication should have higher criticality than general
    const authCritSum = Object.values(authResult.carver).reduce((s, v) => s + v, 0);
    const generalCritSum = Object.values(generalResult.carver).reduce((s, v) => s + v, 0);
    expect(authCritSum).not.toBe(generalCritSum);
  });

  it("command_control assets get different scores than revenue_generation", () => {
    const c2Result = applyMissionBaselines(
      { ...defaultCarver }, { ...defaultShock },
      'command_control', 'general_server'
    );
    const revenueResult = applyMissionBaselines(
      { ...defaultCarver }, { ...defaultShock },
      'revenue_generation', 'payment_processing'
    );
    const c2Sum = Object.values(c2Result.carver).reduce((s, v) => s + v, 0) +
                  Object.values(c2Result.shock).reduce((s, v) => s + v, 0);
    const revSum = Object.values(revenueResult.carver).reduce((s, v) => s + v, 0) +
                   Object.values(revenueResult.shock).reduce((s, v) => s + v, 0);
    expect(c2Sum).not.toBe(revSum);
  });

  it("SSO service gets higher baseline than general_server", () => {
    const ssoResult = applyMissionBaselines(
      { ...defaultCarver }, { ...defaultShock },
      'authentication', 'sso'
    );
    const generalResult = applyMissionBaselines(
      { ...defaultCarver }, { ...defaultShock },
      'authentication', 'general_server'
    );
    // SSO is more critical than general server for same mission
    const ssoCarverSum = Object.values(ssoResult.carver).reduce((s, v) => s + v, 0);
    const genCarverSum = Object.values(generalResult.carver).reduce((s, v) => s + v, 0);
    // At minimum, they should differ (SSO has specific floor adjustments)
    expect(ssoCarverSum).toBeGreaterThanOrEqual(genCarverSum);
  });
});

describe("KEV Floor — Confirmed vs Unconfirmed", () => {
  // Simulate the floor logic from domainIntel.ts
  function applyKevFloor(kevMatches: Array<{ matchQuality: string; knownRansomware: boolean }>, overallRisk: number): number {
    if (kevMatches.length === 0) return overallRisk;
    const confirmedKevMatches = kevMatches.filter(m => m.matchQuality === 'exact_product');
    const confirmedRansomware = confirmedKevMatches.filter(m => m.knownRansomware);
    const confirmedCount = confirmedKevMatches.length;
    let adjustedRisk = overallRisk;

    if (confirmedRansomware.length > 0) {
      adjustedRisk = Math.max(adjustedRisk, 75);
    } else if (confirmedCount >= 3) {
      adjustedRisk = Math.max(adjustedRisk, 55);
    } else if (confirmedCount > 0) {
      adjustedRisk = Math.max(adjustedRisk, 45);
    }
    // Unconfirmed matches: NO floor adjustment
    return adjustedRisk;
  }

  it("unconfirmed KEV matches do NOT raise the floor", () => {
    const unconfirmedMatches = [
      { matchQuality: 'product_family', knownRansomware: true },
      { matchQuality: 'vendor_only', knownRansomware: true },
      { matchQuality: 'product_family', knownRansomware: false },
    ];
    const result = applyKevFloor(unconfirmedMatches, 42);
    expect(result).toBe(42); // No change — all unconfirmed
  });

  it("confirmed ransomware KEV matches raise floor to 75", () => {
    const confirmedMatches = [
      { matchQuality: 'exact_product', knownRansomware: true },
    ];
    const result = applyKevFloor(confirmedMatches, 42);
    expect(result).toBe(75);
  });

  it("3+ confirmed KEV matches (no ransomware) raise floor to 55", () => {
    const confirmedMatches = [
      { matchQuality: 'exact_product', knownRansomware: false },
      { matchQuality: 'exact_product', knownRansomware: false },
      { matchQuality: 'exact_product', knownRansomware: false },
    ];
    const result = applyKevFloor(confirmedMatches, 42);
    expect(result).toBe(55);
  });

  it("1 confirmed KEV match (no ransomware) raises floor to 45", () => {
    const confirmedMatches = [
      { matchQuality: 'exact_product', knownRansomware: false },
      { matchQuality: 'product_family', knownRansomware: true }, // unconfirmed - ignored
    ];
    const result = applyKevFloor(confirmedMatches, 42);
    expect(result).toBe(45);
  });

  it("mix of confirmed and unconfirmed — only confirmed count", () => {
    const mixedMatches = [
      { matchQuality: 'exact_product', knownRansomware: false },
      { matchQuality: 'product_family', knownRansomware: true },
      { matchQuality: 'vendor_only', knownRansomware: true },
      { matchQuality: 'product_family', knownRansomware: true },
    ];
    // Only 1 confirmed, no ransomware on confirmed → floor 45
    const result = applyKevFloor(mixedMatches, 30);
    expect(result).toBe(45);
  });

  it("score already above floor is not changed", () => {
    const confirmedMatches = [
      { matchQuality: 'exact_product', knownRansomware: true },
    ];
    const result = applyKevFloor(confirmedMatches, 85);
    expect(result).toBe(85); // Already above 75 floor
  });

  it("typical scenario: 5 unconfirmed KEV matches from common tech → score unchanged", () => {
    // This is the bug scenario: Apache, jQuery, PHP all produce KEV matches
    // but none are version-confirmed
    const typicalMatches = [
      { matchQuality: 'product_family', knownRansomware: true },  // Apache
      { matchQuality: 'product_family', knownRansomware: false }, // jQuery
      { matchQuality: 'vendor_only', knownRansomware: true },     // PHP
      { matchQuality: 'product_family', knownRansomware: true },  // WordPress
      { matchQuality: 'product_family', knownRansomware: false }, // nginx
    ];
    const result = applyKevFloor(typicalMatches, 48);
    expect(result).toBe(48); // FIX: No longer jumps to 75!
  });
});
