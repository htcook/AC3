import { relations } from "drizzle-orm/relations";
import { agentDeployments, agentAuditLog, agentTasks, engagements, campaignEngagements, domainIntelScans, discoveredAssets, domainRecon, engagementReports, evidenceItems, evidenceChainOfCustody, osintFindings, serverConfigs, serverCredentials } from "./schema";

export const agentAuditLogRelations = relations(agentAuditLog, ({one}) => ({
	agentDeployment: one(agentDeployments, {
		fields: [agentAuditLog.agentId],
		references: [agentDeployments.id]
	}),
}));

export const agentDeploymentsRelations = relations(agentDeployments, ({many}) => ({
	agentAuditLogs: many(agentAuditLog),
	agentTasks: many(agentTasks),
}));

export const agentTasksRelations = relations(agentTasks, ({one}) => ({
	agentDeployment: one(agentDeployments, {
		fields: [agentTasks.agentId],
		references: [agentDeployments.id]
	}),
}));

export const campaignEngagementsRelations = relations(campaignEngagements, ({one}) => ({
	engagement: one(engagements, {
		fields: [campaignEngagements.engagementId],
		references: [engagements.id]
	}),
}));

export const engagementsRelations = relations(engagements, ({many}) => ({
	campaignEngagements: many(campaignEngagements),
	domainRecons: many(domainRecon),
	engagementReports: many(engagementReports),
	osintFindings: many(osintFindings),
}));

export const discoveredAssetsRelations = relations(discoveredAssets, ({one}) => ({
	domainIntelScan: one(domainIntelScans, {
		fields: [discoveredAssets.scanId],
		references: [domainIntelScans.id]
	}),
}));

export const domainIntelScansRelations = relations(domainIntelScans, ({many}) => ({
	discoveredAssets: many(discoveredAssets),
}));

export const domainReconRelations = relations(domainRecon, ({one}) => ({
	engagement: one(engagements, {
		fields: [domainRecon.engagementId],
		references: [engagements.id]
	}),
}));

export const engagementReportsRelations = relations(engagementReports, ({one}) => ({
	engagement: one(engagements, {
		fields: [engagementReports.engagementId],
		references: [engagements.id]
	}),
}));

export const evidenceChainOfCustodyRelations = relations(evidenceChainOfCustody, ({one}) => ({
	evidenceItem: one(evidenceItems, {
		fields: [evidenceChainOfCustody.evidenceId],
		references: [evidenceItems.evidenceId]
	}),
}));

export const evidenceItemsRelations = relations(evidenceItems, ({many}) => ({
	evidenceChainOfCustodies: many(evidenceChainOfCustody),
}));

export const osintFindingsRelations = relations(osintFindings, ({one}) => ({
	engagement: one(engagements, {
		fields: [osintFindings.engagementId],
		references: [engagements.id]
	}),
}));

export const serverCredentialsRelations = relations(serverCredentials, ({one}) => ({
	serverConfig: one(serverConfigs, {
		fields: [serverCredentials.serverId],
		references: [serverConfigs.id]
	}),
}));

export const serverConfigsRelations = relations(serverConfigs, ({many}) => ({
	serverCredentials: many(serverCredentials),
}));