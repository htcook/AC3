CREATE TABLE `guardrail_violations` (
	`id` int AUTO_INCREMENT NOT NULL,
	`violationId` varchar(128) NOT NULL,
	`guardrailContext` varchar(64) NOT NULL,
	`triggerPattern` varchar(256),
	`guardrailAction` enum('blocked','sanitized','warned') NOT NULL,
	`guardrailReason` text NOT NULL,
	`promptSnippet` text,
	`guardrailCreatedAt` bigint NOT NULL,
	CONSTRAINT `guardrail_violations_id` PRIMARY KEY(`id`),
	CONSTRAINT `guardrail_violations_violationId_unique` UNIQUE(`violationId`)
);
--> statement-breakpoint
CREATE TABLE `scan_observations` (
	`id` int AUTO_INCREMENT NOT NULL,
	`observationId` varchar(128) NOT NULL,
	`assetId` varchar(128) NOT NULL,
	`assetHost` varchar(512) NOT NULL,
	`assetPort` int NOT NULL,
	`assetProtocol` varchar(32),
	`assetTags` json,
	`scannerName` varchar(64) NOT NULL,
	`scannerVersion` varchar(64),
	`scannerAdapter` varchar(64) NOT NULL,
	`scannerMode` enum('passive','active-low','active-standard','active-aggressive') DEFAULT 'passive',
	`observationType` enum('service_banner','tls','http_headers','dns','vulnerability_finding','misconfiguration','exposure_surface','cloud_fingerprint') NOT NULL,
	`severity` enum('info','low','medium','high','critical') DEFAULT 'info',
	`confidence` double NOT NULL,
	`evidenceSummary` text NOT NULL,
	`evidenceTemplateId` varchar(256),
	`evidenceCve` varchar(32),
	`evidenceCvss` double,
	`evidenceRequestFingerprint` varchar(128),
	`evidenceResponseFingerprint` varchar(128),
	`evidenceArtifacts` json,
	`scanRunId` varchar(128),
	`policyProfile` varchar(64),
	`rateLimitBucket` varchar(64),
	`notes` text,
	`rawDataHash` varchar(128),
	`observedAt` bigint NOT NULL,
	`ingestedAt` bigint NOT NULL,
	CONSTRAINT `scan_observations_id` PRIMARY KEY(`id`),
	CONSTRAINT `scan_observations_observationId_unique` UNIQUE(`observationId`)
);
--> statement-breakpoint
CREATE TABLE `scan_policies` (
	`id` int AUTO_INCREMENT NOT NULL,
	`profileId` varchar(64) NOT NULL,
	`policyName` varchar(128) NOT NULL,
	`policyDescription` text,
	`isActive` boolean NOT NULL DEFAULT false,
	`profileData` json NOT NULL,
	`escalationRules` json,
	`policyCreatedAt` bigint NOT NULL,
	`policyUpdatedAt` bigint NOT NULL,
	CONSTRAINT `scan_policies_id` PRIMARY KEY(`id`),
	CONSTRAINT `scan_policies_profileId_unique` UNIQUE(`profileId`)
);
--> statement-breakpoint
CREATE TABLE `scan_risk_cards` (
	`id` int AUTO_INCREMENT NOT NULL,
	`riskId` varchar(128) NOT NULL,
	`assetId` varchar(128) NOT NULL,
	`finalScore` double NOT NULL,
	`componentCvss` double NOT NULL,
	`componentCarver` double NOT NULL,
	`componentBia` double NOT NULL,
	`confidenceWeight` double NOT NULL,
	`summary` text NOT NULL,
	`whyItMatters` text,
	`evidence` json,
	`recommendations` json NOT NULL,
	`riskCardCreatedAt` bigint NOT NULL,
	CONSTRAINT `scan_risk_cards_id` PRIMARY KEY(`id`),
	CONSTRAINT `scan_risk_cards_riskId_unique` UNIQUE(`riskId`)
);
--> statement-breakpoint
CREATE TABLE `scan_signals` (
	`id` int AUTO_INCREMENT NOT NULL,
	`signalId` varchar(128) NOT NULL,
	`assetId` varchar(128) NOT NULL,
	`signalType` enum('vulnerability','exposure','weak_signal','intel','hygiene','misconfiguration') NOT NULL,
	`category` varchar(128) NOT NULL,
	`signalSeverity` enum('info','low','medium','high','critical') DEFAULT 'info',
	`signalConfidence` double NOT NULL,
	`rationale` text NOT NULL,
	`sourceObservations` json NOT NULL,
	`enrichmentCvss` double,
	`enrichmentCve` varchar(32),
	`enrichmentReferences` json,
	`signalCreatedAt` bigint NOT NULL,
	CONSTRAINT `scan_signals_id` PRIMARY KEY(`id`),
	CONSTRAINT `scan_signals_signalId_unique` UNIQUE(`signalId`)
);
