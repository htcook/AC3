CREATE TABLE `threat_group_events` (
	`id` int AUTO_INCREMENT NOT NULL,
	`tgeActorId` varchar(128) NOT NULL,
	`eventType` enum('attack','campaign','infrastructure_change','malware_update','law_enforcement','affiliate_change','data_leak','ttp_evolution','group_merger','group_rebrand','new_tool','zero_day') NOT NULL,
	`tgeTitle` varchar(512) NOT NULL,
	`tgeDescription` text,
	`tgeSeverity` enum('critical','high','medium','low','info') DEFAULT 'medium',
	`tgeVictimName` varchar(512),
	`tgeVictimSector` varchar(128),
	`tgeVictimCountry` varchar(128),
	`tgeMitreTechniques` json,
	`tgeIocs` json,
	`tgeSource` varchar(255),
	`tgeSourceUrl` varchar(1024),
	`tgeConfidence` int DEFAULT 75,
	`eventDate` timestamp,
	`discoveredAt` timestamp NOT NULL DEFAULT (now()),
	`tgeCreatedAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `threat_group_events_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `threat_intel_updates` (
	`id` int AUTO_INCREMENT NOT NULL,
	`sweepType` enum('scheduled','manual','triggered') DEFAULT 'manual',
	`tiuStatus` enum('running','completed','failed') DEFAULT 'running',
	`groupsScanned` int DEFAULT 0,
	`updatesApplied` int DEFAULT 0,
	`newEventsFound` int DEFAULT 0,
	`newIocsFound` int DEFAULT 0,
	`newTtpsFound` int DEFAULT 0,
	`tiuSummary` text,
	`tiuDetails` json,
	`tiuErrors` json,
	`tiuStartedAt` timestamp NOT NULL DEFAULT (now()),
	`tiuCompletedAt` timestamp,
	`durationMs` int,
	CONSTRAINT `threat_intel_updates_id` PRIMARY KEY(`id`)
);
