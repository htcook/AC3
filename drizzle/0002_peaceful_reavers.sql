CREATE TABLE `campaign_abilities` (
	`id` int AUTO_INCREMENT NOT NULL,
	`campaignId` int NOT NULL,
	`abilityId` varchar(255) NOT NULL,
	`abilityName` varchar(255) NOT NULL,
	`technique` varchar(32),
	`tactic` varchar(64),
	`description` text,
	`executionOrder` int DEFAULT 0,
	`status` enum('pending','running','completed','failed','skipped') NOT NULL DEFAULT 'pending',
	`executedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `campaign_abilities_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `campaign_agents` (
	`id` int AUTO_INCREMENT NOT NULL,
	`campaignId` int NOT NULL,
	`agentName` varchar(255) NOT NULL,
	`agentPaw` varchar(64),
	`platform` varchar(64),
	`hostname` varchar(255),
	`status` enum('pending','deployed','active','inactive') NOT NULL DEFAULT 'pending',
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `campaign_agents_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `campaigns` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(255) NOT NULL,
	`description` text,
	`targetEnvironment` varchar(255),
	`adversaryId` varchar(255),
	`adversaryName` varchar(255),
	`status` enum('draft','ready','active','paused','completed') NOT NULL DEFAULT 'draft',
	`serverId` int,
	`createdBy` int,
	`startDate` timestamp,
	`endDate` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `campaigns_id` PRIMARY KEY(`id`)
);
