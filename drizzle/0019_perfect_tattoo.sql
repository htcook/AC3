CREATE TABLE `archetype_actor_mappings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`archetypeId` int NOT NULL,
	`actorId` varchar(128) NOT NULL,
	`actorTechniques` json,
	`actorAbilities` json,
	`confidence` int DEFAULT 50,
	`evidence` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `archetype_actor_mappings_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `campaign_archetypes` (
	`id` int AUTO_INCREMENT NOT NULL,
	`slug` varchar(128) NOT NULL,
	`name` varchar(255) NOT NULL,
	`archetypeCategory` enum('saas_oauth_compromise','token_abuse','cloud_lateral_movement','supply_chain','credential_harvesting','ransomware_deployment','data_exfiltration','persistence_implant','custom') NOT NULL,
	`description` text,
	`killChainPhases` json,
	`defaultTechniques` json,
	`defaultAbilities` json,
	`targetPlatforms` json,
	`targetServices` json,
	`prerequisites` json,
	`detectionGuidance` text,
	`archetypeComplexity` enum('low','medium','high','expert') DEFAULT 'medium',
	`isBuiltIn` boolean DEFAULT true,
	`createdBy` int,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `campaign_archetypes_id` PRIMARY KEY(`id`),
	CONSTRAINT `campaign_archetypes_slug_unique` UNIQUE(`slug`)
);
