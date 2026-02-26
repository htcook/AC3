CREATE TABLE `vendor_cached_data` (
	`id` int AUTO_INCREMENT NOT NULL,
	`integrationId` int NOT NULL,
	`dataType` enum('host','detection','incident','alert','threat','vulnerability','indicator','search_result') NOT NULL,
	`externalId` varchar(255),
	`title` varchar(512),
	`dataSeverity` enum('critical','high','medium','low','informational'),
	`dataStatus` varchar(64),
	`rawData` json,
	`normalizedData` json,
	`hostname` varchar(255),
	`ipAddress` varchar(45),
	`domain` varchar(255),
	`mitreAttackId` varchar(32),
	`detectedAt` bigint,
	`lastUpdatedAt` bigint,
	`cachedAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `vendor_cached_data_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `vendor_integrations` (
	`id` int AUTO_INCREMENT NOT NULL,
	`vendor` enum('crowdstrike','sentinelone','defender','splunk','xsoar') NOT NULL,
	`displayName` varchar(255) NOT NULL,
	`enabled` boolean NOT NULL DEFAULT false,
	`authConfig` json,
	`connectionConfig` json,
	`integrationStatus` enum('connected','disconnected','error','unconfigured') NOT NULL DEFAULT 'unconfigured',
	`lastHealthCheck` bigint,
	`lastError` text,
	`syncEnabled` boolean NOT NULL DEFAULT false,
	`syncIntervalMinutes` int DEFAULT 60,
	`lastSyncAt` bigint,
	`createdBy` varchar(64),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `vendor_integrations_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `vendor_sync_events` (
	`id` int AUTO_INCREMENT NOT NULL,
	`integrationId` int NOT NULL,
	`eventType` enum('hosts_sync','detections_sync','incidents_sync','alerts_sync','threats_sync','vulnerabilities_sync','search_sync','indicators_sync','health_check','manual_query') NOT NULL,
	`syncStatus` enum('success','partial','failed') NOT NULL,
	`recordsProcessed` int DEFAULT 0,
	`recordsFailed` int DEFAULT 0,
	`summary` json,
	`errorMessage` text,
	`durationMs` int,
	`triggeredBy` varchar(64),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `vendor_sync_events_id` PRIMARY KEY(`id`)
);
