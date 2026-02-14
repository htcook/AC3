CREATE TABLE `engagement_reports` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagementId` int NOT NULL,
	`reportType` enum('executive_summary','technical_detail','compliance','phishing_results','osint_assessment','full_engagement') NOT NULL,
	`clientType` enum('msp','enterprise','saas','paas','iaas','mixed_hosting','other') NOT NULL DEFAULT 'enterprise',
	`title` varchar(512) NOT NULL,
	`preparedFor` varchar(255),
	`preparedBy` varchar(255),
	`includeSections` json,
	`reportUrl` text,
	`reportKey` varchar(512),
	`status` enum('pending','generating','completed','failed') NOT NULL DEFAULT 'pending',
	`generatedAt` timestamp,
	`brandingLogo` text,
	`brandingColor` varchar(32),
	`createdBy` int,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `engagement_reports_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `osint_monitor_changes` (
	`id` int AUTO_INCREMENT NOT NULL,
	`monitorId` int NOT NULL,
	`domain` varchar(255) NOT NULL,
	`changeType` varchar(64) NOT NULL,
	`severity` enum('info','warning','critical') NOT NULL DEFAULT 'info',
	`previousValue` text,
	`currentValue` text,
	`description` text,
	`acknowledged` boolean DEFAULT false,
	`acknowledgedBy` int,
	`acknowledgedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `osint_monitor_changes_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `osint_monitors` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagementId` int,
	`domain` varchar(255) NOT NULL,
	`intervalHours` int NOT NULL DEFAULT 24,
	`enabled` boolean NOT NULL DEFAULT true,
	`clientType` enum('msp','enterprise','saas','paas','iaas','mixed_hosting','other') NOT NULL DEFAULT 'enterprise',
	`lastScanAt` timestamp,
	`lastChangeDetectedAt` timestamp,
	`totalScans` int DEFAULT 0,
	`totalChangesDetected` int DEFAULT 0,
	`notifyOnChange` boolean DEFAULT true,
	`notifyEmail` varchar(320),
	`baselineSnapshot` json,
	`createdBy` int,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `osint_monitors_id` PRIMARY KEY(`id`)
);
