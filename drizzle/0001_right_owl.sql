CREATE TABLE `activity_logs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int,
	`serverId` int,
	`action` varchar(255) NOT NULL,
	`details` text,
	`ipAddress` varchar(45),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `activity_logs_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `caldera_stats` (
	`id` int AUTO_INCREMENT NOT NULL,
	`serverId` int NOT NULL,
	`totalAdversaries` int DEFAULT 0,
	`totalAbilities` int DEFAULT 0,
	`activeOperations` int DEFAULT 0,
	`totalAgents` int DEFAULT 0,
	`lastUpdated` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `caldera_stats_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `server_configs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(255) NOT NULL,
	`ipAddress` varchar(45) NOT NULL,
	`httpsUrl` varchar(512),
	`httpUrl` varchar(512),
	`region` varchar(64),
	`dropletSize` varchar(64),
	`dropletId` varchar(64),
	`status` enum('online','offline','unknown') NOT NULL DEFAULT 'unknown',
	`lastHealthCheck` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `server_configs_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `server_credentials` (
	`id` int AUTO_INCREMENT NOT NULL,
	`serverId` int NOT NULL,
	`credentialType` enum('admin_login','red_api_key','blue_api_key','ssh_key') NOT NULL,
	`username` varchar(255),
	`password` text,
	`apiKey` text,
	`sshKeyPath` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `server_credentials_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
ALTER TABLE `users` MODIFY COLUMN `role` enum('user','admin','viewer') NOT NULL DEFAULT 'viewer';