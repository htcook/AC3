CREATE TABLE `ioc_sync_logs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`syncType` varchar(32) NOT NULL,
	`status` varchar(32) NOT NULL,
	`results` json,
	`totalFetched` int DEFAULT 0,
	`errorMessage` text,
	`startedAt` timestamp NOT NULL DEFAULT (now()),
	`completedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `ioc_sync_logs_id` PRIMARY KEY(`id`)
);
