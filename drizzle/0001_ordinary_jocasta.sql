CREATE TABLE `engagement_ops_snapshots` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`state_json` json NOT NULL,
	`phase` varchar(64),
	`is_running` boolean DEFAULT false,
	`asset_count` int DEFAULT 0,
	`created_at` timestamp NOT NULL DEFAULT (now()),
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `engagement_ops_snapshots_id` PRIMARY KEY(`id`)
);
