CREATE TABLE `roe_versions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`roe_id` int NOT NULL,
	`version_number` varchar(32) NOT NULL,
	`change_type` enum('created','updated','status_change','approved','restored') NOT NULL DEFAULT 'updated',
	`change_summary` text,
	`changed_fields` json,
	`previous_snapshot` json,
	`current_snapshot` json,
	`changed_by` int,
	`changed_by_name` varchar(256),
	`created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `roe_versions_id` PRIMARY KEY(`id`)
);
