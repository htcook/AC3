CREATE TABLE `scan_results` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`tool` varchar(64) NOT NULL,
	`target` varchar(255) NOT NULL,
	`command` text,
	`raw_output` mediumtext,
	`raw_stderr` mediumtext,
	`exit_code` int,
	`duration_ms` int,
	`timed_out` boolean DEFAULT false,
	`findings` json,
	`finding_count` int DEFAULT 0,
	`severity_summary` json,
	`phase` varchar(64),
	`operator_id` int,
	`created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `scan_results_id` PRIMARY KEY(`id`)
);
