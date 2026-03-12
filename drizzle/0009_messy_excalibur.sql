CREATE TABLE `accuracy_comparisons` (
	`id` int AUTO_INCREMENT NOT NULL,
	`session_id` varchar(128) NOT NULL,
	`engagement_id` varchar(128),
	`target_preset` varchar(128) NOT NULL,
	`target_url` varchar(512),
	`scan_type` varchar(64),
	`precision` double DEFAULT 0,
	`recall` double DEFAULT 0,
	`f1_score` double DEFAULT 0,
	`true_positives` int DEFAULT 0,
	`false_positives` int DEFAULT 0,
	`false_negatives` int DEFAULT 0,
	`total_findings` int DEFAULT 0,
	`total_ground_truth` int DEFAULT 0,
	`matched_findings` json,
	`missed_vulns` json,
	`false_positive_findings` json,
	`f1_delta` double,
	`precision_delta` double,
	`recall_delta` double,
	`knowledge_modules_used` json,
	`scan_duration_ms` int,
	`scored_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `accuracy_comparisons_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `vuln_type_accuracy` (
	`id` int AUTO_INCREMENT NOT NULL,
	`comparison_id` int NOT NULL,
	`vuln_type` varchar(128) NOT NULL,
	`detection_rate` double DEFAULT 0,
	`false_positive_rate` double DEFAULT 0,
	`times_found` int DEFAULT 0,
	`times_missed` int DEFAULT 0,
	`times_false_positive` int DEFAULT 0,
	`target_preset` varchar(128) NOT NULL,
	`scored_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `vuln_type_accuracy_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `acc_comp_session_idx` ON `accuracy_comparisons` (`session_id`);--> statement-breakpoint
CREATE INDEX `acc_comp_target_idx` ON `accuracy_comparisons` (`target_preset`);--> statement-breakpoint
CREATE INDEX `acc_comp_engagement_idx` ON `accuracy_comparisons` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `acc_comp_scored_idx` ON `accuracy_comparisons` (`scored_at`);--> statement-breakpoint
CREATE INDEX `vta_comparison_idx` ON `vuln_type_accuracy` (`comparison_id`);--> statement-breakpoint
CREATE INDEX `vta_vuln_type_idx` ON `vuln_type_accuracy` (`vuln_type`);--> statement-breakpoint
CREATE INDEX `vta_target_idx` ON `vuln_type_accuracy` (`target_preset`);