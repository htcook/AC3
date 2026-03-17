CREATE TABLE `ac3_report_artifacts` (
	`id` int AUTO_INCREMENT NOT NULL,
	`artifact_id` varchar(64) NOT NULL,
	`report_id` varchar(64) NOT NULL,
	`finding_id` varchar(64),
	`artifact_type` varchar(32) NOT NULL DEFAULT 'screenshot',
	`label` varchar(32) NOT NULL,
	`filename` varchar(255),
	`url` text,
	`description` text,
	`mime_type` varchar(128),
	`file_size` int,
	`captured_at` bigint,
	`created_at` bigint NOT NULL,
	CONSTRAINT `ac3_report_artifacts_id` PRIMARY KEY(`id`),
	CONSTRAINT `ac3_report_artifacts_artifact_id_unique` UNIQUE(`artifact_id`)
);
--> statement-breakpoint
ALTER TABLE `ac3_reports` ADD `compliance_framework` varchar(32) DEFAULT 'nist_800_53_r5' NOT NULL;--> statement-breakpoint
CREATE INDEX `art_report_idx` ON `ac3_report_artifacts` (`report_id`);--> statement-breakpoint
CREATE INDEX `art_finding_idx` ON `ac3_report_artifacts` (`finding_id`);--> statement-breakpoint
CREATE INDEX `art_label_idx` ON `ac3_report_artifacts` (`label`);