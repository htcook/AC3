CREATE TABLE `cicd_baselines` (
	`id` int AUTO_INCREMENT NOT NULL,
	`pipeline_id` int NOT NULL,
	`commit_sha` varchar(64) NOT NULL,
	`branch` varchar(255),
	`finding_hashes` json NOT NULL,
	`total_findings` int NOT NULL DEFAULT 0,
	`created_at` bigint NOT NULL,
	`created_by` varchar(255),
	CONSTRAINT `cicd_baselines_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `cicd_run_findings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`run_id` int NOT NULL,
	`pipeline_id` int NOT NULL,
	`title` varchar(512) NOT NULL,
	`title_hash` varchar(64) NOT NULL,
	`severity` enum('critical','high','medium','low','info') NOT NULL DEFAULT 'medium',
	`cvss` double,
	`scanner` varchar(64) NOT NULL,
	`url` varchar(1024),
	`description` text,
	`cwe_id` varchar(32),
	`is_new` tinyint NOT NULL DEFAULT 1,
	`created_at` bigint NOT NULL,
	CONSTRAINT `cicd_run_findings_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `cicd_sbom_artifacts` (
	`id` int AUTO_INCREMENT NOT NULL,
	`run_id` int NOT NULL,
	`pipeline_id` int NOT NULL,
	`image_ref` varchar(512) NOT NULL,
	`format` enum('cyclonedx','spdx') NOT NULL DEFAULT 'cyclonedx',
	`storage_url` varchar(1024) NOT NULL,
	`storage_key` varchar(512) NOT NULL,
	`package_count` int DEFAULT 0,
	`created_at` bigint NOT NULL,
	CONSTRAINT `cicd_sbom_artifacts_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `cicd_bl_pipeline_idx` ON `cicd_baselines` (`pipeline_id`);--> statement-breakpoint
CREATE INDEX `cicd_bl_commit_idx` ON `cicd_baselines` (`commit_sha`);--> statement-breakpoint
CREATE INDEX `cicd_rf_run_idx` ON `cicd_run_findings` (`run_id`);--> statement-breakpoint
CREATE INDEX `cicd_rf_pipeline_idx` ON `cicd_run_findings` (`pipeline_id`);--> statement-breakpoint
CREATE INDEX `cicd_rf_hash_idx` ON `cicd_run_findings` (`title_hash`);--> statement-breakpoint
CREATE INDEX `cicd_rf_severity_idx` ON `cicd_run_findings` (`severity`);--> statement-breakpoint
CREATE INDEX `cicd_sbom_run_idx` ON `cicd_sbom_artifacts` (`run_id`);--> statement-breakpoint
CREATE INDEX `cicd_sbom_pipeline_idx` ON `cicd_sbom_artifacts` (`pipeline_id`);