CREATE TABLE `corroboration_results` (
	`id` int AUTO_INCREMENT NOT NULL,
	`cr_import_id` int NOT NULL,
	`cr_finding_id` int NOT NULL,
	`cr_original_confidence` int NOT NULL,
	`cr_adjusted_confidence` int NOT NULL,
	`cr_corroborating_count` int DEFAULT 0,
	`cr_contradicting_count` int DEFAULT 0,
	`cr_corroborating_sources` text,
	`cr_contradicting_sources` text,
	`cr_verdict` varchar(32) NOT NULL,
	`cr_reasoning` text,
	`cr_suppress_recommendation` boolean DEFAULT false,
	`cr_created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `corroboration_results_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
ALTER TABLE `vuln_scan_findings` ADD `vsf_corroboration_score` int;--> statement-breakpoint
ALTER TABLE `vuln_scan_findings` ADD `vsf_corroboration_verdict` varchar(32);--> statement-breakpoint
ALTER TABLE `vuln_scan_findings` ADD `vsf_corroboration_sources` int DEFAULT 0;--> statement-breakpoint
ALTER TABLE `vuln_scan_findings` ADD `vsf_suppress_recommended` boolean DEFAULT false;