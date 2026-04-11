CREATE TABLE `nuclei_template_mappings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`cve_id` varchar(32) NOT NULL,
	`template_path` varchar(512) NOT NULL,
	`vuln_class` varchar(64),
	`service` varchar(128),
	`success_count` int DEFAULT 1,
	`last_used_at` bigint NOT NULL,
	`discovered_from` enum('exploit_success','manual','knowledge_store') DEFAULT 'exploit_success',
	`created_at` bigint NOT NULL
);
--> statement-breakpoint
ALTER TABLE `nuclei_findings` ADD `access_level` varchar(64);--> statement-breakpoint
ALTER TABLE `nuclei_findings` ADD `confidence` int;--> statement-breakpoint
ALTER TABLE `nuclei_findings` ADD `execution_context` varchar(32);--> statement-breakpoint
ALTER TABLE `nuclei_findings` ADD `nuclei_command` text;--> statement-breakpoint
ALTER TABLE `nuclei_findings` ADD `finding_hash` varchar(64);--> statement-breakpoint
ALTER TABLE `nuclei_findings` ADD `port` int;--> statement-breakpoint
ALTER TABLE `nuclei_findings` ADD `nuclei_verified` tinyint DEFAULT 0;--> statement-breakpoint
CREATE INDEX `ntm_cve_idx` ON `nuclei_template_mappings` (`cve_id`);--> statement-breakpoint
CREATE INDEX `ntm_template_idx` ON `nuclei_template_mappings` (`template_path`);--> statement-breakpoint
CREATE INDEX `ntm_vuln_class_idx` ON `nuclei_template_mappings` (`vuln_class`);--> statement-breakpoint
CREATE INDEX `nf_engagement_idx` ON `nuclei_findings` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `nf_cve_idx` ON `nuclei_findings` (`cve_id`);--> statement-breakpoint
CREATE INDEX `nf_template_idx` ON `nuclei_findings` (`template_id`);--> statement-breakpoint
CREATE INDEX `nf_severity_idx` ON `nuclei_findings` (`severity`);--> statement-breakpoint
CREATE INDEX `nf_host_idx` ON `nuclei_findings` (`host`);--> statement-breakpoint
CREATE INDEX `nf_hash_idx` ON `nuclei_findings` (`finding_hash`);