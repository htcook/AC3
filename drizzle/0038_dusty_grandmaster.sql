ALTER TABLE `remediation_verifications` ADD `rv_severity` enum('critical','high','medium','low','info') DEFAULT 'medium';--> statement-breakpoint
ALTER TABLE `remediation_verifications` ADD `rv_sla_deadline` timestamp;--> statement-breakpoint
ALTER TABLE `remediation_verifications` ADD `rv_sla_hours` int;--> statement-breakpoint
ALTER TABLE `remediation_verifications` ADD `rv_verification_output` text;--> statement-breakpoint
ALTER TABLE `remediation_verifications` ADD `rv_attempt_count` int DEFAULT 0;--> statement-breakpoint
ALTER TABLE `remediation_verifications` ADD `rv_asset_name` varchar(255);--> statement-breakpoint
ALTER TABLE `remediation_verifications` ADD `rv_finding_title` varchar(512);