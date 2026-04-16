ALTER TABLE `cicd_runs` MODIFY COLUMN `cicd_report_url` text;--> statement-breakpoint
ALTER TABLE `cicd_pipelines` ADD `cicd_engagement_id` int;--> statement-breakpoint
ALTER TABLE `cicd_pipelines` ADD `cicd_sector_context` varchar(128);--> statement-breakpoint
ALTER TABLE `cicd_runs` ADD `cicd_run_engagement_id` int;--> statement-breakpoint
ALTER TABLE `cicd_runs` ADD `cicd_threat_context` json;