ALTER TABLE `cicd_pipelines` ADD `cicd_schedule_cron` varchar(128);--> statement-breakpoint
ALTER TABLE `cicd_pipelines` ADD `cicd_schedule_enabled` tinyint DEFAULT 0;--> statement-breakpoint
ALTER TABLE `cicd_pipelines` ADD `cicd_schedule_target_url` varchar(512);--> statement-breakpoint
ALTER TABLE `cicd_pipelines` ADD `cicd_schedule_last_run` timestamp;--> statement-breakpoint
ALTER TABLE `cicd_pipelines` ADD `cicd_schedule_next_run` timestamp;