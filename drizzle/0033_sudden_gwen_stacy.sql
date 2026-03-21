ALTER TABLE `engagement_ops_snapshots` ADD `interrupt_count` int DEFAULT 0;--> statement-breakpoint
ALTER TABLE `engagement_ops_snapshots` ADD `last_interrupted_at` timestamp;--> statement-breakpoint
ALTER TABLE `engagements` ADD `auto_resume_on_restart` tinyint DEFAULT 0;