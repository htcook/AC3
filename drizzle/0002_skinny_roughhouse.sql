CREATE TABLE `classification_audit_log` (
	`id` int AUTO_INCREMENT NOT NULL,
	`actor_id` varchar(255) NOT NULL,
	`actor_name` varchar(500),
	`previous_type` varchar(100) NOT NULL,
	`new_type` varchar(100) NOT NULL,
	`confidence` int NOT NULL,
	`reasoning` text,
	`source` varchar(100) NOT NULL DEFAULT 'llm_auto',
	`applied_by` varchar(255),
	`applied_method` varchar(50) NOT NULL DEFAULT 'auto_apply',
	`batch_id` varchar(100),
	`was_reverted` tinyint DEFAULT 0,
	`reverted_at` bigint,
	`reverted_by` varchar(255),
	`created_at` bigint NOT NULL,
	CONSTRAINT `classification_audit_log_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `cal_actor_idx` ON `classification_audit_log` (`actor_id`);--> statement-breakpoint
CREATE INDEX `cal_source_idx` ON `classification_audit_log` (`source`);--> statement-breakpoint
CREATE INDEX `cal_batch_idx` ON `classification_audit_log` (`batch_id`);--> statement-breakpoint
CREATE INDEX `cal_created_idx` ON `classification_audit_log` (`created_at`);