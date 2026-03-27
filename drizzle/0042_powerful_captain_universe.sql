CREATE TABLE `scanforge_promotion_history` (
	`id` int AUTO_INCREMENT NOT NULL,
	`template_id` varchar(128) NOT NULL,
	`generated_template_db_id` int NOT NULL,
	`decision` varchar(32) NOT NULL,
	`reason` text NOT NULL,
	`metrics_snapshot` json NOT NULL,
	`rules_evaluated` json NOT NULL,
	`trigger_engagement_id` varchar(64),
	`previous_status` varchar(32) NOT NULL,
	`new_status` varchar(32) NOT NULL,
	`evaluated_by` varchar(64) NOT NULL DEFAULT 'auto',
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `scanforge_promotion_history_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `sph_template_idx` ON `scanforge_promotion_history` (`template_id`);--> statement-breakpoint
CREATE INDEX `sph_decision_idx` ON `scanforge_promotion_history` (`decision`);--> statement-breakpoint
CREATE INDEX `sph_trigger_idx` ON `scanforge_promotion_history` (`trigger_engagement_id`);