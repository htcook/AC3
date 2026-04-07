CREATE TABLE `adjustment_effectiveness` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ae_adjustment_type` varchar(64) NOT NULL,
	`ae_failure_category` varchar(64) NOT NULL,
	`ae_service` varchar(128) NOT NULL,
	`ae_engagement_id` int,
	`ae_target` varchar(255),
	`ae_port` int,
	`ae_success` tinyint NOT NULL,
	`ae_retry_number` int,
	`ae_base_priority` int,
	`ae_adjusted_priority` int,
	`ae_exec_duration_ms` int,
	`ae_exploit_output` text,
	`ae_created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE INDEX `ae_adj_type_idx` ON `adjustment_effectiveness` (`ae_adjustment_type`);--> statement-breakpoint
CREATE INDEX `ae_fail_cat_idx` ON `adjustment_effectiveness` (`ae_failure_category`);--> statement-breakpoint
CREATE INDEX `ae_service_idx` ON `adjustment_effectiveness` (`ae_service`);--> statement-breakpoint
CREATE INDEX `ae_composite_idx` ON `adjustment_effectiveness` (`ae_adjustment_type`,`ae_failure_category`,`ae_service`);