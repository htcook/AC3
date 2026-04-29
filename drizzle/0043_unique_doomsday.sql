CREATE TABLE `customer_stack_profiles` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int,
	`customer_name` varchar(255) NOT NULL,
	`languages` json,
	`web_frameworks` json,
	`data_and_ml` json,
	`genai_and_llm` json,
	`cloud_services` json,
	`security_tools` json,
	`devops_and_ci` json,
	`databases_list` json,
	`infrastructure` json,
	`other_techs` json,
	`auto_detected` json,
	`generated_test_plan` json,
	`matched_scanners` json,
	`coverage_percent` int,
	`gaps` json,
	`notes` text,
	`created_by` int,
	`created_at` timestamp NOT NULL DEFAULT (now()),
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `customer_stack_profiles_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `csp_engagement_idx` ON `customer_stack_profiles` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `csp_customer_idx` ON `customer_stack_profiles` (`customer_name`);