CREATE TABLE `knowledge_entries` (
	`id` int AUTO_INCREMENT NOT NULL,
	`entry_id` varchar(64) NOT NULL,
	`name` varchar(255) NOT NULL,
	`category` varchar(64) NOT NULL,
	`subcategory` varchar(64),
	`description` text NOT NULL,
	`mitre_technique_ids` json,
	`phase` varchar(64) NOT NULL,
	`target_platform` varchar(32) DEFAULT 'both',
	`required_privilege` varchar(32),
	`tools` json,
	`code` text,
	`language` varchar(32),
	`prerequisites` json,
	`detection_indicators` json,
	`post_exploit_actions` json,
	`verification_steps` json,
	`opsec_risk` int,
	`confidence` int,
	`source` varchar(255),
	`source_url` varchar(512),
	`tags` json,
	`is_active` tinyint NOT NULL DEFAULT 1,
	`created_by` varchar(255),
	`created_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP',
	`updated_at` timestamp NOT NULL DEFAULT 'CURRENT_TIMESTAMP'
);
--> statement-breakpoint
CREATE INDEX `ke_entry_id_unique` ON `knowledge_entries` (`entry_id`);--> statement-breakpoint
CREATE INDEX `ke_category_idx` ON `knowledge_entries` (`category`);--> statement-breakpoint
CREATE INDEX `ke_phase_idx` ON `knowledge_entries` (`phase`);