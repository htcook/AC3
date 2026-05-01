CREATE TABLE `customer_intelligence_profiles` (
	`id` int AUTO_INCREMENT NOT NULL,
	`customer_id` varchar(255) NOT NULL,
	`customer_name` varchar(255) NOT NULL,
	`overall_posture_score` double,
	`posture_grade` varchar(8),
	`posture_trend` varchar(16) DEFAULT 'stable',
	`total_engagements` int DEFAULT 0,
	`total_di_scans` int DEFAULT 0,
	`total_findings` int DEFAULT 0,
	`total_critical` int DEFAULT 0,
	`total_high` int DEFAULT 0,
	`total_medium` int DEFAULT 0,
	`total_low` int DEFAULT 0,
	`posture_trend_data` json,
	`findings_trend_data` json,
	`recurring_weaknesses` json,
	`persistent_gaps` json,
	`known_technologies` json,
	`technology_changes` json,
	`attack_surface_size` int,
	`attack_surface_trend` json,
	`strategic_recommendations` json,
	`open_gaps_count` int DEFAULT 0,
	`resolved_gaps_count` int DEFAULT 0,
	`last_engagement_date` timestamp,
	`last_updated` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `customer_intelligence_profiles_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `intelligence_gaps` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int,
	`scan_id` int,
	`customer_id` varchar(255),
	`category` varchar(64) NOT NULL,
	`subcategory` varchar(128),
	`title` varchar(512) NOT NULL,
	`description` text,
	`reason` text NOT NULL,
	`risk_implication` text,
	`potential_impact` varchar(32) DEFAULT 'unknown',
	`recommendation` text,
	`estimated_effort` varchar(64),
	`status` varchar(32) NOT NULL DEFAULT 'open',
	`resolved_at` timestamp,
	`resolved_by` int,
	`resolution_note` text,
	`detected_by` varchar(64) DEFAULT 'system',
	`confidence` double,
	`affected_assets` json,
	`affected_scope` json,
	`related_findings` json,
	`tags` json,
	`created_at` timestamp NOT NULL DEFAULT (now()),
	`updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `intelligence_gaps_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `cip_customer_id_idx` ON `customer_intelligence_profiles` (`customer_id`);--> statement-breakpoint
CREATE INDEX `cip_customer_name_idx` ON `customer_intelligence_profiles` (`customer_name`);--> statement-breakpoint
CREATE INDEX `ig_engagement_idx` ON `intelligence_gaps` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `ig_scan_idx` ON `intelligence_gaps` (`scan_id`);--> statement-breakpoint
CREATE INDEX `ig_customer_idx` ON `intelligence_gaps` (`customer_id`);--> statement-breakpoint
CREATE INDEX `ig_status_idx` ON `intelligence_gaps` (`status`);--> statement-breakpoint
CREATE INDEX `ig_category_idx` ON `intelligence_gaps` (`category`);