CREATE TABLE `evidence_guardrail_audit` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ega_engagement_id` varchar(64) NOT NULL,
	`ega_evidence_id` varchar(128),
	`ega_specialist` varchar(100) NOT NULL,
	`ega_check_type` enum('hallucination','provenance','chain_integrity','evidence_gate') NOT NULL,
	`ega_passed` tinyint NOT NULL,
	`ega_score` int,
	`ega_recommendation` enum('accept','review','reject','quarantine') NOT NULL,
	`ega_grounded_claims` int DEFAULT 0,
	`ega_ungrounded_claims` int DEFAULT 0,
	`ega_critical_issues` int DEFAULT 0,
	`ega_was_sanitized` tinyint DEFAULT 0,
	`ega_details` json,
	`ega_content_hash` varchar(64),
	`ega_created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `evidence_integrity_anchors` (
	`id` int AUTO_INCREMENT NOT NULL,
	`eia_engagement_id` varchar(64) NOT NULL,
	`eia_merkle_root` varchar(64) NOT NULL,
	`eia_hmac_signature` varchar(64) NOT NULL,
	`eia_chain_length` int NOT NULL,
	`eia_anchored_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`eia_anchored_by` varchar(255) NOT NULL,
	`eia_status` enum('active','superseded','invalidated') NOT NULL DEFAULT 'active',
	`eia_notes` text
);
--> statement-breakpoint
CREATE INDEX `ega_engagement_idx` ON `evidence_guardrail_audit` (`ega_engagement_id`);--> statement-breakpoint
CREATE INDEX `ega_specialist_idx` ON `evidence_guardrail_audit` (`ega_specialist`);--> statement-breakpoint
CREATE INDEX `ega_passed_idx` ON `evidence_guardrail_audit` (`ega_passed`);--> statement-breakpoint
CREATE INDEX `ega_recommendation_idx` ON `evidence_guardrail_audit` (`ega_recommendation`);--> statement-breakpoint
CREATE INDEX `ega_created_at_idx` ON `evidence_guardrail_audit` (`ega_created_at`);--> statement-breakpoint
CREATE INDEX `eia_engagement_idx` ON `evidence_integrity_anchors` (`eia_engagement_id`);--> statement-breakpoint
CREATE INDEX `eia_status_idx` ON `evidence_integrity_anchors` (`eia_status`);