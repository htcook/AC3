CREATE TABLE `engagement_telemetry` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`phase` varchar(64) NOT NULL,
	`step` varchar(128) NOT NULL,
	`event_type` enum('tool_call','tool_response','llm_request','llm_response','decision','error','retry','phase_transition','approval_request','approval_response','evidence_captured','evidence_validated') NOT NULL,
	`input_summary` text,
	`output_summary` text,
	`full_payload_ref` varchar(512),
	`duration_ms` int,
	`exit_code` int,
	`success` tinyint NOT NULL DEFAULT 1,
	`error_class` enum('none','timeout','auth_failure','connection_refused','api_error','parse_failure','llm_hallucination','knowledge_gap','logic_error','evidence_integrity','infrastructure','rate_limit','unknown') NOT NULL DEFAULT 'none',
	`error_message` text,
	`retry_count` int NOT NULL DEFAULT 0,
	`context_snapshot` json,
	`storage_provider` enum('do_spaces','aws_s3','local','none') NOT NULL DEFAULT 'none',
	`correlation_id` varchar(64),
	`operator_id` varchar(64),
	`target_host` varchar(255),
	`source_module` varchar(128),
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `engagement_telemetry_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `telemetry_diagnostics` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagement_id` int NOT NULL,
	`report_type` enum('post_engagement','phase_complete','error_burst','manual') NOT NULL,
	`total_events` int NOT NULL DEFAULT 0,
	`event_type_breakdown` json,
	`failure_rate_by_category` json,
	`slowest_operations` json,
	`knowledge_gaps` json,
	`retry_storms` json,
	`total_duration_ms` int,
	`llm_tokens_total` int DEFAULT 0,
	`llm_cost_estimate` double,
	`health_score` int,
	`diagnostic_markdown` text,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `telemetry_diagnostics_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `telemetry_llm_quality` (
	`id` int AUTO_INCREMENT NOT NULL,
	`telemetry_event_id` int NOT NULL,
	`engagement_id` int NOT NULL,
	`prompt_hash` varchar(64) NOT NULL,
	`tokens_in` int NOT NULL DEFAULT 0,
	`tokens_out` int NOT NULL DEFAULT 0,
	`total_tokens` int NOT NULL DEFAULT 0,
	`parsed_successfully` tinyint NOT NULL DEFAULT 1,
	`schema_valid` tinyint NOT NULL DEFAULT 1,
	`hallucination_detected` tinyint NOT NULL DEFAULT 0,
	`hallucination_confidence` double,
	`knowledge_gap` tinyint NOT NULL DEFAULT 0,
	`knowledge_gap_topic` varchar(255),
	`model` varchar(128),
	`response_format` varchar(64),
	`grounding_check_passed` tinyint,
	`prompt_payload_ref` varchar(512),
	`response_payload_ref` varchar(512),
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `telemetry_llm_quality_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `et_engagement_idx` ON `engagement_telemetry` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `et_phase_idx` ON `engagement_telemetry` (`phase`);--> statement-breakpoint
CREATE INDEX `et_event_type_idx` ON `engagement_telemetry` (`event_type`);--> statement-breakpoint
CREATE INDEX `et_error_class_idx` ON `engagement_telemetry` (`error_class`);--> statement-breakpoint
CREATE INDEX `et_correlation_idx` ON `engagement_telemetry` (`correlation_id`);--> statement-breakpoint
CREATE INDEX `et_created_at_idx` ON `engagement_telemetry` (`created_at`);--> statement-breakpoint
CREATE INDEX `et_success_idx` ON `engagement_telemetry` (`success`);--> statement-breakpoint
CREATE INDEX `et_source_module_idx` ON `engagement_telemetry` (`source_module`);--> statement-breakpoint
CREATE INDEX `td_engagement_idx` ON `telemetry_diagnostics` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `td_report_type_idx` ON `telemetry_diagnostics` (`report_type`);--> statement-breakpoint
CREATE INDEX `td_health_score_idx` ON `telemetry_diagnostics` (`health_score`);--> statement-breakpoint
CREATE INDEX `td_created_at_idx` ON `telemetry_diagnostics` (`created_at`);--> statement-breakpoint
CREATE INDEX `tlq_telemetry_event_idx` ON `telemetry_llm_quality` (`telemetry_event_id`);--> statement-breakpoint
CREATE INDEX `tlq_engagement_idx` ON `telemetry_llm_quality` (`engagement_id`);--> statement-breakpoint
CREATE INDEX `tlq_prompt_hash_idx` ON `telemetry_llm_quality` (`prompt_hash`);--> statement-breakpoint
CREATE INDEX `tlq_knowledge_gap_idx` ON `telemetry_llm_quality` (`knowledge_gap`);--> statement-breakpoint
CREATE INDEX `tlq_hallucination_idx` ON `telemetry_llm_quality` (`hallucination_detected`);--> statement-breakpoint
CREATE INDEX `tlq_created_at_idx` ON `telemetry_llm_quality` (`created_at`);