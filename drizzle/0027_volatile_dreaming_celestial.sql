CREATE TABLE `cicd_webhook_deliveries` (
	`id` int AUTO_INCREMENT NOT NULL,
	`pipeline_id` int NOT NULL,
	`run_id` int,
	`event_type` varchar(128) NOT NULL,
	`payload_summary` text,
	`response_status` int,
	`response_body` text,
	`delivery_status` enum('pending','delivered','failed','retrying') NOT NULL DEFAULT 'pending',
	`attempt_count` int NOT NULL DEFAULT 0,
	`max_retries` int NOT NULL DEFAULT 3,
	`next_retry_at` timestamp,
	`last_attempt_at` timestamp,
	`delivered_at` timestamp,
	`created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`webhook_url` varchar(512),
	`error_message` text,
	`duration_ms` int
);
