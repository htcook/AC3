CREATE TABLE `credential_rotation_audit` (
	`id` int AUTO_INCREMENT NOT NULL,
	`rotation_audit_policy_id` int NOT NULL,
	`rotation_audit_credential_id` int NOT NULL,
	`rotation_audit_provider` enum('aws','azure','gcp') NOT NULL,
	`rotation_status` enum('pending','in_progress','success','failed','rollback') NOT NULL,
	`old_key_identifier` varchar(255),
	`new_key_identifier` varchar(255),
	`rotation_error_message` text,
	`rotation_duration_ms` int NOT NULL DEFAULT 0,
	`rotation_initiated_by` varchar(255) NOT NULL,
	`rotation_audit_created_at` timestamp DEFAULT (now()),
	CONSTRAINT `credential_rotation_audit_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `credential_rotation_policies` (
	`id` int AUTO_INCREMENT NOT NULL,
	`rotation_credential_id` int NOT NULL,
	`rotation_provider` enum('aws','azure','gcp') NOT NULL,
	`rotation_cred_name` varchar(255) NOT NULL,
	`rotation_enabled` boolean NOT NULL DEFAULT false,
	`rotation_interval_days` int NOT NULL DEFAULT 90,
	`last_rotated_at` timestamp,
	`next_rotation_at` timestamp,
	`rotation_max_retries` int NOT NULL DEFAULT 3,
	`rotation_retry_count` int NOT NULL DEFAULT 0,
	`rotation_created_by` varchar(255),
	`rotation_policy_created_at` timestamp DEFAULT (now()),
	`rotation_policy_updated_at` timestamp DEFAULT (now()),
	CONSTRAINT `credential_rotation_policies_id` PRIMARY KEY(`id`)
);
