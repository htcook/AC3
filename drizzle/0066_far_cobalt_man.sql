CREATE TABLE `team_invitations` (
	`id` int AUTO_INCREMENT NOT NULL,
	`invite_email` varchar(320) NOT NULL,
	`invite_role` enum('user','admin','viewer','operator','team_lead','analyst','executive','client') NOT NULL DEFAULT 'operator',
	`token_hash` varchar(128) NOT NULL,
	`invited_by` int NOT NULL,
	`invited_by_name` varchar(255),
	`invite_status` enum('pending','accepted','expired','revoked') NOT NULL DEFAULT 'pending',
	`expires_at` timestamp NOT NULL,
	`accepted_at` timestamp,
	`accepted_by_user_id` int,
	`invite_message` text,
	`invite_created_at` timestamp NOT NULL DEFAULT (now()),
	`invite_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `team_invitations_id` PRIMARY KEY(`id`),
	CONSTRAINT `team_invitations_token_hash_unique` UNIQUE(`token_hash`)
);
--> statement-breakpoint
ALTER TABLE `users` ADD `avatar_url` text;--> statement-breakpoint
ALTER TABLE `users` ADD `title` varchar(128);--> statement-breakpoint
ALTER TABLE `users` ADD `department` varchar(128);--> statement-breakpoint
ALTER TABLE `users` ADD `phone` varchar(32);--> statement-breakpoint
ALTER TABLE `users` ADD `timezone` varchar(64) DEFAULT 'America/New_York';--> statement-breakpoint
ALTER TABLE `users` ADD `status` enum('active','inactive','suspended','pending') DEFAULT 'active' NOT NULL;--> statement-breakpoint
ALTER TABLE `users` ADD `invited_by` int;--> statement-breakpoint
ALTER TABLE `users` ADD `last_password_change` timestamp;--> statement-breakpoint
ALTER TABLE `users` ADD `mfa_enabled` boolean DEFAULT false;