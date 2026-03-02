CREATE TABLE `caldera_accounts` (
	`id` int AUTO_INCREMENT NOT NULL,
	`email` varchar(255) NOT NULL,
	`password_hash` varchar(255) NOT NULL,
	`display_name` varchar(255) NOT NULL,
	`account_role` enum('admin','operator','analyst','team_lead','executive','client','soc','viewer') NOT NULL DEFAULT 'viewer',
	`account_status` enum('active','invited','suspended','deactivated') NOT NULL DEFAULT 'invited',
	`last_login_at` timestamp,
	`invited_by` int,
	`invite_token` varchar(128),
	`invite_expires_at` timestamp,
	`password_reset_token` varchar(128),
	`password_reset_expires_at` timestamp,
	`created_at` timestamp NOT NULL DEFAULT (now()),
	`updated_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `caldera_accounts_id` PRIMARY KEY(`id`),
	CONSTRAINT `caldera_accounts_email_unique` UNIQUE(`email`)
);
