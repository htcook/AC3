ALTER TABLE `web_app_scans` ADD `auth_credential_source` varchar(50);--> statement-breakpoint
ALTER TABLE `web_app_scans` ADD `auth_username` varchar(100);--> statement-breakpoint
ALTER TABLE `web_app_scans` ADD `auth_method` varchar(30);