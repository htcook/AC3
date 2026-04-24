DROP TABLE `jarm_community_signatures`;--> statement-breakpoint
DROP TABLE `jarm_feed_sources`;--> statement-breakpoint
DROP TABLE `jarm_scan_history`;--> statement-breakpoint
ALTER TABLE `enrichment_history` DROP PRIMARY KEY;--> statement-breakpoint
ALTER TABLE `access_broker_listings` ADD `priority_level` varchar(16);