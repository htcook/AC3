CREATE TABLE `cve_enrichment` (
	`id` int AUTO_INCREMENT NOT NULL,
	`cve_id` varchar(32) NOT NULL,
	`description` text,
	`cwes` json,
	`cvss_v3_score` float,
	`cvss_v3_vector` varchar(128),
	`published_date` varchar(64),
	`last_modified_date` varchar(64),
	`references` json,
	`enriched_at` bigint NOT NULL,
	`error` text
);
--> statement-breakpoint
CREATE INDEX `cve_enrichment_cve_id_unique` ON `cve_enrichment` (`cve_id`);