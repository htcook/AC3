ALTER TABLE `discovered_assets` ADD `assetCriticalityScore` int;--> statement-breakpoint
ALTER TABLE `discovered_assets` ADD `assetCriticalityBand` varchar(32);--> statement-breakpoint
ALTER TABLE `discovered_assets` ADD `vulnRiskScore` int;--> statement-breakpoint
ALTER TABLE `discovered_assets` ADD `vulnRiskBand` varchar(32);