CREATE TABLE `campaign_engagements` (
	`id` int AUTO_INCREMENT NOT NULL,
	`engagementId` int NOT NULL,
	`gophishCampaignId` int NOT NULL,
	`gophishCampaignName` varchar(255),
	`calderaOperationId` varchar(255),
	`notes` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `campaign_engagements_id` PRIMARY KEY(`id`)
);
