ALTER TABLE `engagements` MODIFY COLUMN `engagementType` enum('red_team','phishing','pentest','purple_team','tabletop','bug_bounty','vulnerability_assessment') NOT NULL DEFAULT 'red_team';--> statement-breakpoint
ALTER TABLE `engagements` ADD `license_tier` enum('standard','professional','enterprise') DEFAULT 'standard';--> statement-breakpoint
ALTER TABLE `engagements` ADD `bug_bounty_program_url` text;--> statement-breakpoint
ALTER TABLE `engagements` ADD `bug_bounty_platform` enum('hackerone','bugcrowd','intigriti','synack','yeswehack','custom');--> statement-breakpoint
ALTER TABLE `engagements` ADD `selected_frameworks` json;