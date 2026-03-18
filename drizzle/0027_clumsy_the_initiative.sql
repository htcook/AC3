ALTER TABLE `llm_training_examples` ADD `te_review_status` enum('pending_review','approved','rejected','flagged') DEFAULT 'pending_review' NOT NULL;--> statement-breakpoint
ALTER TABLE `llm_training_examples` ADD `te_reviewed_by` varchar(128);--> statement-breakpoint
ALTER TABLE `llm_training_examples` ADD `te_reviewed_at` timestamp;--> statement-breakpoint
ALTER TABLE `llm_training_examples` ADD `te_review_notes` text;--> statement-breakpoint
CREATE INDEX `lte_review_status_idx` ON `llm_training_examples` (`te_review_status`);