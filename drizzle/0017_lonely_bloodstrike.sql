ALTER TABLE `ac3_report_findings` ADD `rf_source_module` varchar(128);--> statement-breakpoint
ALTER TABLE `ac3_report_findings` ADD `rf_source_event_id` varchar(128);--> statement-breakpoint
ALTER TABLE `ac3_reports` ADD `rpt_docx_url` text;