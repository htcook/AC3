CREATE TABLE `container_vulnerabilities` (
	`id` int AUTO_INCREMENT NOT NULL,
	`scan_run_id` int NOT NULL,
	`image_name` varchar(512) NOT NULL,
	`image_tag` varchar(128),
	`image_digest` varchar(128),
	`vuln_id` varchar(64) NOT NULL,
	`severity` enum('critical','high','medium','low','unknown') NOT NULL DEFAULT 'unknown',
	`pkg_name` varchar(255) NOT NULL,
	`installed_version` varchar(128),
	`fixed_version` varchar(128),
	`title` text,
	`description` text,
	`primary_url` text,
	`data_source` varchar(128),
	`published_date` varchar(32),
	`cvss_score` varchar(10),
	`created_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `cspm_findings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`scan_run_id` int NOT NULL,
	`scan_tool` enum('prowler','scoutsuite','trivy') NOT NULL,
	`finding_uid` varchar(512),
	`severity` enum('critical','high','medium','low','info') NOT NULL DEFAULT 'medium',
	`status` enum('fail','pass','warning','manual','not_available') NOT NULL DEFAULT 'fail',
	`provider` varchar(64) NOT NULL,
	`service` varchar(128),
	`region` varchar(64),
	`resource_arn` varchar(512),
	`resource_name` varchar(255),
	`resource_type` varchar(128),
	`check_id` varchar(255),
	`check_title` varchar(512),
	`description` text,
	`risk_details` text,
	`remediation` text,
	`compliance_frameworks` json,
	`categories` json,
	`raw_finding` json,
	`created_at` bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE `cspm_scan_runs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`credential_id` int,
	`engagement_id` int,
	`scan_tool` enum('prowler','scoutsuite','trivy') NOT NULL,
	`scan_provider` enum('aws','azure','gcp','digitalocean','alibaba','oracle','kubernetes','docker','filesystem') NOT NULL,
	`scan_status` enum('pending','running','completed','error','cancelled') NOT NULL DEFAULT 'pending',
	`scan_scope` json,
	`total_findings` int DEFAULT 0,
	`critical_count` int DEFAULT 0,
	`high_count` int DEFAULT 0,
	`medium_count` int DEFAULT 0,
	`low_count` int DEFAULT 0,
	`info_count` int DEFAULT 0,
	`pass_count` int DEFAULT 0,
	`fail_count` int DEFAULT 0,
	`compliance_score` int,
	`compliance_framework` varchar(128),
	`scan_duration_ms` int,
	`raw_output_url` text,
	`error_message` text,
	`triggered_by` varchar(255),
	`scan_started_at` bigint,
	`scan_completed_at` bigint,
	`created_at` bigint NOT NULL
);
--> statement-breakpoint
ALTER TABLE `cloud_credentials` MODIFY COLUMN `cred_provider` enum('aws','azure','gcp','digitalocean','alibaba','oracle') NOT NULL;--> statement-breakpoint
ALTER TABLE `cloud_credentials` MODIFY COLUMN `credential_type` enum('aws_access_key','aws_assume_role','aws_session_token','azure_client_secret','azure_managed_identity','azure_cli','gcp_service_account_key','gcp_workload_identity','gcp_oauth','do_api_token','alibaba_access_key','oracle_api_key') NOT NULL;--> statement-breakpoint
ALTER TABLE `cloud_enumeration_runs` MODIFY COLUMN `enum_provider` enum('aws','azure','gcp','digitalocean','alibaba','oracle') NOT NULL;--> statement-breakpoint
ALTER TABLE `cloud_providers` MODIFY COLUMN `provider` enum('aws','azure','gcp','digitalocean','alibaba','oracle') NOT NULL;--> statement-breakpoint
CREATE INDEX `cv_scan_run_idx` ON `container_vulnerabilities` (`scan_run_id`);--> statement-breakpoint
CREATE INDEX `cv_severity_idx` ON `container_vulnerabilities` (`severity`);--> statement-breakpoint
CREATE INDEX `cv_vuln_id_idx` ON `container_vulnerabilities` (`vuln_id`);--> statement-breakpoint
CREATE INDEX `cv_image_idx` ON `container_vulnerabilities` (`image_name`);--> statement-breakpoint
CREATE INDEX `cspmf_scan_run_idx` ON `cspm_findings` (`scan_run_id`);--> statement-breakpoint
CREATE INDEX `cspmf_severity_idx` ON `cspm_findings` (`severity`);--> statement-breakpoint
CREATE INDEX `cspmf_status_idx` ON `cspm_findings` (`status`);--> statement-breakpoint
CREATE INDEX `cspmf_check_id_idx` ON `cspm_findings` (`check_id`);--> statement-breakpoint
CREATE INDEX `cspmf_provider_idx` ON `cspm_findings` (`provider`);--> statement-breakpoint
CREATE INDEX `cspm_scan_tool_idx` ON `cspm_scan_runs` (`scan_tool`);--> statement-breakpoint
CREATE INDEX `cspm_scan_provider_idx` ON `cspm_scan_runs` (`scan_provider`);--> statement-breakpoint
CREATE INDEX `cspm_scan_status_idx` ON `cspm_scan_runs` (`scan_status`);--> statement-breakpoint
CREATE INDEX `cspm_credential_idx` ON `cspm_scan_runs` (`credential_id`);--> statement-breakpoint
CREATE INDEX `cspm_created_idx` ON `cspm_scan_runs` (`created_at`);