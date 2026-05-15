-- Free DI Scan Lead Generation Tables
-- These support the public free scan flow: form → email verify → scan → results

CREATE TABLE IF NOT EXISTS free_scan_requests (
  id INT AUTO_INCREMENT PRIMARY KEY,
  -- Lead info
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL,
  organization VARCHAR(255),
  job_title VARCHAR(255),
  -- Scan target
  target_domain VARCHAR(255) NOT NULL,
  -- Verification
  verification_token VARCHAR(128) NOT NULL,
  verified_at TIMESTAMP NULL,
  verification_expires_at TIMESTAMP NOT NULL,
  -- Scan linkage
  scan_id INT NULL,
  -- Results access
  results_token VARCHAR(128) NOT NULL,
  results_expires_at TIMESTAMP NOT NULL,
  -- Status tracking
  status ENUM('pending_verification', 'verified', 'scanning', 'completed', 'expired', 'failed') NOT NULL DEFAULT 'pending_verification',
  -- Rate limiting / abuse prevention
  ip_address VARCHAR(45),
  user_agent VARCHAR(512),
  -- Timestamps
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP NOT NULL,
  -- Indexes
  INDEX fsr_email_idx (email),
  INDEX fsr_verification_token_idx (verification_token),
  INDEX fsr_results_token_idx (results_token),
  INDEX fsr_status_idx (status),
  INDEX fsr_created_at_idx (created_at),
  UNIQUE INDEX fsr_verification_token_unique (verification_token),
  UNIQUE INDEX fsr_results_token_unique (results_token)
);
