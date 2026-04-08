/**
 * Nextcloud Bug Bounty Test Lab
 * 
 * Generates Docker Compose configurations and management scripts for deploying
 * a self-hosted Nextcloud test environment with all bounty-eligible apps and
 * supporting services (MariaDB, Redis, Collabora, ClamAV, OpenLDAP, Coturn,
 * MinIO, Mailhog, Keycloak).
 * 
 * Designed to comply with Nextcloud HackerOne program requirements:
 * - All testing on self-hosted instances only
 * - No automated scanning against Nextcloud-operated servers
 * - No cloud-based AI/LLM services for report generation
 * - Only current supported server versions
 * - Must include version numbers in all findings
 */

// ─── Nextcloud Version Config ───────────────────────────────────────────────
export const NEXTCLOUD_VERSIONS = {
  latest: '30.0.6',
  supported: ['30.0.6', '29.0.12', '28.0.14'],
  hub: 'Hub 10',
  phpVersion: '8.3',
} as const;

// ─── Bounty-Eligible Apps ───────────────────────────────────────────────────
// All 61 SOURCE_CODE assets from HackerOne scope that are bounty-eligible
export const BOUNTY_ELIGIBLE_APPS = [
  // Tier 1 - High Value (core security-sensitive)
  { name: 'server', repo: 'nextcloud/server', tier: 1, description: 'Core server', builtIn: true },
  { name: 'files_antivirus', repo: 'nextcloud/files_antivirus', tier: 1, description: 'Antivirus integration' },
  { name: 'end_to_end_encryption', repo: 'nextcloud/end_to_end_encryption', tier: 1, description: 'E2E encryption' },
  { name: 'user_saml', repo: 'nextcloud/user_saml', tier: 1, description: 'SAML authentication' },
  { name: 'user_oidc', repo: 'nextcloud/user_oidc', tier: 1, description: 'OpenID Connect auth' },
  { name: 'twofactor_totp', repo: 'nextcloud/twofactor_totp', tier: 1, description: 'TOTP 2FA' },
  { name: 'twofactor_webauthn', repo: 'nextcloud/twofactor_webauthn', tier: 1, description: 'WebAuthn 2FA' },
  { name: 'password_policy', repo: 'nextcloud/password_policy', tier: 1, description: 'Password policy enforcement' },
  { name: 'bruteforcesettings', repo: 'nextcloud/bruteforcesettings', tier: 1, description: 'Brute force protection settings' },
  { name: 'suspicious_login', repo: 'nextcloud/suspicious_login', tier: 1, description: 'Suspicious login detection' },
  { name: 'files_accesscontrol', repo: 'nextcloud/files_accesscontrol', tier: 1, description: 'File access control rules' },

  // Tier 2 - Collaboration & Sharing (high attack surface)
  { name: 'spreed', repo: 'nextcloud/spreed', tier: 2, description: 'Nextcloud Talk' },
  { name: 'mail', repo: 'nextcloud/mail', tier: 2, description: 'Mail client' },
  { name: 'richdocuments', repo: 'nextcloud/richdocuments', tier: 2, description: 'Collabora Office integration' },
  { name: 'deck', repo: 'nextcloud/deck', tier: 2, description: 'Kanban board' },
  { name: 'groupfolders', repo: 'nextcloud/groupfolders', tier: 2, description: 'Group folders' },
  { name: 'guests', repo: 'nextcloud/guests', tier: 2, description: 'Guest accounts' },
  { name: 'circles', repo: 'nextcloud/circles', tier: 2, description: 'Custom groups/circles' },
  { name: 'sharepoint', repo: 'nextcloud/sharepoint', tier: 2, description: 'SharePoint integration' },
  { name: 'globalsiteselector', repo: 'nextcloud/globalsiteselector', tier: 2, description: 'Global site selector' },
  { name: 'socialsharing', repo: 'nextcloud/socialsharing', tier: 2, description: 'Social sharing' },

  // Tier 3 - PIM & Productivity
  { name: 'calendar', repo: 'nextcloud/calendar', tier: 3, description: 'Calendar' },
  { name: 'contacts', repo: 'nextcloud/contacts', tier: 3, description: 'Contacts' },
  { name: 'calendar_resource_management', repo: 'nextcloud/calendar_resource_management', tier: 3, description: 'Calendar resource management' },
  { name: 'notes', repo: 'nextcloud/notes', tier: 3, description: 'Notes' },
  { name: 'text', repo: 'nextcloud/text', tier: 3, description: 'Rich text editor' },
  { name: 'collectives', repo: 'nextcloud/collectives', tier: 3, description: 'Knowledge management' },
  { name: 'tables', repo: 'nextcloud/tables', tier: 3, description: 'Tables/spreadsheets' },

  // Tier 4 - Files & Storage
  { name: 'files_retention', repo: 'nextcloud/files_retention', tier: 4, description: 'File retention policies' },
  { name: 'files_automatedtagging', repo: 'nextcloud/files_automatedtagging', tier: 4, description: 'Automated file tagging' },
  { name: 'files_lock', repo: 'nextcloud/files_lock', tier: 4, description: 'File locking' },
  { name: 'files_pdfviewer', repo: 'nextcloud/files_pdfviewer', tier: 4, description: 'PDF viewer' },
  { name: 'files_rightclick', repo: 'nextcloud/files_rightclick', tier: 4, description: 'Right-click menu' },
  { name: 'files_texteditor', repo: 'nextcloud/files_texteditor', tier: 4, description: 'Text editor' },
  { name: 'files_fulltextsearch', repo: 'nextcloud/files_fulltextsearch', tier: 4, description: 'Full text search' },
  { name: 'files_fulltextsearch_tesseract', repo: 'nextcloud/files_fulltextsearch_tesseract', tier: 4, description: 'OCR search' },
  { name: 'files_confidential', repo: 'nextcloud/files_confidential', tier: 4, description: 'Confidential files' },
  { name: 'photos', repo: 'nextcloud/photos', tier: 4, description: 'Photos' },

  // Tier 5 - Search & Indexing
  { name: 'fulltextsearch', repo: 'nextcloud/fulltextsearch', tier: 5, description: 'Full text search framework' },
  { name: 'fulltextsearch_elasticsearch', repo: 'nextcloud/fulltextsearch_elasticsearch', tier: 5, description: 'Elasticsearch provider' },

  // Tier 6 - System & Admin
  { name: 'updater', repo: 'nextcloud/updater', tier: 6, description: 'Updater' },
  { name: 'serverinfo', repo: 'nextcloud/serverinfo', tier: 6, description: 'Server info' },
  { name: 'logreader', repo: 'nextcloud/logreader', tier: 6, description: 'Log reader' },
  { name: 'notifications', repo: 'nextcloud/notifications', tier: 6, description: 'Notifications' },
  { name: 'notify_push', repo: 'nextcloud/notify_push', tier: 6, description: 'Push notifications' },
  { name: 'nextcloud_announcements', repo: 'nextcloud/nextcloud_announcements', tier: 6, description: 'Announcements' },
  { name: 'survey_client', repo: 'nextcloud/survey_client', tier: 6, description: 'Survey client' },
  { name: 'user_migration', repo: 'nextcloud/user_migration', tier: 6, description: 'User migration' },
  { name: 'data_request', repo: 'nextcloud/data_request', tier: 6, description: 'GDPR data request' },
  { name: 'privacy', repo: 'nextcloud/privacy', tier: 6, description: 'Privacy settings' },
  { name: 'terms_of_service', repo: 'nextcloud/terms_of_service', tier: 6, description: 'Terms of service' },

  // Tier 7 - Workflow & Automation
  { name: 'approval', repo: 'nextcloud/approval', tier: 7, description: 'Approval workflows' },
  { name: 'workflow_script', repo: 'nextcloud/workflow_script', tier: 7, description: 'Workflow scripts' },
  { name: 'flow_notifications', repo: 'nextcloud/flow_notifications', tier: 7, description: 'Flow notifications' },

  // Tier 8 - UI & Misc
  { name: 'viewer', repo: 'nextcloud/viewer', tier: 8, description: 'File viewer' },
  { name: 'firstrunwizard', repo: 'nextcloud/firstrunwizard', tier: 8, description: 'First run wizard' },
  { name: 'recommendations', repo: 'nextcloud/recommendations', tier: 8, description: 'File recommendations' },
  { name: 'related_resources', repo: 'nextcloud/related_resources', tier: 8, description: 'Related resources' },
  { name: 'external', repo: 'nextcloud/external', tier: 8, description: 'External sites' },
  { name: 'preferred_providers', repo: 'nextcloud/preferred_providers', tier: 8, description: 'Preferred providers' },
  { name: 'activity', repo: 'nextcloud/activity', tier: 8, description: 'Activity feed' },

  // Libraries
  { name: '3rdparty', repo: 'nextcloud/3rdparty', tier: 9, description: '3rd party libraries', builtIn: true },
] as const;

// ─── Docker Compose Configuration ───────────────────────────────────────────

export interface TestLabConfig {
  nextcloudVersion: string;
  adminUser: string;
  adminPassword: string;
  labName: string;
  hostPort: number;
  enableCollabora: boolean;
  enableClamAV: boolean;
  enableLDAP: boolean;
  enableKeycloak: boolean;
  enableElasticsearch: boolean;
  enableMinIO: boolean;
  enableMailhog: boolean;
  enableCoturn: boolean;
  scanServerHost?: string; // External host where lab runs (for remote deployment)
}

export const DEFAULT_LAB_CONFIG: TestLabConfig = {
  nextcloudVersion: NEXTCLOUD_VERSIONS.latest,
  adminUser: 'admin',
  adminPassword: 'AC3-TestLab-2026!',
  labName: 'nc-bugbounty-lab',
  hostPort: 8443,
  enableCollabora: true,
  enableClamAV: true,
  enableLDAP: true,
  enableKeycloak: true,
  enableElasticsearch: true,
  enableMinIO: true,
  enableMailhog: true,
  enableCoturn: true,
};

export function generateDockerCompose(config: TestLabConfig = DEFAULT_LAB_CONFIG): string {
  const services: Record<string, any> = {};

  // ── Core: Nextcloud + MariaDB + Redis ──
  services.db = {
    image: 'mariadb:11.4',
    container_name: `${config.labName}-db`,
    restart: 'unless-stopped',
    environment: {
      MYSQL_ROOT_PASSWORD: 'nc-root-pw-2026',
      MYSQL_DATABASE: 'nextcloud',
      MYSQL_USER: 'nextcloud',
      MYSQL_PASSWORD: 'nc-db-pw-2026',
    },
    volumes: ['db_data:/var/lib/mysql'],
    networks: ['nc-lab'],
    healthcheck: {
      test: ['CMD', 'healthcheck.sh', '--connect', '--innodb_initialized'],
      interval: '10s',
      timeout: '5s',
      retries: 5,
    },
  };

  services.redis = {
    image: 'redis:7-alpine',
    container_name: `${config.labName}-redis`,
    restart: 'unless-stopped',
    networks: ['nc-lab'],
    healthcheck: {
      test: ['CMD', 'redis-cli', 'ping'],
      interval: '10s',
      timeout: '5s',
      retries: 5,
    },
  };

  services.nextcloud = {
    image: `nextcloud:${config.nextcloudVersion}-apache`,
    container_name: `${config.labName}-app`,
    restart: 'unless-stopped',
    depends_on: {
      db: { condition: 'service_healthy' },
      redis: { condition: 'service_healthy' },
    },
    ports: [`${config.hostPort}:80`],
    environment: {
      MYSQL_HOST: 'db',
      MYSQL_DATABASE: 'nextcloud',
      MYSQL_USER: 'nextcloud',
      MYSQL_PASSWORD: 'nc-db-pw-2026',
      NEXTCLOUD_ADMIN_USER: config.adminUser,
      NEXTCLOUD_ADMIN_PASSWORD: config.adminPassword,
      REDIS_HOST: 'redis',
      NEXTCLOUD_TRUSTED_DOMAINS: `localhost ${config.scanServerHost || 'localhost'}`,
      OVERWRITEPROTOCOL: 'http',
      PHP_MEMORY_LIMIT: '1G',
      PHP_UPLOAD_LIMIT: '16G',
    },
    volumes: [
      'nc_data:/var/www/html',
      'nc_custom_apps:/var/www/html/custom_apps',
      'nc_config:/var/www/html/config',
      'nc_themes:/var/www/html/themes',
    ],
    networks: ['nc-lab'],
    healthcheck: {
      test: ['CMD', 'curl', '-f', 'http://localhost/status.php'],
      interval: '30s',
      timeout: '10s',
      retries: 10,
      start_period: '120s',
    },
  };

  services.cron = {
    image: `nextcloud:${config.nextcloudVersion}-apache`,
    container_name: `${config.labName}-cron`,
    restart: 'unless-stopped',
    depends_on: ['nextcloud'],
    volumes: [
      'nc_data:/var/www/html',
      'nc_custom_apps:/var/www/html/custom_apps',
      'nc_config:/var/www/html/config',
    ],
    entrypoint: '/cron.sh',
    networks: ['nc-lab'],
  };

  // ── Collabora Online ──
  if (config.enableCollabora) {
    services.collabora = {
      image: 'collabora/code:latest',
      container_name: `${config.labName}-collabora`,
      restart: 'unless-stopped',
      environment: {
        aliasgroup1: `http://${config.labName}-app:80`,
        extra_params: '--o:ssl.enable=false --o:ssl.termination=false',
        username: 'admin',
        password: 'collabora-pw-2026',
      },
      cap_add: ['MKNOD'],
      networks: ['nc-lab'],
    };
  }

  // ── ClamAV ──
  if (config.enableClamAV) {
    services.clamav = {
      image: 'clamav/clamav:1.4',
      container_name: `${config.labName}-clamav`,
      restart: 'unless-stopped',
      volumes: ['clamav_data:/var/lib/clamav'],
      networks: ['nc-lab'],
      healthcheck: {
        test: ['CMD', '/usr/local/bin/clamdcheck.sh'],
        interval: '60s',
        timeout: '10s',
        retries: 3,
        start_period: '120s',
      },
    };
  }

  // ── OpenLDAP ──
  if (config.enableLDAP) {
    services.openldap = {
      image: 'osixia/openldap:1.5.0',
      container_name: `${config.labName}-ldap`,
      restart: 'unless-stopped',
      environment: {
        LDAP_ORGANISATION: 'AC3 Test Lab',
        LDAP_DOMAIN: 'ac3-testlab.local',
        LDAP_ADMIN_PASSWORD: 'ldap-admin-2026',
        LDAP_READONLY_USER: 'true',
        LDAP_READONLY_USER_USERNAME: 'readonly',
        LDAP_READONLY_USER_PASSWORD: 'ldap-readonly-2026',
      },
      volumes: ['ldap_data:/var/lib/ldap', 'ldap_config:/etc/ldap/slapd.d'],
      networks: ['nc-lab'],
    };

    services.phpldapadmin = {
      image: 'osixia/phpLDAPadmin:0.9.0',
      container_name: `${config.labName}-ldapadmin`,
      restart: 'unless-stopped',
      environment: {
        PHPLDAPADMIN_LDAP_HOSTS: 'openldap',
        PHPLDAPADMIN_HTTPS: 'false',
      },
      ports: [`${config.hostPort + 1}:80`],
      depends_on: ['openldap'],
      networks: ['nc-lab'],
    };
  }

  // ── Keycloak (OIDC/SAML IdP) ──
  if (config.enableKeycloak) {
    services.keycloak = {
      image: 'quay.io/keycloak/keycloak:26.0',
      container_name: `${config.labName}-keycloak`,
      restart: 'unless-stopped',
      command: 'start-dev',
      environment: {
        KC_DB: 'mariadb',
        KC_DB_URL: 'jdbc:mariadb://db:3306/keycloak',
        KC_DB_USERNAME: 'root',
        KC_DB_PASSWORD: 'nc-root-pw-2026',
        KEYCLOAK_ADMIN: 'admin',
        KEYCLOAK_ADMIN_PASSWORD: 'keycloak-admin-2026',
        KC_PROXY: 'edge',
        KC_HTTP_RELATIVE_PATH: '/auth',
      },
      ports: [`${config.hostPort + 2}:8080`],
      depends_on: { db: { condition: 'service_healthy' } },
      networks: ['nc-lab'],
    };
  }

  // ── MinIO (S3-compatible object storage) ──
  if (config.enableMinIO) {
    services.minio = {
      image: 'minio/minio:latest',
      container_name: `${config.labName}-minio`,
      restart: 'unless-stopped',
      command: 'server /data --console-address ":9001"',
      environment: {
        MINIO_ROOT_USER: 'minioadmin',
        MINIO_ROOT_PASSWORD: 'minio-pw-2026',
      },
      ports: [`${config.hostPort + 3}:9000`, `${config.hostPort + 4}:9001`],
      volumes: ['minio_data:/data'],
      networks: ['nc-lab'],
    };
  }

  // ── Mailhog (SMTP testing) ──
  if (config.enableMailhog) {
    services.mailhog = {
      image: 'mailhog/mailhog:latest',
      container_name: `${config.labName}-mailhog`,
      restart: 'unless-stopped',
      ports: [`${config.hostPort + 5}:8025`],
      networks: ['nc-lab'],
    };
  }

  // ── Coturn (TURN server for Talk) ──
  if (config.enableCoturn) {
    services.coturn = {
      image: 'coturn/coturn:latest',
      container_name: `${config.labName}-coturn`,
      restart: 'unless-stopped',
      network_mode: 'host',
      command: [
        '-n',
        '--log-file=stdout',
        '--min-port=49160',
        '--max-port=49200',
        '--use-auth-secret',
        '--static-auth-secret=coturn-secret-2026',
        '--realm=ac3-testlab.local',
      ],
    };
  }

  // ── Elasticsearch (for full text search) ──
  if (config.enableElasticsearch) {
    services.elasticsearch = {
      image: 'docker.elastic.co/elasticsearch/elasticsearch:8.15.0',
      container_name: `${config.labName}-elasticsearch`,
      restart: 'unless-stopped',
      environment: {
        'discovery.type': 'single-node',
        'xpack.security.enabled': 'false',
        'ES_JAVA_OPTS': '-Xms512m -Xmx512m',
      },
      volumes: ['es_data:/usr/share/elasticsearch/data'],
      networks: ['nc-lab'],
      healthcheck: {
        test: ['CMD-SHELL', 'curl -f http://localhost:9200/_cluster/health || exit 1'],
        interval: '30s',
        timeout: '10s',
        retries: 5,
        start_period: '60s',
      },
    };
  }

  // ── Volumes ──
  const volumes: Record<string, any> = {
    db_data: {},
    nc_data: {},
    nc_custom_apps: {},
    nc_config: {},
    nc_themes: {},
  };
  if (config.enableClamAV) volumes.clamav_data = {};
  if (config.enableLDAP) { volumes.ldap_data = {}; volumes.ldap_config = {}; }
  if (config.enableMinIO) volumes.minio_data = {};
  if (config.enableElasticsearch) volumes.es_data = {};

  const compose = {
    version: '3.8',
    services,
    volumes,
    networks: {
      'nc-lab': {
        driver: 'bridge',
      },
    },
  };

  return formatYaml(compose);
}

// ─── App Installation Script ────────────────────────────────────────────────

export function generateAppInstallScript(config: TestLabConfig = DEFAULT_LAB_CONFIG): string {
  const installableApps = BOUNTY_ELIGIBLE_APPS.filter(a => !a.builtIn);
  
  const lines = [
    '#!/bin/bash',
    '# Nextcloud Bug Bounty Test Lab - App Installer',
    '# Installs all 61 bounty-eligible apps from the HackerOne scope',
    `# Generated for Nextcloud ${config.nextcloudVersion}`,
    '',
    'set -e',
    '',
    `CONTAINER="${config.labName}-app"`,
    'OCC="docker exec -u www-data $CONTAINER php occ"',
    '',
    '# Wait for Nextcloud to be ready',
    'echo "Waiting for Nextcloud to be ready..."',
    'until docker exec $CONTAINER curl -sf http://localhost/status.php > /dev/null 2>&1; do',
    '  sleep 5',
    '  echo "  Still waiting..."',
    'done',
    'echo "Nextcloud is ready!"',
    '',
    '# Enable maintenance mode during bulk install',
    '$OCC maintenance:mode --on',
    '',
    'echo ""',
    'echo "=== Installing Bounty-Eligible Apps ==="',
    'echo ""',
    '',
    'INSTALLED=0',
    'FAILED=0',
    'SKIPPED=0',
    '',
  ];

  // Group by tier for organized installation
  const tiers = new Map<number, typeof installableApps>();
  for (const app of installableApps) {
    const tier = tiers.get(app.tier) || [];
    tier.push(app);
    tiers.set(app.tier, tier);
  }

  const tierNames: Record<number, string> = {
    1: 'Security & Authentication',
    2: 'Collaboration & Sharing',
    3: 'PIM & Productivity',
    4: 'Files & Storage',
    5: 'Search & Indexing',
    6: 'System & Admin',
    7: 'Workflow & Automation',
    8: 'UI & Miscellaneous',
  };

  for (const [tier, apps] of [...tiers.entries()].sort((a, b) => a[0] - b[0])) {
    if (tier >= 9) continue; // Skip built-in/library tier
    lines.push(`echo "--- Tier ${tier}: ${tierNames[tier] || 'Other'} ---"`);
    for (const app of apps) {
      lines.push(`if $OCC app:install ${app.name} 2>/dev/null; then`);
      lines.push(`  echo "  ✓ ${app.name} (${app.description})"`);
      lines.push(`  ((INSTALLED++))`);
      lines.push(`elif $OCC app:enable ${app.name} 2>/dev/null; then`);
      lines.push(`  echo "  ✓ ${app.name} (already installed, enabled)"`);
      lines.push(`  ((SKIPPED++))`);
      lines.push(`else`);
      lines.push(`  echo "  ✗ ${app.name} (failed or not available for this version)"`);
      lines.push(`  ((FAILED++))`);
      lines.push(`fi`);
    }
    lines.push('');
  }

  lines.push(
    '# Disable maintenance mode',
    '$OCC maintenance:mode --off',
    '',
    '# Run upgrade to ensure all apps are properly configured',
    '$OCC upgrade',
    '$OCC db:add-missing-indices',
    '$OCC db:add-missing-columns',
    '$OCC db:add-missing-primary-keys',
    '',
    'echo ""',
    'echo "=== Installation Summary ==="',
    'echo "  Installed: $INSTALLED"',
    'echo "  Skipped (already present): $SKIPPED"',
    'echo "  Failed: $FAILED"',
    'echo ""',
    '',
    '# List all enabled apps',
    'echo "=== Enabled Apps ==="',
    '$OCC app:list --enabled',
  );

  return lines.join('\n');
}

// ─── Test User Provisioning Script ──────────────────────────────────────────

export function generateUserProvisioningScript(config: TestLabConfig = DEFAULT_LAB_CONFIG): string {
  const lines = [
    '#!/bin/bash',
    '# Nextcloud Bug Bounty Test Lab - User Provisioning',
    '# Creates test users for various attack scenarios',
    '',
    'set -e',
    '',
    `CONTAINER="${config.labName}-app"`,
    'OCC="docker exec -u www-data $CONTAINER php occ"',
    '',
    'echo "=== Provisioning Test Users ==="',
    '',
    '# Regular test users (for IDOR, privilege escalation, sharing tests)',
    'for i in 1 2 3 4 5; do',
    '  export OC_PASS="TestUser${i}Pass2026!"',
    '  $OCC user:add --password-from-env --display-name "Test User ${i}" "testuser${i}" 2>/dev/null || echo "  testuser${i} already exists"',
    '  echo "  ✓ testuser${i} created"',
    'done',
    '',
    '# Share-specific test users',
    'export OC_PASS="ShareUser1Pass2026!"',
    '$OCC user:add --password-from-env --display-name "Share User 1" "shareuser1" 2>/dev/null || echo "  shareuser1 already exists"',
    'export OC_PASS="ShareUser2Pass2026!"',
    '$OCC user:add --password-from-env --display-name "Share User 2" "shareuser2" 2>/dev/null || echo "  shareuser2 already exists"',
    '',
    '# Encryption test user',
    'export OC_PASS="EncUserPass2026!"',
    '$OCC user:add --password-from-env --display-name "Encryption User" "encuser" 2>/dev/null || echo "  encuser already exists"',
    '',
    '# Group admin user',
    'export OC_PASS="GroupAdminPass2026!"',
    '$OCC user:add --password-from-env --display-name "Group Admin" "groupadmin" 2>/dev/null || echo "  groupadmin already exists"',
    '',
    '# Create test groups',
    '$OCC group:add "testers" 2>/dev/null || true',
    '$OCC group:add "developers" 2>/dev/null || true',
    '$OCC group:add "managers" 2>/dev/null || true',
    '$OCC group:add "external" 2>/dev/null || true',
    '',
    '# Assign users to groups',
    '$OCC group:adduser "testers" "testuser1"',
    '$OCC group:adduser "testers" "testuser2"',
    '$OCC group:adduser "developers" "testuser3"',
    '$OCC group:adduser "developers" "testuser4"',
    '$OCC group:adduser "managers" "testuser5"',
    '$OCC group:adduser "managers" "groupadmin"',
    '',
    '# Make groupadmin a group admin for "testers"',
    '$OCC group:adduser "testers" "groupadmin"',
    '',
    '# Create shared folders for testing',
    'echo ""',
    'echo "=== Creating Test Data ==="',
    'docker exec -u www-data $CONTAINER mkdir -p /var/www/html/data/testuser1/files/SharedDocs',
    'docker exec -u www-data $CONTAINER mkdir -p /var/www/html/data/testuser1/files/PrivateDocs',
    'docker exec -u www-data $CONTAINER bash -c \'echo "Confidential test document" > /var/www/html/data/testuser1/files/PrivateDocs/secret.txt\'',
    'docker exec -u www-data $CONTAINER bash -c \'echo "Shared test document" > /var/www/html/data/testuser1/files/SharedDocs/readme.txt\'',
    '',
    '# Rescan files',
    '$OCC files:scan --all',
    '',
    'echo ""',
    'echo "=== Test Users Summary ==="',
    'echo "  admin / ' + config.adminPassword + '"',
    'echo "  testuser1-5 / TestUser{N}Pass2026!"',
    'echo "  shareuser1-2 / ShareUser{N}Pass2026!"',
    'echo "  encuser / EncUserPass2026!"',
    'echo "  groupadmin / GroupAdminPass2026!"',
    'echo ""',
    'echo "  Groups: testers, developers, managers, external"',
    '',
  ];

  return lines.join('\n');
}

// ─── LDAP User Seeding Script ───────────────────────────────────────────────

export function generateLdapSeedScript(config: TestLabConfig = DEFAULT_LAB_CONFIG): string {
  return `#!/bin/bash
# Nextcloud Bug Bounty Test Lab - LDAP User Seeding
# Seeds LDAP directory with test users for user_saml and LDAP auth testing

set -e

CONTAINER="${config.labName}-ldap"

echo "=== Seeding LDAP Test Users ==="

# Add organizational units
docker exec $CONTAINER ldapadd -x -D "cn=admin,dc=ac3-testlab,dc=local" -w "ldap-admin-2026" <<EOF
dn: ou=People,dc=ac3-testlab,dc=local
objectClass: organizationalUnit
ou: People

dn: ou=Groups,dc=ac3-testlab,dc=local
objectClass: organizationalUnit
ou: Groups
EOF

# Add LDAP test users
for i in 1 2 3; do
  docker exec $CONTAINER ldapadd -x -D "cn=admin,dc=ac3-testlab,dc=local" -w "ldap-admin-2026" <<EOF
dn: uid=ldapuser\${i},ou=People,dc=ac3-testlab,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: ldapuser\${i}
sn: User\${i}
givenName: LDAP
cn: LDAP User \${i}
displayName: LDAP User \${i}
uidNumber: 100\${i}
gidNumber: 5000
userPassword: LdapUser\${i}Pass2026!
homeDirectory: /home/ldapuser\${i}
mail: ldapuser\${i}@ac3-testlab.local
EOF
  echo "  ✓ ldapuser\${i} created"
done

echo ""
echo "=== LDAP Users ==="
echo "  ldapuser1-3 / LdapUser{N}Pass2026!"
echo "  LDAP Admin: cn=admin,dc=ac3-testlab,dc=local / ldap-admin-2026"
echo "  LDAP Readonly: readonly / ldap-readonly-2026"
`;
}

// ─── Nextcloud Configuration Script ─────────────────────────────────────────

export function generateConfigScript(config: TestLabConfig = DEFAULT_LAB_CONFIG): string {
  const lines = [
    '#!/bin/bash',
    '# Nextcloud Bug Bounty Test Lab - Post-Install Configuration',
    '# Configures all services for testing',
    '',
    'set -e',
    '',
    `CONTAINER="${config.labName}-app"`,
    'OCC="docker exec -u www-data $CONTAINER php occ"',
    '',
    'echo "=== Configuring Nextcloud for Bug Bounty Testing ==="',
    '',
    '# Enable debug mode for detailed error messages',
    '$OCC config:system:set debug --value=true --type=boolean',
    '',
    '# Configure Redis for caching and locking',
    '$OCC config:system:set memcache.local --value="\\OC\\Memcache\\Redis"',
    '$OCC config:system:set memcache.distributed --value="\\OC\\Memcache\\Redis"',
    '$OCC config:system:set memcache.locking --value="\\OC\\Memcache\\Redis"',
    '$OCC config:system:set redis host --value="redis"',
    '$OCC config:system:set redis port --value=6379 --type=integer',
    '',
    '# Configure mail (Mailhog)',
  ];

  if (config.enableMailhog) {
    lines.push(
      '$OCC config:system:set mail_smtpmode --value="smtp"',
      '$OCC config:system:set mail_smtphost --value="mailhog"',
      '$OCC config:system:set mail_smtpport --value=1025 --type=integer',
      '$OCC config:system:set mail_from_address --value="admin"',
      '$OCC config:system:set mail_domain --value="ac3-testlab.local"',
    );
  }

  if (config.enableClamAV) {
    lines.push(
      '',
      '# Configure ClamAV',
      '$OCC config:app:set files_antivirus av_mode --value="socket"',
      '$OCC config:app:set files_antivirus av_socket --value="/var/run/clamav/clamd.ctl"',
    );
  }

  if (config.enableCollabora) {
    lines.push(
      '',
      '# Configure Collabora',
      '$OCC config:app:set richdocuments wopi_url --value="http://collabora:9980"',
      '$OCC config:app:set richdocuments wopi_allowlist --value="0.0.0.0/0"',
    );
  }

  if (config.enableCoturn) {
    lines.push(
      '',
      '# Configure TURN server for Talk',
      '$OCC config:app:set spreed turn_servers --value=\'[{"schemes":"turn,turns","server":"' + (config.scanServerHost || 'localhost') + ':3478","secret":"coturn-secret-2026","protocols":"udp,tcp"}]\'',
    );
  }

  lines.push(
    '',
    '# Security headers for testing',
    '$OCC config:system:set overwrite.cli.url --value="http://localhost:' + config.hostPort + '"',
    '',
    '# Enable all logging for security testing',
    '$OCC config:system:set loglevel --value=0 --type=integer',
    '$OCC config:system:set log_type --value="file"',
    '',
    '# Disable rate limiting for testing (allows brute force testing)',
    '$OCC config:system:set ratelimit.protection.enabled --value=false --type=boolean',
    '',
    '# Enable CORS for API testing',
    '$OCC config:system:set cors.allowed-domains 0 --value="*"',
    '',
    '# Print version info',
    'echo ""',
    'echo "=== Nextcloud Version ==="',
    '$OCC status',
    'echo ""',
    'echo "=== Enabled Apps ==="',
    '$OCC app:list --enabled | head -80',
    'echo ""',
    'echo "=== Test Lab Ready ==="',
    `echo "  URL: http://localhost:${config.hostPort}"`,
    `echo "  Admin: ${config.adminUser} / ${config.adminPassword}"`,
  );

  if (config.enableCollabora) {
    lines.push(`echo "  Collabora: http://localhost:${config.hostPort} (proxied)"`);
  }
  if (config.enableLDAP) {
    lines.push(`echo "  phpLDAPadmin: http://localhost:${config.hostPort + 1}"`);
  }
  if (config.enableKeycloak) {
    lines.push(`echo "  Keycloak: http://localhost:${config.hostPort + 2}/auth"`);
  }
  if (config.enableMinIO) {
    lines.push(`echo "  MinIO Console: http://localhost:${config.hostPort + 4}"`);
  }
  if (config.enableMailhog) {
    lines.push(`echo "  Mailhog: http://localhost:${config.hostPort + 5}"`);
  }

  return lines.join('\n');
}

// ─── Full Deployment Script ─────────────────────────────────────────────────

export function generateFullDeployScript(config: TestLabConfig = DEFAULT_LAB_CONFIG): string {
  return `#!/bin/bash
# Nextcloud Bug Bounty Test Lab - Full Deployment
# Deploys all services, installs apps, provisions users, configures settings

set -e

SCRIPT_DIR="$(cd "$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
LAB_NAME="${config.labName}"

echo "╔══════════════════════════════════════════════════════╗"
echo "║  AC3 Nextcloud Bug Bounty Test Lab                  ║"
echo "║  Version: ${config.nextcloudVersion}                              ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# Step 1: Deploy containers
echo "Step 1/5: Deploying containers..."
docker compose -f "\${SCRIPT_DIR}/docker-compose.yml" -p "$LAB_NAME" up -d
echo "  ✓ Containers started"

# Step 2: Wait for Nextcloud
echo ""
echo "Step 2/5: Waiting for Nextcloud to initialize (this may take 2-3 minutes)..."
TIMEOUT=300
ELAPSED=0
until docker exec ${config.labName}-app curl -sf http://localhost/status.php > /dev/null 2>&1; do
  sleep 10
  ELAPSED=$((ELAPSED + 10))
  if [ $ELAPSED -ge $TIMEOUT ]; then
    echo "  ✗ Timeout waiting for Nextcloud"
    exit 1
  fi
  echo "  Waiting... ($ELAPSED/$TIMEOUT seconds)"
done
echo "  ✓ Nextcloud is ready"

# Step 3: Install apps
echo ""
echo "Step 3/5: Installing bounty-eligible apps..."
bash "\${SCRIPT_DIR}/install-apps.sh"

# Step 4: Provision users
echo ""
echo "Step 4/5: Provisioning test users..."
bash "\${SCRIPT_DIR}/provision-users.sh"
${config.enableLDAP ? `\n# Seed LDAP users\nbash "\${SCRIPT_DIR}/seed-ldap-users.sh"` : ''}

# Step 5: Configure services
echo ""
echo "Step 5/5: Configuring services..."
bash "\${SCRIPT_DIR}/configure.sh"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  Test Lab Deployment Complete!                      ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "Access Points:"
echo "  Nextcloud:    http://localhost:${config.hostPort}"
${config.enableLDAP ? `echo "  phpLDAPadmin: http://localhost:${config.hostPort + 1}"` : ''}
${config.enableKeycloak ? `echo "  Keycloak:     http://localhost:${config.hostPort + 2}/auth"` : ''}
${config.enableMinIO ? `echo "  MinIO:        http://localhost:${config.hostPort + 4}"` : ''}
${config.enableMailhog ? `echo "  Mailhog:      http://localhost:${config.hostPort + 5}"` : ''}
echo ""
echo "Credentials:"
echo "  NC Admin:     ${config.adminUser} / ${config.adminPassword}"
echo "  Test Users:   testuser1-5 / TestUser{N}Pass2026!"
echo "  Share Users:  shareuser1-2 / ShareUser{N}Pass2026!"
echo "  Enc User:     encuser / EncUserPass2026!"
echo "  Group Admin:  groupadmin / GroupAdminPass2026!"
${config.enableLDAP ? 'echo "  LDAP Users:   ldapuser1-3 / LdapUser{N}Pass2026!"' : ''}
${config.enableKeycloak ? 'echo "  Keycloak:     admin / keycloak-admin-2026"' : ''}
${config.enableMinIO ? 'echo "  MinIO:        minioadmin / minio-pw-2026"' : ''}
`;
}

// ─── Status Check Script ────────────────────────────────────────────────────

export function generateStatusScript(config: TestLabConfig = DEFAULT_LAB_CONFIG): string {
  return `#!/bin/bash
# Nextcloud Bug Bounty Test Lab - Status Check

LAB_NAME="${config.labName}"
CONTAINER="${config.labName}-app"
OCC="docker exec -u www-data $CONTAINER php occ"

echo "=== Container Status ==="
docker compose -p "$LAB_NAME" ps 2>/dev/null || docker ps --filter "name=$LAB_NAME" --format "table {{.Names}}\\t{{.Status}}\\t{{.Ports}}"

echo ""
echo "=== Nextcloud Status ==="
$OCC status 2>/dev/null || echo "  Nextcloud container not running"

echo ""
echo "=== Enabled Apps (count) ==="
$OCC app:list --enabled 2>/dev/null | grep -c "- " || echo "  Unable to count apps"

echo ""
echo "=== User Count ==="
$OCC user:list 2>/dev/null | wc -l || echo "  Unable to count users"

echo ""
echo "=== Disk Usage ==="
docker exec $CONTAINER du -sh /var/www/html/data 2>/dev/null || echo "  Unable to check"
`;
}

// ─── Teardown Script ────────────────────────────────────────────────────────

export function generateTeardownScript(config: TestLabConfig = DEFAULT_LAB_CONFIG): string {
  return `#!/bin/bash
# Nextcloud Bug Bounty Test Lab - Teardown

LAB_NAME="${config.labName}"

echo "=== Tearing Down Test Lab ==="
echo "WARNING: This will destroy all test data!"
echo ""

read -p "Are you sure? (y/N) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
  docker compose -p "$LAB_NAME" down -v --remove-orphans 2>/dev/null || true
  echo "  ✓ Containers and volumes removed"
else
  echo "  Cancelled"
fi
`;
}

// ─── Test Lab Info for Engagement ───────────────────────────────────────────

export interface TestLabInfo {
  labUrl: string;
  adminCredentials: { user: string; password: string };
  testUsers: Array<{ username: string; password: string; role: string }>;
  services: Array<{ name: string; url: string; description: string }>;
  nextcloudVersion: string;
  installedApps: number;
  complianceNotes: string[];
}

export function getTestLabInfo(config: TestLabConfig = DEFAULT_LAB_CONFIG): TestLabInfo {
  const host = config.scanServerHost || 'localhost';
  const services: TestLabInfo['services'] = [
    { name: 'Nextcloud', url: `http://${host}:${config.hostPort}`, description: 'Main Nextcloud instance' },
  ];

  if (config.enableLDAP) {
    services.push({ name: 'phpLDAPadmin', url: `http://${host}:${config.hostPort + 1}`, description: 'LDAP management' });
  }
  if (config.enableKeycloak) {
    services.push({ name: 'Keycloak', url: `http://${host}:${config.hostPort + 2}/auth`, description: 'OIDC/SAML IdP' });
  }
  if (config.enableMinIO) {
    services.push({ name: 'MinIO Console', url: `http://${host}:${config.hostPort + 4}`, description: 'S3-compatible storage' });
  }
  if (config.enableMailhog) {
    services.push({ name: 'Mailhog', url: `http://${host}:${config.hostPort + 5}`, description: 'SMTP test server' });
  }

  return {
    labUrl: `http://${host}:${config.hostPort}`,
    adminCredentials: { user: config.adminUser, password: config.adminPassword },
    testUsers: [
      { username: 'testuser1', password: 'TestUser1Pass2026!', role: 'Regular user (testers group)' },
      { username: 'testuser2', password: 'TestUser2Pass2026!', role: 'Regular user (testers group)' },
      { username: 'testuser3', password: 'TestUser3Pass2026!', role: 'Regular user (developers group)' },
      { username: 'testuser4', password: 'TestUser4Pass2026!', role: 'Regular user (developers group)' },
      { username: 'testuser5', password: 'TestUser5Pass2026!', role: 'Regular user (managers group)' },
      { username: 'shareuser1', password: 'ShareUser1Pass2026!', role: 'Share testing' },
      { username: 'shareuser2', password: 'ShareUser2Pass2026!', role: 'Share testing' },
      { username: 'encuser', password: 'EncUserPass2026!', role: 'Encryption testing' },
      { username: 'groupadmin', password: 'GroupAdminPass2026!', role: 'Group admin (managers + testers)' },
      ...(config.enableLDAP ? [
        { username: 'ldapuser1', password: 'LdapUser1Pass2026!', role: 'LDAP user' },
        { username: 'ldapuser2', password: 'LdapUser2Pass2026!', role: 'LDAP user' },
        { username: 'ldapuser3', password: 'LdapUser3Pass2026!', role: 'LDAP user' },
      ] : []),
    ],
    services,
    nextcloudVersion: config.nextcloudVersion,
    installedApps: BOUNTY_ELIGIBLE_APPS.filter(a => !a.builtIn).length,
    complianceNotes: [
      'All testing MUST be performed on this self-hosted instance only',
      'Do NOT run automated scans against *.nextcloud.com domains',
      'Do NOT use cloud-based AI/LLM services for report generation',
      'Only use locally-running LLMs if needed',
      'Include Nextcloud Server version and App version in all reports',
      'Reproduce all findings with screenshots before reporting',
      'Third-party AppStore apps are OUT OF SCOPE',
      `Current server version: ${config.nextcloudVersion}`,
    ],
  };
}

// ─── YAML Formatter (simple) ────────────────────────────────────────────────

function formatYaml(obj: any, indent = 0): string {
  const pad = '  '.repeat(indent);
  let out = '';

  if (Array.isArray(obj)) {
    for (const item of obj) {
      if (typeof item === 'object' && !Array.isArray(item)) {
        out += `${pad}-\n`;
        out += formatYaml(item, indent + 1);
      } else {
        out += `${pad}- ${JSON.stringify(item)}\n`;
      }
    }
  } else if (typeof obj === 'object' && obj !== null) {
    for (const [key, val] of Object.entries(obj)) {
      if (val === null || val === undefined) continue;
      if (typeof val === 'object' && !Array.isArray(val) && Object.keys(val).length > 0) {
        out += `${pad}${key}:\n`;
        out += formatYaml(val, indent + 1);
      } else if (Array.isArray(val)) {
        out += `${pad}${key}:\n`;
        out += formatYaml(val, indent + 1);
      } else {
        const v = typeof val === 'string' && (val.includes(':') || val.includes('#') || val.includes('{'))
          ? `"${val.replace(/"/g, '\\"')}"`
          : val;
        out += `${pad}${key}: ${v}\n`;
      }
    }
  }

  return out;
}
