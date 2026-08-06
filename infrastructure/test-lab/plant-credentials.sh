#!/bin/bash
# Plant test credentials on lab targets for blind engagement testing
# This simulates a real environment where credentials are scattered across hosts

SCAN_SERVER="http://137.184.71.192:4000/api/scan/raw"
SCAN_KEY="X-Scan-Key: ADMIN123"
LINUX_TARGET="159.223.154.80"
WINDOWS_TARGET="104.248.62.133"

echo "=== Planting credentials on Linux target ($LINUX_TARGET) ==="

# Plant credentials file in /tmp
curl -s -X POST "$SCAN_SERVER" -H "Content-Type: application/json" -H "$SCAN_KEY" -d "{
  \"command\": \"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes root@$LINUX_TARGET 'printf \\\"admin:Sup3rS3cr3t!2024\\\\nroot:R00tP@ss!Lab\\\\nms3user:ms3user123\\\\ndbadmin:Pr0duction_DB_P@ss\\\\nwinuser:WinLab2024!\\\\nbackup:B@ckup_Cr3ds_2024\\\\n\\\" > /tmp/credentials.txt && chmod 644 /tmp/credentials.txt && echo PLANTED_CREDS'\",
  \"timeout\": 15000
}"

echo ""

# Plant web app config
curl -s -X POST "$SCAN_SERVER" -H "Content-Type: application/json" -H "$SCAN_KEY" -d "{
  \"command\": \"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes root@$LINUX_TARGET 'printf \\\"DB_HOST=$WINDOWS_TARGET\\\\nDB_USER=appuser\\\\nDB_PASSWORD=AppDB_S3cret\\\\nREDIS_PASSWORD=r3d1s_p4ss\\\\nSMB_USER=winuser\\\\nSMB_PASS=WinLab2024!\\\\n\\\" > /var/www/html/app-config.env && chmod 644 /var/www/html/app-config.env && echo PLANTED_CONFIG'\",
  \"timeout\": 15000
}"

echo ""

# Plant bash history with credential leaks
curl -s -X POST "$SCAN_SERVER" -H "Content-Type: application/json" -H "$SCAN_KEY" -d "{
  \"command\": \"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes root@$LINUX_TARGET 'printf \\\"mysql -u dbadmin -pPr0duction_DB_P@ss production\\\\nsshpass -p WinLab2024! ssh winuser@$WINDOWS_TARGET\\\\ncurl -u admin:Sup3rS3cr3t!2024 http://localhost:8080/manager\\\\n\\\" >> /root/.bash_history && echo PLANTED_HISTORY'\",
  \"timeout\": 15000
}"

echo ""

# Plant SUID binary for privesc testing
curl -s -X POST "$SCAN_SERVER" -H "Content-Type: application/json" -H "$SCAN_KEY" -d "{
  \"command\": \"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes root@$LINUX_TARGET 'chmod u+s /usr/bin/find /usr/bin/python3.10 2>/dev/null; ls -la /usr/bin/find /usr/bin/python3.10 2>/dev/null | grep -c rws && echo PLANTED_SUID'\",
  \"timeout\": 15000
}"

echo ""
echo "=== Planting credentials on Windows-equiv target ($WINDOWS_TARGET) ==="

# Plant credentials in SMB share
curl -s -X POST "$SCAN_SERVER" -H "Content-Type: application/json" -H "$SCAN_KEY" -d "{
  \"command\": \"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes root@$WINDOWS_TARGET 'mkdir -p /srv/samba/share && printf \\\"=== INTERNAL CREDENTIALS ===\\\\nDomain Admin: administrator / D0m@inAdm1n!\\\\nLinux Server: root / R00tP@ss!Lab\\\\nMySQL: dbadmin / Pr0duction_DB_P@ss\\\\nBackup: backup / B@ckup_Cr3ds_2024\\\\nSSH to $LINUX_TARGET: admin / Sup3rS3cr3t!2024\\\\n\\\" > /srv/samba/share/credentials.txt && chmod 644 /srv/samba/share/credentials.txt && echo PLANTED_SMB'\",
  \"timeout\": 15000
}"

echo ""

# Plant web config on Windows target
curl -s -X POST "$SCAN_SERVER" -H "Content-Type: application/json" -H "$SCAN_KEY" -d "{
  \"command\": \"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes root@$WINDOWS_TARGET 'printf \\\"username=administrator\\\\npassword=D0m@inAdm1n!\\\\nserver=$LINUX_TARGET\\\\n\\\" > /var/www/html/appsettings.json && echo PLANTED_APPSETTINGS'\",
  \"timeout\": 15000
}"

echo ""

# Add known_hosts entries for cross-target discovery
curl -s -X POST "$SCAN_SERVER" -H "Content-Type: application/json" -H "$SCAN_KEY" -d "{
  \"command\": \"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes root@$LINUX_TARGET 'mkdir -p /root/.ssh && echo \\\"$WINDOWS_TARGET ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForLabTesting\\\" >> /root/.ssh/known_hosts && echo PLANTED_KNOWN_HOSTS'\",
  \"timeout\": 15000
}"

echo ""
echo "=== Credential planting complete ==="
