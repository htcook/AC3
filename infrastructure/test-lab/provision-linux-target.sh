#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# AC3 Test Lab — Metasploitable3-equivalent Linux Target Provisioner
# Deploys vulnerable services on a fresh Ubuntu 14.04/16.04 droplet
# Author: AC3 Platform
# ─────────────────────────────────────────────────────────────────────────────
# WARNING: This creates an INTENTIONALLY VULNERABLE server.
# ONLY deploy inside an isolated VPC with no public internet access.
# ─────────────────────────────────────────────────────────────────────────────

set -e

echo "═══════════════════════════════════════════════════════════════"
echo "  AC3 Test Lab — Linux Target Provisioner (Metasploitable3)"
echo "═══════════════════════════════════════════════════════════════"

# ─── System Setup ────────────────────────────────────────────────────────────
export DEBIAN_FRONTEND=noninteractive

echo "[1/12] Creating vulnerable users..."
# Weak credential users (mirrors Metasploitable3 user list)
useradd -m -s /bin/bash vagrant && echo "vagrant:vagrant" | chpasswd
useradd -m -s /bin/bash admin && echo "admin:admin" | chpasswd
useradd -m -s /bin/bash user && echo "user:password" | chpasswd
useradd -m -s /bin/bash leia_organa && echo "leia_organa:princess" | chpasswd
useradd -m -s /bin/bash luke_skywalker && echo "luke_skywalker:skywalker" | chpasswd
useradd -m -s /bin/bash han_solo && echo "han_solo:nerf_herder" | chpasswd
useradd -m -s /bin/bash artoo_detoo && echo "artoo_detoo:beep_boop" | chpasswd
useradd -m -s /bin/bash c_three_pio && echo "c_three_pio:pr0telewd" | chpasswd
useradd -m -s /bin/bash ben_kenobi && echo "ben_kenobi:thef0rce" | chpasswd
useradd -m -s /bin/bash darth_vader && echo "darth_vader:d@rkside" | chpasswd
useradd -m -s /bin/bash anakin_skywalker && echo "anakin_skywalker:yipp33" | chpasswd
useradd -m -s /bin/bash jarjar_binks && echo "jarjar_binks:yousa" | chpasswd
useradd -m -s /bin/bash lando_calrissian && echo "lando_calrissian:smoothop" | chpasswd
useradd -m -s /bin/bash boba_fett && echo "boba_fett:mandalorian1" | chpasswd
useradd -m -s /bin/bash jabba_hutt && echo "jabba_hutt:yourm0m" | chpasswd
# Add vagrant to sudoers
echo "vagrant ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

echo "[2/12] Installing base packages..."
apt-get update -qq
apt-get install -y -qq build-essential curl wget git unzip \
  openssh-server net-tools nmap netcat \
  libssl-dev libffi-dev python python-dev \
  ruby ruby-dev 2>/dev/null

# Enable password auth for SSH
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
service ssh restart

# ─── ProFTPD 1.3.5 (CVE-2015-3306 mod_copy) ────────────────────────────────
echo "[3/12] Installing ProFTPD 1.3.5 with mod_copy..."
apt-get install -y -qq proftpd 2>/dev/null || true
# Configure to allow mod_copy (the vulnerability)
cat > /etc/proftpd/proftpd.conf << 'EOF'
ServerName "AC3 Lab FTP"
ServerType standalone
DefaultServer on
Port 21
Umask 022
MaxInstances 30
User nobody
Group nogroup
DefaultRoot ~
AllowOverwrite on
<Anonymous ~ftp>
  User ftp
  Group nogroup
  UserAlias anonymous ftp
  MaxClients 10
  <Directory *>
    <Limit WRITE>
      DenyAll
    </Limit>
  </Directory>
</Anonymous>
# mod_copy enabled (VULNERABLE — CVE-2015-3306)
<IfModule mod_copy.c>
  AllowAll
</IfModule>
EOF
service proftpd restart || true

# ─── MySQL (root with no password) ──────────────────────────────────────────
echo "[4/12] Installing MySQL with empty root password..."
echo "mysql-server mysql-server/root_password password " | debconf-set-selections
echo "mysql-server mysql-server/root_password_again password " | debconf-set-selections
apt-get install -y -qq mysql-server mysql-client 2>/dev/null
# Bind to all interfaces
sed -i 's/bind-address.*=.*/bind-address = 0.0.0.0/' /etc/mysql/my.cnf 2>/dev/null || \
sed -i 's/bind-address.*=.*/bind-address = 0.0.0.0/' /etc/mysql/mysql.conf.d/mysqld.cnf 2>/dev/null
# Grant remote root access with no password
mysql -u root -e "GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' IDENTIFIED BY '' WITH GRANT OPTION; FLUSH PRIVILEGES;" 2>/dev/null || true
service mysql restart

# ─── Apache + PHP + phpMyAdmin ───────────────────────────────────────────────
echo "[5/12] Installing Apache + PHP + phpMyAdmin..."
apt-get install -y -qq apache2 php5 php5-mysql libapache2-mod-php5 2>/dev/null || \
apt-get install -y -qq apache2 php php-mysql libapache2-mod-php 2>/dev/null
# phpMyAdmin with no auth
echo "phpmyadmin phpmyadmin/dbconfig-install boolean true" | debconf-set-selections
echo "phpmyadmin phpmyadmin/mysql/admin-pass password " | debconf-set-selections
echo "phpmyadmin phpmyadmin/mysql/app-pass password " | debconf-set-selections
echo "phpmyadmin phpmyadmin/reconfigure-webserver multiselect apache2" | debconf-set-selections
apt-get install -y -qq phpmyadmin 2>/dev/null || true
ln -sf /etc/phpmyadmin/apache.conf /etc/apache2/conf-available/phpmyadmin.conf 2>/dev/null
a2enconf phpmyadmin 2>/dev/null || true
service apache2 restart

# ─── Samba (CVE-2017-7494 is_known_pipename) ────────────────────────────────
echo "[6/12] Installing Samba with writable share..."
apt-get install -y -qq samba 2>/dev/null
mkdir -p /tmp/samba_share
chmod 777 /tmp/samba_share
cat >> /etc/samba/smb.conf << 'EOF'

[public]
   path = /tmp/samba_share
   browsable = yes
   writable = yes
   guest ok = yes
   read only = no
   create mask = 0777
   directory mask = 0777

[tmp]
   path = /tmp
   browsable = yes
   writable = yes
   guest ok = yes
   read only = no
EOF
service smbd restart || service samba restart

# ─── UnrealIRCd 3.2.8.1 (CVE-2010-2075 backdoor) ───────────────────────────
echo "[7/12] Installing UnrealIRCd 3.2.8.1 (backdoored)..."
cd /tmp
# Download the backdoored version
wget -q "https://github.com/Metasploitable/unrealircd/raw/master/Unreal3.2.8.1.tar.gz" -O Unreal3.2.8.1.tar.gz 2>/dev/null || \
wget -q "https://raw.githubusercontent.com/rapid7/metasploitable3/master/chef/cookbooks/metasploitable/files/default/unrealircd/Unreal3.2.8.1.tar.gz" -O Unreal3.2.8.1.tar.gz 2>/dev/null || true

if [ -f Unreal3.2.8.1.tar.gz ]; then
  tar xzf Unreal3.2.8.1.tar.gz
  cd Unreal3.2*/
  ./Config <<< $'y\n\n\n\n\n\n\n\n\n\n' 2>/dev/null || true
  make 2>/dev/null || true
  # Start the IRCd
  ./unreal start 2>/dev/null || true
else
  echo "  [WARN] UnrealIRCd download failed — installing from apt as fallback"
  apt-get install -y -qq ircd-hybrid 2>/dev/null || true
fi
cd /tmp

# ─── Drupal 7 (Drupalgeddon — CVE-2014-3704, CVE-2018-7600) ─────────────────
echo "[8/12] Installing Drupal 7 (Drupalgeddon)..."
cd /var/www/html
wget -q "https://ftp.drupal.org/files/projects/drupal-7.28.tar.gz" -O drupal.tar.gz 2>/dev/null
if [ -f drupal.tar.gz ]; then
  tar xzf drupal.tar.gz
  mv drupal-7.28 drupal
  cp drupal/sites/default/default.settings.php drupal/sites/default/settings.php
  chmod 777 drupal/sites/default/settings.php
  chmod 777 drupal/sites/default
  mkdir -p drupal/sites/default/files
  chmod 777 drupal/sites/default/files
  chown -R www-data:www-data drupal/
  # Create Drupal database
  mysql -u root -e "CREATE DATABASE IF NOT EXISTS drupal; GRANT ALL ON drupal.* TO 'drupal'@'localhost' IDENTIFIED BY 'drupal';" 2>/dev/null || true
  rm drupal.tar.gz
fi
cd /tmp

# ─── Apache Continuum (CVE-2016-3087) ───────────────────────────────────────
echo "[9/12] Installing Apache Continuum..."
wget -q "https://archive.apache.org/dist/continuum/binaries/apache-continuum-1.4.2-bin.tar.gz" -O continuum.tar.gz 2>/dev/null
if [ -f continuum.tar.gz ]; then
  tar xzf continuum.tar.gz -C /opt/
  /opt/apache-continuum-1.4.2/bin/continuum start 2>/dev/null || true
  rm continuum.tar.gz
fi

# ─── CUPS (Common UNIX Printing System) ─────────────────────────────────────
echo "[10/12] Installing CUPS..."
apt-get install -y -qq cups 2>/dev/null
# Allow remote access
sed -i 's/Listen localhost:631/Listen 0.0.0.0:631/' /etc/cups/cupsd.conf 2>/dev/null
sed -i '/<Location \/>/,/<\/Location>/s/Order allow,deny/Order allow,deny\n  Allow all/' /etc/cups/cupsd.conf 2>/dev/null
service cups restart 2>/dev/null || true

# ─── Docker (exposed API on 2375) ───────────────────────────────────────────
echo "[11/12] Installing Docker with exposed TCP API..."
curl -fsSL https://get.docker.com | sh 2>/dev/null || apt-get install -y docker.io 2>/dev/null
# Expose Docker daemon on TCP (VULNERABLE)
mkdir -p /etc/systemd/system/docker.service.d
cat > /etc/systemd/system/docker.service.d/override.conf << 'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/dockerd -H fd:// -H tcp://0.0.0.0:2375
EOF
systemctl daemon-reload 2>/dev/null
systemctl restart docker 2>/dev/null || service docker restart

# ─── SNMP (public community string) ─────────────────────────────────────────
echo "[12/12] Installing SNMP with public community string..."
apt-get install -y -qq snmpd snmp 2>/dev/null
sed -i 's/agentAddress  udp:127.0.0.1:161/agentAddress udp:161/' /etc/snmp/snmpd.conf 2>/dev/null
sed -i 's/#rocommunity public/rocommunity public/' /etc/snmp/snmpd.conf 2>/dev/null
echo "rocommunity public" >> /etc/snmp/snmpd.conf
service snmpd restart 2>/dev/null || true

# ─── Disable Firewall ────────────────────────────────────────────────────────
ufw disable 2>/dev/null || true
iptables -F 2>/dev/null || true
iptables -P INPUT ACCEPT 2>/dev/null || true
iptables -P FORWARD ACCEPT 2>/dev/null || true
iptables -P OUTPUT ACCEPT 2>/dev/null || true

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  ✓ Linux Target Provisioned Successfully"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "  Vulnerable Services:"
echo "  ─────────────────────────────────────────────────────────────"
echo "  Port 21    — ProFTPD 1.3.5 (CVE-2015-3306 mod_copy)"
echo "  Port 22    — SSH (weak credentials)"
echo "  Port 80    — Apache + phpMyAdmin + Drupal 7"
echo "  Port 139   — Samba (writable shares)"
echo "  Port 161   — SNMP (public community string)"
echo "  Port 445   — Samba (CVE-2017-7494)"
echo "  Port 631   — CUPS"
echo "  Port 2375  — Docker (exposed TCP API)"
echo "  Port 3306  — MySQL (root no password)"
echo "  Port 6667  — UnrealIRCd (CVE-2010-2075 backdoor)"
echo "  Port 8080  — Apache Continuum"
echo "  ─────────────────────────────────────────────────────────────"
echo ""
echo "  Default Credentials:"
echo "    vagrant:vagrant | admin:admin | root:(empty for mysql)"
echo ""
echo "  ⚠️  This server is INTENTIONALLY VULNERABLE."
echo "  ⚠️  Keep it isolated in a private VPC."
echo "═══════════════════════════════════════════════════════════════"
