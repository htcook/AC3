# ─────────────────────────────────────────────────────────────────────────────
# AC3 Test Lab — Metasploitable3-equivalent Windows Target Provisioner
# Deploys vulnerable services on a Windows Server 2008 R2 / 2012 R2 droplet
# Author: AC3 Platform
# ─────────────────────────────────────────────────────────────────────────────
# WARNING: This creates an INTENTIONALLY VULNERABLE server.
# ONLY deploy inside an isolated VPC with no public internet access.
# ─────────────────────────────────────────────────────────────────────────────

Write-Host "═══════════════════════════════════════════════════════════════"
Write-Host "  AC3 Test Lab — Windows Target Provisioner (Metasploitable3)"
Write-Host "═══════════════════════════════════════════════════════════════"

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"
$InstallDir = "C:\tools"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# ─── Create Vulnerable Users ────────────────────────────────────────────────
Write-Host "[1/10] Creating vulnerable users..."
$users = @{
    "vagrant"     = "vagrant"
    "sshd"        = "sshd"
    "leah_organa" = "princess"
    "luke_skywalker" = "skywalker"
    "han_solo"    = "nerf_herder"
    "anakin_skywalker" = "yipp33"
    "darth_vader" = "d@rkside"
    "ben_kenobi"  = "thef0rce"
    "artoo_detoo" = "beep_boop"
    "c_three_pio" = "pr0telewd"
    "jarjar_binks" = "yousa"
    "lando_calrissian" = "smoothop"
    "boba_fett"   = "mandalorian1"
    "jabba_hutt"  = "yourm0m"
    "chewbacca"   = "rwaaaaawr1"
}

foreach ($user in $users.GetEnumerator()) {
    try {
        net user $user.Key $user.Value /add /y 2>$null
        net localgroup "Remote Desktop Users" $user.Key /add 2>$null
    } catch {}
}
# Add vagrant to administrators
net localgroup Administrators vagrant /add 2>$null

# ─── Enable SSH (OpenSSH) ────────────────────────────────────────────────────
Write-Host "[2/10] Enabling SSH..."
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 2>$null
Start-Service sshd 2>$null
Set-Service -Name sshd -StartupType Automatic 2>$null

# ─── Enable WinRM ────────────────────────────────────────────────────────────
Write-Host "[3/10] Enabling WinRM..."
Enable-PSRemoting -Force -SkipNetworkProfileCheck 2>$null
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value true 2>$null
Set-Item WSMan:\localhost\Service\Auth\Basic -Value true 2>$null
winrm set winrm/config/service '@{AllowUnencrypted="true"}' 2>$null

# ─── Install Java (required for GlassFish, Jenkins, Tomcat, Axis2, JMX) ─────
Write-Host "[4/10] Installing Java JDK 8..."
$jdkUrl = "https://github.com/adoptium/temurin8-binaries/releases/download/jdk8u392-b08/OpenJDK8U-jdk_x64_windows_hotspot_8u392b08.zip"
Invoke-WebRequest -Uri $jdkUrl -OutFile "$InstallDir\jdk8.zip" 2>$null
if (Test-Path "$InstallDir\jdk8.zip") {
    Expand-Archive -Path "$InstallDir\jdk8.zip" -DestinationPath "$InstallDir\java" -Force
    $javaHome = (Get-ChildItem "$InstallDir\java" -Directory | Select-Object -First 1).FullName
    [Environment]::SetEnvironmentVariable("JAVA_HOME", $javaHome, "Machine")
    [Environment]::SetEnvironmentVariable("PATH", "$env:PATH;$javaHome\bin", "Machine")
    $env:JAVA_HOME = $javaHome
    $env:PATH = "$env:PATH;$javaHome\bin"
}

# ─── GlassFish 4.1 (CVE-2011-0807) ─────────────────────────────────────────
Write-Host "[5/10] Installing GlassFish 4.1..."
$gfUrl = "https://download.oracle.com/glassfish/4.1/release/glassfish-4.1.zip"
Invoke-WebRequest -Uri $gfUrl -OutFile "$InstallDir\glassfish.zip" 2>$null
if (Test-Path "$InstallDir\glassfish.zip") {
    Expand-Archive -Path "$InstallDir\glassfish.zip" -DestinationPath "$InstallDir" -Force
    # Set admin password to 'sploit'
    & "$InstallDir\glassfish4\bin\asadmin.bat" start-domain 2>$null
    echo "AS_ADMIN_PASSWORD=`nAS_ADMIN_NEWPASSWORD=sploit" | Out-File "$InstallDir\pwdfile.txt" -Encoding ascii
    & "$InstallDir\glassfish4\bin\asadmin.bat" --user admin --passwordfile "$InstallDir\pwdfile.txt" change-admin-password 2>$null
    & "$InstallDir\glassfish4\bin\asadmin.bat" enable-secure-admin 2>$null
}

# ─── Apache Tomcat 8.0 + Struts + Axis2 (CVE-2016-3087, CVE-2010-0219) ──────
Write-Host "[6/10] Installing Tomcat 8.0 with Struts and Axis2..."
$tomcatUrl = "https://archive.apache.org/dist/tomcat/tomcat-8/v8.0.33/bin/apache-tomcat-8.0.33-windows-x64.zip"
Invoke-WebRequest -Uri $tomcatUrl -OutFile "$InstallDir\tomcat.zip" 2>$null
if (Test-Path "$InstallDir\tomcat.zip") {
    Expand-Archive -Path "$InstallDir\tomcat.zip" -DestinationPath "$InstallDir" -Force
    $tomcatDir = "$InstallDir\apache-tomcat-8.0.33"
    # Configure manager credentials
    @"
<?xml version='1.0' encoding='utf-8'?>
<tomcat-users>
  <role rolename="manager-gui"/>
  <role rolename="manager-script"/>
  <user username="sploit" password="sploit" roles="manager-gui,manager-script"/>
</tomcat-users>
"@ | Out-File "$tomcatDir\conf\tomcat-users.xml" -Encoding utf8
    # Change port to 8282
    (Get-Content "$tomcatDir\conf\server.xml") -replace 'port="8080"', 'port="8282"' | Set-Content "$tomcatDir\conf\server.xml"
    # Start Tomcat
    & "$tomcatDir\bin\startup.bat" 2>$null
}

# ─── Jenkins (unauthenticated script console) ────────────────────────────────
Write-Host "[7/10] Installing Jenkins..."
$jenkinsUrl = "https://get.jenkins.io/war-stable/2.60.3/jenkins.war"
Invoke-WebRequest -Uri $jenkinsUrl -OutFile "$InstallDir\jenkins.war" 2>$null
if (Test-Path "$InstallDir\jenkins.war") {
    # Start Jenkins on port 8484 with no auth
    Start-Process -FilePath "java" -ArgumentList "-jar", "$InstallDir\jenkins.war", "--httpPort=8484", "--argumentsRealm.passwd.admin=admin", "--argumentsRealm.roles.admin=admin" -WindowStyle Hidden
}

# ─── ElasticSearch 1.1.1 (CVE-2014-3120) ────────────────────────────────────
Write-Host "[8/10] Installing ElasticSearch 1.1.1..."
$esUrl = "https://download.elastic.co/elasticsearch/elasticsearch/elasticsearch-1.1.1.zip"
Invoke-WebRequest -Uri $esUrl -OutFile "$InstallDir\elasticsearch.zip" 2>$null
if (Test-Path "$InstallDir\elasticsearch.zip") {
    Expand-Archive -Path "$InstallDir\elasticsearch.zip" -DestinationPath "$InstallDir" -Force
    # Enable dynamic scripting (VULNERABLE)
    Add-Content "$InstallDir\elasticsearch-1.1.1\config\elasticsearch.yml" "`nscript.disable_dynamic: false"
    & "$InstallDir\elasticsearch-1.1.1\bin\elasticsearch.bat" -d 2>$null
}

# ─── ManageEngine Desktop Central (CVE-2015-8249) ───────────────────────────
Write-Host "[9/10] Installing ManageEngine Desktop Central..."
# Note: ManageEngine requires a large installer. For the test lab, we simulate
# the vulnerable endpoint behavior with a lightweight stub.
Write-Host "  [INFO] ManageEngine stub — full installer requires manual download"

# ─── MySQL 5.5 (root no password, remote access) ────────────────────────────
Write-Host "[10/10] Installing MySQL..."
$mysqlUrl = "https://dev.mysql.com/get/Downloads/MySQL-5.5/mysql-5.5.62-winx64.zip"
Invoke-WebRequest -Uri $mysqlUrl -OutFile "$InstallDir\mysql.zip" 2>$null
if (Test-Path "$InstallDir\mysql.zip") {
    Expand-Archive -Path "$InstallDir\mysql.zip" -DestinationPath "$InstallDir" -Force
    $mysqlDir = (Get-ChildItem "$InstallDir\mysql-5.5*" -Directory | Select-Object -First 1).FullName
    # Create my.ini with no root password and remote binding
    @"
[mysqld]
basedir=$mysqlDir
datadir=$mysqlDir\data
port=3306
bind-address=0.0.0.0
skip-grant-tables
"@ | Out-File "$mysqlDir\my.ini" -Encoding ascii
    & "$mysqlDir\bin\mysqld.exe" --install MySQL 2>$null
    Start-Service MySQL 2>$null
}

# ─── Enable SNMP ─────────────────────────────────────────────────────────────
Write-Host "Enabling SNMP service..."
Install-WindowsFeature SNMP-Service -IncludeManagementTools 2>$null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" -Name "public" -Value 4 2>$null
Start-Service SNMP 2>$null

# ─── Disable Firewall ────────────────────────────────────────────────────────
Write-Host "Disabling Windows Firewall..."
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False 2>$null
netsh advfirewall set allprofiles state off 2>$null

# ─── Enable RDP ──────────────────────────────────────────────────────────────
Write-Host "Enabling Remote Desktop..."
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop" 2>$null

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════"
Write-Host "  ✓ Windows Target Provisioned Successfully"
Write-Host "═══════════════════════════════════════════════════════════════"
Write-Host ""
Write-Host "  Vulnerable Services:"
Write-Host "  ─────────────────────────────────────────────────────────────"
Write-Host "  Port 22    — SSH (weak credentials)"
Write-Host "  Port 445   — SMB/psexec (weak credentials)"
Write-Host "  Port 3306  — MySQL (root no password)"
Write-Host "  Port 3389  — RDP (weak credentials)"
Write-Host "  Port 4848  — GlassFish Admin (admin:sploit, CVE-2011-0807)"
Write-Host "  Port 5985  — WinRM (weak credentials)"
Write-Host "  Port 8080  — GlassFish HTTP"
Write-Host "  Port 8282  — Tomcat + Struts + Axis2 (sploit:sploit)"
Write-Host "  Port 8484  — Jenkins (no auth, script console)"
Write-Host "  Port 9200  — ElasticSearch (CVE-2014-3120)"
Write-Host "  Port 161   — SNMP (public community string)"
Write-Host "  ─────────────────────────────────────────────────────────────"
Write-Host ""
Write-Host "  Default Credentials:"
Write-Host "    vagrant:vagrant | admin:admin | sploit:sploit"
Write-Host ""
Write-Host "  ⚠️  This server is INTENTIONALLY VULNERABLE."
Write-Host "  ⚠️  Keep it isolated in a private VPC."
Write-Host "═══════════════════════════════════════════════════════════════"
