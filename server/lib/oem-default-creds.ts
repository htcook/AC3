/**
 * OEM Default Credentials — intelligence data for active testing.
 * 
 * Auto-matches discovered technologies against known default credentials.
 * Consumed by:
 *   1. Automated tools (SSH/FTP/admin panel testing)
 *   2. Operators (reference table in UI)
 *   3. AI assistant (contextual suggestions during chat)
 */
import { eq, like, sql, or, and } from "drizzle-orm";
import { oemDefaultCredentials } from "../../drizzle/schema";

async function getDb() {
  const { getDb: _getDb } = await import("../db");
  return _getDb();
}

/** Comprehensive built-in OEM default credential database */
export const BUILTIN_DEFAULT_CREDS: Array<{
  vendor: string;
  product: string;
  version?: string;
  protocol: string;
  port?: number;
  username: string;
  password: string;
  accessLevel: string;
  notes?: string;
  cveReference?: string;
  source: string;
  tags: string[];
}> = [
  // ─── Network Equipment ─────────────────────────────────────────────
  { vendor: "Cisco", product: "IOS Router", protocol: "ssh", port: 22, username: "admin", password: "admin", accessLevel: "admin", notes: "Common on older IOS devices", source: "CISA default creds advisory", tags: ["router", "network"] },
  { vendor: "Cisco", product: "IOS Router", protocol: "telnet", port: 23, username: "cisco", password: "cisco", accessLevel: "admin", source: "Vendor documentation", tags: ["router", "network"] },
  { vendor: "Cisco", product: "ASA Firewall", protocol: "https", port: 443, username: "admin", password: "admin", accessLevel: "admin", source: "Vendor documentation", tags: ["firewall", "network"] },
  { vendor: "Cisco", product: "Catalyst Switch", protocol: "ssh", port: 22, username: "admin", password: "admin", accessLevel: "admin", source: "Vendor documentation", tags: ["switch", "network"] },
  { vendor: "Juniper", product: "Junos", protocol: "ssh", port: 22, username: "root", password: "root123", accessLevel: "root", source: "Vendor documentation", tags: ["router", "firewall", "network"] },
  { vendor: "MikroTik", product: "RouterOS", protocol: "ssh", port: 22, username: "admin", password: "", accessLevel: "admin", notes: "Empty password by default", source: "Vendor documentation", tags: ["router", "network"] },
  { vendor: "MikroTik", product: "RouterOS", protocol: "web_admin", port: 80, username: "admin", password: "", accessLevel: "admin", source: "Vendor documentation", tags: ["router", "network"] },
  { vendor: "Ubiquiti", product: "EdgeOS", protocol: "ssh", port: 22, username: "ubnt", password: "ubnt", accessLevel: "admin", source: "Vendor documentation", tags: ["router", "network"] },
  { vendor: "Ubiquiti", product: "UniFi", protocol: "https", port: 8443, username: "ubnt", password: "ubnt", accessLevel: "admin", source: "Vendor documentation", tags: ["wireless", "network"] },
  { vendor: "Netgear", product: "ProSafe", protocol: "web_admin", port: 80, username: "admin", password: "password", accessLevel: "admin", source: "Vendor documentation", tags: ["switch", "router", "network"] },
  { vendor: "TP-Link", product: "Router", protocol: "web_admin", port: 80, username: "admin", password: "admin", accessLevel: "admin", source: "Vendor documentation", tags: ["router", "network", "iot"] },
  { vendor: "D-Link", product: "Router", protocol: "web_admin", port: 80, username: "admin", password: "", accessLevel: "admin", source: "Vendor documentation", tags: ["router", "network", "iot"] },
  { vendor: "Aruba", product: "ArubaOS", protocol: "ssh", port: 22, username: "admin", password: "admin", accessLevel: "admin", source: "Vendor documentation", tags: ["wireless", "network"] },

  // ─── Firewalls ─────────────────────────────────────────────────────
  { vendor: "Fortinet", product: "FortiGate", protocol: "https", port: 443, username: "admin", password: "", accessLevel: "admin", notes: "Empty password on factory reset", source: "Vendor documentation", tags: ["firewall", "network"] },
  { vendor: "Fortinet", product: "FortiGate", protocol: "ssh", port: 22, username: "admin", password: "", accessLevel: "admin", source: "Vendor documentation", tags: ["firewall", "network"] },
  { vendor: "Palo Alto", product: "PAN-OS", protocol: "https", port: 443, username: "admin", password: "admin", accessLevel: "admin", source: "Vendor documentation", tags: ["firewall", "network"] },
  { vendor: "SonicWall", product: "SonicOS", protocol: "https", port: 443, username: "admin", password: "password", accessLevel: "admin", source: "Vendor documentation", tags: ["firewall", "network"] },
  { vendor: "pfSense", product: "pfSense", protocol: "https", port: 443, username: "admin", password: "pfsense", accessLevel: "admin", source: "Vendor documentation", tags: ["firewall", "network", "open_source"] },
  { vendor: "WatchGuard", product: "Firebox", protocol: "https", port: 8080, username: "admin", password: "readwrite", accessLevel: "admin", source: "Vendor documentation", tags: ["firewall", "network"] },
  { vendor: "Check Point", product: "Gaia", protocol: "https", port: 443, username: "admin", password: "admin", accessLevel: "admin", source: "Vendor documentation", tags: ["firewall", "network"] },

  // ─── Web Servers & Application Servers ─────────────────────────────
  { vendor: "Apache", product: "Tomcat", protocol: "http", port: 8080, username: "tomcat", password: "tomcat", accessLevel: "admin", notes: "Manager app default", source: "Apache documentation", tags: ["web_server", "java"] },
  { vendor: "Apache", product: "Tomcat", protocol: "http", port: 8080, username: "admin", password: "admin", accessLevel: "admin", source: "Apache documentation", tags: ["web_server", "java"] },
  { vendor: "Apache", product: "Tomcat", protocol: "http", port: 8080, username: "manager", password: "manager", accessLevel: "admin", source: "Common misconfiguration", tags: ["web_server", "java"] },
  { vendor: "JBoss", product: "WildFly", protocol: "http", port: 9990, username: "admin", password: "admin", accessLevel: "admin", source: "Vendor documentation", tags: ["web_server", "java", "application_server"] },
  { vendor: "Oracle", product: "WebLogic", protocol: "http", port: 7001, username: "weblogic", password: "welcome1", accessLevel: "admin", source: "Vendor documentation", tags: ["web_server", "java", "application_server"] },
  { vendor: "Nginx", product: "Nginx Plus", protocol: "web_admin", port: 8080, username: "admin", password: "admin", accessLevel: "admin", source: "Common misconfiguration", tags: ["web_server"] },
  { vendor: "IBM", product: "WebSphere", protocol: "https", port: 9043, username: "wasadmin", password: "wasadmin", accessLevel: "admin", source: "Vendor documentation", tags: ["web_server", "java", "application_server"] },

  // ─── Databases ─────────────────────────────────────────────────────
  { vendor: "MySQL", product: "MySQL Server", protocol: "mysql", port: 3306, username: "root", password: "", accessLevel: "root", notes: "Empty password on fresh install", source: "MySQL documentation", tags: ["database", "mysql"] },
  { vendor: "MySQL", product: "MySQL Server", protocol: "mysql", port: 3306, username: "root", password: "root", accessLevel: "root", source: "Common misconfiguration", tags: ["database", "mysql"] },
  { vendor: "PostgreSQL", product: "PostgreSQL", protocol: "postgres", port: 5432, username: "postgres", password: "postgres", accessLevel: "admin", source: "Common misconfiguration", tags: ["database", "postgres"] },
  { vendor: "Microsoft", product: "SQL Server", protocol: "mssql", port: 1433, username: "sa", password: "sa", accessLevel: "admin", source: "Common misconfiguration", tags: ["database", "mssql"] },
  { vendor: "Microsoft", product: "SQL Server", protocol: "mssql", port: 1433, username: "sa", password: "Password123!", accessLevel: "admin", source: "Common Docker/dev default", tags: ["database", "mssql"] },
  { vendor: "Oracle", product: "Oracle DB", protocol: "oracle", port: 1521, username: "system", password: "oracle", accessLevel: "admin", source: "Vendor documentation", tags: ["database", "oracle"] },
  { vendor: "Oracle", product: "Oracle DB", protocol: "oracle", port: 1521, username: "sys", password: "change_on_install", accessLevel: "root", source: "Vendor documentation", tags: ["database", "oracle"] },
  { vendor: "MongoDB", product: "MongoDB", protocol: "other", port: 27017, username: "admin", password: "admin", accessLevel: "admin", notes: "Auth often disabled by default", source: "Common misconfiguration", tags: ["database", "nosql", "mongodb"] },
  { vendor: "Redis", product: "Redis", protocol: "other", port: 6379, username: "", password: "", accessLevel: "admin", notes: "No auth by default", source: "Redis documentation", tags: ["database", "cache", "redis"] },
  { vendor: "Elasticsearch", product: "Elasticsearch", protocol: "http", port: 9200, username: "elastic", password: "changeme", accessLevel: "admin", source: "Elastic documentation", tags: ["database", "search", "elasticsearch"] },
  { vendor: "CouchDB", product: "CouchDB", protocol: "http", port: 5984, username: "admin", password: "admin", accessLevel: "admin", source: "Vendor documentation", tags: ["database", "nosql"] },

  // ─── SCADA / ICS / OT ─────────────────────────────────────────────
  { vendor: "Siemens", product: "SIMATIC S7", protocol: "other", port: 102, username: "admin", password: "admin", accessLevel: "admin", notes: "S7 PLC default", source: "ICS-CERT advisory", tags: ["scada", "ics", "plc"] },
  { vendor: "Siemens", product: "WinCC", protocol: "mssql", port: 1433, username: "WinCCAdmin", password: "2WSXcder", accessLevel: "admin", cveReference: "CVE-2010-2772", source: "ICS-CERT", tags: ["scada", "hmi"] },
  { vendor: "Schneider Electric", product: "Modicon M340", protocol: "ftp", port: 21, username: "USER", password: "USER", accessLevel: "user", source: "ICS-CERT advisory", tags: ["scada", "ics", "plc"] },
  { vendor: "Allen-Bradley", product: "MicroLogix", protocol: "web_admin", port: 80, username: "admin", password: "1234", accessLevel: "admin", source: "ICS-CERT advisory", tags: ["scada", "ics", "plc"] },
  { vendor: "ABB", product: "AC500 PLC", protocol: "web_admin", port: 80, username: "admin", password: "admin", accessLevel: "admin", source: "ICS-CERT advisory", tags: ["scada", "ics", "plc"] },
  { vendor: "GE", product: "CIMPLICITY", protocol: "other", port: 80, username: "admin", password: "admin", accessLevel: "admin", source: "ICS-CERT advisory", tags: ["scada", "hmi"] },
  { vendor: "Honeywell", product: "Experion PKS", protocol: "web_admin", port: 443, username: "admin", password: "admin", accessLevel: "admin", source: "ICS-CERT advisory", tags: ["scada", "dcs"] },

  // ─── IoT / Embedded ───────────────────────────────────────────────
  { vendor: "Hikvision", product: "IP Camera", protocol: "web_admin", port: 80, username: "admin", password: "12345", accessLevel: "admin", source: "Vendor documentation", tags: ["iot", "camera", "surveillance"] },
  { vendor: "Dahua", product: "IP Camera", protocol: "web_admin", port: 80, username: "admin", password: "admin", accessLevel: "admin", source: "Vendor documentation", tags: ["iot", "camera", "surveillance"] },
  { vendor: "Axis", product: "Network Camera", protocol: "web_admin", port: 80, username: "root", password: "pass", accessLevel: "root", source: "Vendor documentation", tags: ["iot", "camera", "surveillance"] },
  { vendor: "Raspberry Pi", product: "Raspbian", protocol: "ssh", port: 22, username: "pi", password: "raspberry", accessLevel: "user", source: "Vendor documentation", tags: ["iot", "embedded", "linux"] },

  // ─── Remote Access / Management ───────────────────────────────────
  { vendor: "Dell", product: "iDRAC", protocol: "https", port: 443, username: "root", password: "calvin", accessLevel: "root", source: "Dell documentation", tags: ["bmc", "ipmi", "server_management"] },
  { vendor: "HP", product: "iLO", protocol: "https", port: 443, username: "Administrator", password: "admin", accessLevel: "admin", source: "HP documentation", tags: ["bmc", "ipmi", "server_management"] },
  { vendor: "Supermicro", product: "IPMI", protocol: "https", port: 443, username: "ADMIN", password: "ADMIN", accessLevel: "admin", source: "Vendor documentation", tags: ["bmc", "ipmi", "server_management"] },
  { vendor: "APC", product: "Smart-UPS", protocol: "web_admin", port: 80, username: "apc", password: "apc", accessLevel: "admin", source: "Vendor documentation", tags: ["ups", "power", "infrastructure"] },
  { vendor: "VMware", product: "ESXi", protocol: "https", port: 443, username: "root", password: "vmware", accessLevel: "root", source: "Common misconfiguration", tags: ["hypervisor", "virtualization"] },
  { vendor: "VMware", product: "vCenter", protocol: "https", port: 443, username: "administrator@vsphere.local", password: "VMware1!", accessLevel: "admin", source: "Common lab default", tags: ["hypervisor", "virtualization", "management"] },
  { vendor: "Proxmox", product: "VE", protocol: "https", port: 8006, username: "root", password: "proxmox", accessLevel: "root", source: "Common misconfiguration", tags: ["hypervisor", "virtualization", "open_source"] },

  // ─── CMS / Web Applications ───────────────────────────────────────
  { vendor: "WordPress", product: "WordPress", protocol: "http", port: 80, username: "admin", password: "admin", accessLevel: "admin", source: "Common misconfiguration", tags: ["cms", "web_app"] },
  { vendor: "Joomla", product: "Joomla", protocol: "http", port: 80, username: "admin", password: "admin", accessLevel: "admin", source: "Common misconfiguration", tags: ["cms", "web_app"] },
  { vendor: "Drupal", product: "Drupal", protocol: "http", port: 80, username: "admin", password: "admin", accessLevel: "admin", source: "Common misconfiguration", tags: ["cms", "web_app"] },
  { vendor: "Grafana", product: "Grafana", protocol: "http", port: 3000, username: "admin", password: "admin", accessLevel: "admin", source: "Grafana documentation", tags: ["monitoring", "web_app", "dashboard"] },
  { vendor: "Jenkins", product: "Jenkins", protocol: "http", port: 8080, username: "admin", password: "admin", accessLevel: "admin", source: "Common misconfiguration", tags: ["ci_cd", "web_app", "devops"] },
  { vendor: "Nagios", product: "Nagios XI", protocol: "http", port: 80, username: "nagiosadmin", password: "nagiosadmin", accessLevel: "admin", source: "Vendor documentation", tags: ["monitoring", "web_app"] },
  { vendor: "Zabbix", product: "Zabbix", protocol: "http", port: 80, username: "Admin", password: "zabbix", accessLevel: "admin", source: "Zabbix documentation", tags: ["monitoring", "web_app"] },
  { vendor: "phpMyAdmin", product: "phpMyAdmin", protocol: "http", port: 80, username: "root", password: "", accessLevel: "admin", source: "Common misconfiguration", tags: ["database", "web_app", "admin_panel"] },
  { vendor: "Portainer", product: "Portainer", protocol: "https", port: 9443, username: "admin", password: "admin", accessLevel: "admin", source: "Common misconfiguration", tags: ["docker", "container", "web_app"] },
  { vendor: "GitLab", product: "GitLab CE", protocol: "http", port: 80, username: "root", password: "5iveL!fe", accessLevel: "admin", source: "GitLab documentation", tags: ["git", "ci_cd", "web_app", "devops"] },
  { vendor: "SonarQube", product: "SonarQube", protocol: "http", port: 9000, username: "admin", password: "admin", accessLevel: "admin", source: "SonarQube documentation", tags: ["code_quality", "web_app", "devops"] },
  { vendor: "Kibana", product: "Kibana", protocol: "http", port: 5601, username: "elastic", password: "changeme", accessLevel: "admin", source: "Elastic documentation", tags: ["siem", "monitoring", "web_app"] },
  { vendor: "Splunk", product: "Splunk", protocol: "https", port: 8089, username: "admin", password: "changeme", accessLevel: "admin", source: "Splunk documentation", tags: ["siem", "monitoring", "web_app"] },
  { vendor: "Apache", product: "Airflow", protocol: "http", port: 8080, username: "airflow", password: "airflow", accessLevel: "admin", source: "Airflow documentation", tags: ["workflow", "web_app", "devops"] },
  { vendor: "HashiCorp", product: "Consul", protocol: "http", port: 8500, username: "", password: "", accessLevel: "admin", notes: "No ACL by default", source: "HashiCorp documentation", tags: ["service_mesh", "devops"] },
  { vendor: "RabbitMQ", product: "RabbitMQ", protocol: "http", port: 15672, username: "guest", password: "guest", accessLevel: "admin", source: "RabbitMQ documentation", tags: ["message_queue", "web_app"] },

  // ─── VPN / Remote Access ──────────────────────────────────────────
  { vendor: "OpenVPN", product: "Access Server", protocol: "https", port: 943, username: "openvpn", password: "openvpn", accessLevel: "admin", source: "Vendor documentation", tags: ["vpn", "remote_access"] },
  { vendor: "Fortinet", product: "FortiClient EMS", protocol: "https", port: 443, username: "admin", password: "", accessLevel: "admin", source: "Vendor documentation", tags: ["vpn", "endpoint", "remote_access"] },

  // ─── Printers / MFPs ──────────────────────────────────────────────
  { vendor: "HP", product: "LaserJet", protocol: "web_admin", port: 80, username: "admin", password: "admin", accessLevel: "admin", source: "Vendor documentation", tags: ["printer", "iot"] },
  { vendor: "Xerox", product: "WorkCentre", protocol: "web_admin", port: 80, username: "admin", password: "1111", accessLevel: "admin", source: "Vendor documentation", tags: ["printer", "iot"] },
  { vendor: "Brother", product: "MFC", protocol: "web_admin", port: 80, username: "admin", password: "access", accessLevel: "admin", source: "Vendor documentation", tags: ["printer", "iot"] },

  // ─── FTP Servers ──────────────────────────────────────────────────
  { vendor: "vsftpd", product: "vsftpd", protocol: "ftp", port: 21, username: "anonymous", password: "", accessLevel: "readonly", notes: "Anonymous FTP often enabled", source: "Common misconfiguration", tags: ["ftp", "file_server"] },
  { vendor: "ProFTPD", product: "ProFTPD", protocol: "ftp", port: 21, username: "anonymous", password: "", accessLevel: "readonly", source: "Common misconfiguration", tags: ["ftp", "file_server"] },
  { vendor: "FileZilla", product: "FileZilla Server", protocol: "ftp", port: 21, username: "admin", password: "admin", accessLevel: "admin", source: "Common misconfiguration", tags: ["ftp", "file_server"] },

  // ─── SNMP ─────────────────────────────────────────────────────────
  { vendor: "Generic", product: "SNMP Agent", protocol: "snmp", port: 161, username: "public", password: "public", accessLevel: "readonly", notes: "SNMPv1/v2c community string", source: "RFC 1157", tags: ["snmp", "network", "monitoring"] },
  { vendor: "Generic", product: "SNMP Agent", protocol: "snmp", port: 161, username: "private", password: "private", accessLevel: "admin", notes: "SNMPv1/v2c write community", source: "RFC 1157", tags: ["snmp", "network", "monitoring"] },

  // ─── VoIP / Telephony ─────────────────────────────────────────────
  { vendor: "Asterisk", product: "FreePBX", protocol: "web_admin", port: 80, username: "admin", password: "admin", accessLevel: "admin", source: "Vendor documentation", tags: ["voip", "pbx", "telephony"] },
  { vendor: "Cisco", product: "Unified CM", protocol: "https", port: 443, username: "admin", password: "admin", accessLevel: "admin", source: "Vendor documentation", tags: ["voip", "pbx", "telephony"] },
  { vendor: "Avaya", product: "IP Office", protocol: "https", port: 443, username: "Administrator", password: "Administrator", accessLevel: "admin", source: "Vendor documentation", tags: ["voip", "pbx", "telephony"] },
  { vendor: "Polycom", product: "VVX Phone", protocol: "web_admin", port: 80, username: "Polycom", password: "456", accessLevel: "admin", source: "Vendor documentation", tags: ["voip", "phone", "iot"] },
  { vendor: "Yealink", product: "IP Phone", protocol: "web_admin", port: 80, username: "admin", password: "admin", accessLevel: "admin", source: "Vendor documentation", tags: ["voip", "phone", "iot"] },

  // ─── Palo Alto Networks (Expanded) ────────────────────────────────
  { vendor: "Palo Alto", product: "Panorama", protocol: "https", port: 443, username: "admin", password: "admin", accessLevel: "admin", notes: "Panorama management server factory default", source: "Palo Alto documentation", tags: ["firewall", "management", "network"] },
  { vendor: "Palo Alto", product: "Panorama", protocol: "ssh", port: 22, username: "admin", password: "admin", accessLevel: "admin", source: "Palo Alto documentation", tags: ["firewall", "management", "network"] },
  { vendor: "Palo Alto", product: "PAN-OS", protocol: "ssh", port: 22, username: "admin", password: "admin", accessLevel: "admin", source: "Vendor documentation", tags: ["firewall", "network"] },
  { vendor: "Palo Alto", product: "GlobalProtect", protocol: "https", port: 443, username: "admin", password: "admin", accessLevel: "admin", notes: "GlobalProtect portal/gateway", source: "Vendor documentation", tags: ["vpn", "firewall", "remote_access"] },
  { vendor: "Palo Alto", product: "Prisma Access", protocol: "https", port: 443, username: "admin", password: "admin", accessLevel: "admin", source: "Vendor documentation", tags: ["cloud", "sase", "network"] },

  // ─── SonicWall (Expanded) ─────────────────────────────────────────
  { vendor: "SonicWall", product: "SonicOS", protocol: "ssh", port: 22, username: "admin", password: "password", accessLevel: "admin", source: "Vendor documentation", tags: ["firewall", "network"] },
  { vendor: "SonicWall", product: "SMA 100", protocol: "https", port: 443, username: "admin", password: "password", accessLevel: "admin", notes: "Secure Mobile Access appliance", source: "Vendor documentation", tags: ["vpn", "remote_access", "firewall"] },
  { vendor: "SonicWall", product: "SMA 1000", protocol: "https", port: 443, username: "admin", password: "password", accessLevel: "admin", source: "Vendor documentation", tags: ["vpn", "remote_access", "firewall"] },
  { vendor: "SonicWall", product: "NSA", protocol: "https", port: 443, username: "admin", password: "password", accessLevel: "admin", notes: "Network Security Appliance", source: "Vendor documentation", tags: ["firewall", "network"] },
  { vendor: "SonicWall", product: "TZ Series", protocol: "https", port: 443, username: "admin", password: "password", accessLevel: "admin", notes: "TZ entry-level firewall", source: "Vendor documentation", tags: ["firewall", "network"] },
  { vendor: "SonicWall", product: "Email Security", protocol: "https", port: 443, username: "admin", password: "password", accessLevel: "admin", source: "Vendor documentation", tags: ["email", "security"] },
  { vendor: "SonicWall", product: "GMS", protocol: "https", port: 443, username: "admin", password: "password", accessLevel: "admin", notes: "Global Management System", source: "Vendor documentation", tags: ["management", "firewall", "network"] },

  // ─── ICS / SCADA / OT (Expanded) ──────────────────────────────────
  { vendor: "Siemens", product: "SIMATIC HMI", protocol: "web_admin", port: 80, username: "admin", password: "admin", accessLevel: "admin", source: "ICS-CERT advisory", tags: ["scada", "hmi", "ics"] },
  { vendor: "Siemens", product: "SCALANCE", protocol: "web_admin", port: 443, username: "admin", password: "admin", accessLevel: "admin", notes: "Industrial Ethernet switches", source: "ICS-CERT advisory", tags: ["scada", "ics", "network", "switch"] },
  { vendor: "Siemens", product: "SINEMA", protocol: "https", port: 443, username: "admin", password: "admin", accessLevel: "admin", notes: "Network management", source: "ICS-CERT advisory", tags: ["scada", "ics", "management"] },
  { vendor: "Siemens", product: "TIA Portal", protocol: "other", port: 4840, username: "admin", password: "admin", accessLevel: "admin", notes: "OPC UA default", source: "ICS-CERT advisory", tags: ["scada", "ics", "engineering"] },
  { vendor: "Schneider Electric", product: "Unity Pro", protocol: "other", port: 502, username: "", password: "", accessLevel: "admin", notes: "Modbus TCP — no auth by default", source: "ICS-CERT advisory", tags: ["scada", "ics", "plc"] },
  { vendor: "Schneider Electric", product: "EcoStruxure", protocol: "https", port: 443, username: "admin", password: "admin", accessLevel: "admin", source: "ICS-CERT advisory", tags: ["scada", "ics", "management"] },
  { vendor: "Schneider Electric", product: "PowerLogic", protocol: "web_admin", port: 80, username: "admin", password: "admin", accessLevel: "admin", notes: "Power monitoring", source: "ICS-CERT advisory", tags: ["scada", "ics", "power"] },
  { vendor: "Allen-Bradley", product: "ControlLogix", protocol: "web_admin", port: 80, username: "admin", password: "1234", accessLevel: "admin", source: "ICS-CERT advisory", tags: ["scada", "ics", "plc"] },
  { vendor: "Allen-Bradley", product: "CompactLogix", protocol: "web_admin", port: 80, username: "admin", password: "1234", accessLevel: "admin", source: "ICS-CERT advisory", tags: ["scada", "ics", "plc"] },
  { vendor: "Rockwell", product: "FactoryTalk", protocol: "https", port: 443, username: "admin", password: "admin", accessLevel: "admin", source: "ICS-CERT advisory", tags: ["scada", "ics", "hmi"] },
  { vendor: "Emerson", product: "DeltaV", protocol: "web_admin", port: 80, username: "admin", password: "admin", accessLevel: "admin", notes: "DCS controller", source: "ICS-CERT advisory", tags: ["scada", "dcs", "ics"] },
  { vendor: "Emerson", product: "ROC800", protocol: "other", port: 4000, username: "LOI", password: "LOI", accessLevel: "admin", notes: "Remote Operations Controller", source: "ICS-CERT advisory", tags: ["scada", "ics", "rtu"] },
  { vendor: "Yokogawa", product: "CENTUM VP", protocol: "web_admin", port: 80, username: "admin", password: "admin", accessLevel: "admin", notes: "DCS platform", source: "ICS-CERT advisory", tags: ["scada", "dcs", "ics"] },
  { vendor: "Yokogawa", product: "ProSafe-RS", protocol: "web_admin", port: 80, username: "admin", password: "admin", accessLevel: "admin", notes: "Safety instrumented system", source: "ICS-CERT advisory", tags: ["scada", "sis", "ics"] },
  { vendor: "Beckhoff", product: "TwinCAT", protocol: "other", port: 48898, username: "Administrator", password: "1", accessLevel: "admin", notes: "ADS/AMS default", source: "ICS-CERT advisory", tags: ["scada", "ics", "plc"] },
  { vendor: "WAGO", product: "PFC200", protocol: "web_admin", port: 80, username: "admin", password: "wago", accessLevel: "admin", source: "ICS-CERT advisory", tags: ["scada", "ics", "plc"] },
  { vendor: "Phoenix Contact", product: "AXC F 2152", protocol: "web_admin", port: 80, username: "admin", password: "admin", accessLevel: "admin", source: "ICS-CERT advisory", tags: ["scada", "ics", "plc"] },
  { vendor: "Moxa", product: "NPort", protocol: "web_admin", port: 80, username: "admin", password: "", accessLevel: "admin", notes: "Serial device server — empty password default", source: "ICS-CERT advisory", tags: ["scada", "ics", "serial", "iot"] },
  { vendor: "Moxa", product: "EDS Switch", protocol: "web_admin", port: 80, username: "admin", password: "", accessLevel: "admin", notes: "Industrial Ethernet switch", source: "ICS-CERT advisory", tags: ["scada", "ics", "switch", "network"] },
  { vendor: "Advantech", product: "WebAccess", protocol: "web_admin", port: 80, username: "admin", password: "", accessLevel: "admin", notes: "HMI/SCADA platform", cveReference: "CVE-2019-3953", source: "ICS-CERT advisory", tags: ["scada", "hmi", "ics"] },
  { vendor: "Mitsubishi", product: "MELSEC", protocol: "other", port: 5007, username: "", password: "", accessLevel: "admin", notes: "MC Protocol — no auth by default", source: "ICS-CERT advisory", tags: ["scada", "ics", "plc"] },
  { vendor: "Omron", product: "CJ2 PLC", protocol: "other", port: 9600, username: "", password: "", accessLevel: "admin", notes: "FINS protocol — no auth by default", source: "ICS-CERT advisory", tags: ["scada", "ics", "plc"] },
  { vendor: "B&R", product: "Automation Runtime", protocol: "web_admin", port: 80, username: "admin", password: "admin", accessLevel: "admin", source: "ICS-CERT advisory", tags: ["scada", "ics", "plc"] },

  // ─── Building Automation / BACnet ──────────────────────────────────
  { vendor: "Tridium", product: "Niagara", protocol: "https", port: 443, username: "admin", password: "admin", accessLevel: "admin", notes: "Niagara Framework BAS", source: "ICS-CERT advisory", tags: ["bas", "building_automation", "ics"] },
  { vendor: "Johnson Controls", product: "Metasys", protocol: "https", port: 443, username: "MetasysSysAgent", password: "Mets1234!", accessLevel: "admin", notes: "Building management system", source: "ICS-CERT advisory", tags: ["bas", "building_automation", "ics"] },
  { vendor: "Honeywell", product: "WEBs-AX", protocol: "https", port: 443, username: "admin", password: "admin", accessLevel: "admin", notes: "Niagara-based BAS", source: "ICS-CERT advisory", tags: ["bas", "building_automation", "ics"] },
  { vendor: "Schneider Electric", product: "SmartStruxure", protocol: "https", port: 443, username: "admin", password: "admin", accessLevel: "admin", source: "ICS-CERT advisory", tags: ["bas", "building_automation", "ics"] },

  // ─── Medical / Healthcare IoT ─────────────────────────────────────
  { vendor: "GE Healthcare", product: "CARESCAPE", protocol: "web_admin", port: 80, username: "admin", password: "admin", accessLevel: "admin", notes: "Patient monitoring", source: "ICS-CERT advisory", tags: ["medical", "iot", "healthcare"] },
  { vendor: "Philips", product: "IntelliVue", protocol: "web_admin", port: 80, username: "admin", password: "admin", accessLevel: "admin", notes: "Patient monitoring", source: "ICS-CERT advisory", tags: ["medical", "iot", "healthcare"] },
  { vendor: "BD", product: "Alaris Infusion", protocol: "web_admin", port: 80, username: "admin", password: "admin", accessLevel: "admin", notes: "Infusion pump", source: "ICS-CERT advisory", tags: ["medical", "iot", "healthcare"] },
  { vendor: "Baxter", product: "Sigma Spectrum", protocol: "web_admin", port: 80, username: "admin", password: "admin", accessLevel: "admin", notes: "Infusion pump", source: "ICS-CERT advisory", tags: ["medical", "iot", "healthcare"] },

  // ─── Additional Firewalls & UTM ───────────────────────────────────
  { vendor: "Sophos", product: "XG Firewall", protocol: "https", port: 4444, username: "admin", password: "admin", accessLevel: "admin", source: "Vendor documentation", tags: ["firewall", "utm", "network"] },
  { vendor: "Sophos", product: "UTM", protocol: "https", port: 4444, username: "admin", password: "", accessLevel: "admin", notes: "Set during initial wizard", source: "Vendor documentation", tags: ["firewall", "utm", "network"] },
  { vendor: "Barracuda", product: "CloudGen Firewall", protocol: "https", port: 443, username: "admin", password: "", accessLevel: "admin", notes: "Password set during setup", source: "Vendor documentation", tags: ["firewall", "network"] },
  { vendor: "Barracuda", product: "WAF", protocol: "https", port: 8443, username: "admin", password: "admin", accessLevel: "admin", source: "Vendor documentation", tags: ["waf", "web_security", "network"] },
  { vendor: "Forcepoint", product: "NGFW", protocol: "https", port: 8082, username: "admin", password: "admin", accessLevel: "admin", source: "Vendor documentation", tags: ["firewall", "network"] },
  { vendor: "Zyxel", product: "USG", protocol: "https", port: 443, username: "admin", password: "1234", accessLevel: "admin", cveReference: "CVE-2020-29583", source: "CVE advisory", tags: ["firewall", "network"] },
  { vendor: "Zyxel", product: "ATP", protocol: "https", port: 443, username: "admin", password: "1234", accessLevel: "admin", source: "Vendor documentation", tags: ["firewall", "network"] },
  { vendor: "Zyxel", product: "NAS", protocol: "web_admin", port: 5000, username: "admin", password: "1234", accessLevel: "admin", source: "Vendor documentation", tags: ["nas", "storage", "iot"] },

  // ─── Network Attached Storage ─────────────────────────────────────
  { vendor: "Synology", product: "DiskStation", protocol: "https", port: 5001, username: "admin", password: "", accessLevel: "admin", notes: "Empty password on first setup", source: "Vendor documentation", tags: ["nas", "storage"] },
  { vendor: "QNAP", product: "QTS", protocol: "https", port: 8080, username: "admin", password: "admin", accessLevel: "admin", source: "Vendor documentation", tags: ["nas", "storage"] },
  { vendor: "Western Digital", product: "My Cloud", protocol: "web_admin", port: 80, username: "admin", password: "", accessLevel: "admin", notes: "No password by default", cveReference: "CVE-2018-17153", source: "CVE advisory", tags: ["nas", "storage", "iot"] },
  { vendor: "Buffalo", product: "TeraStation", protocol: "web_admin", port: 80, username: "admin", password: "password", accessLevel: "admin", source: "Vendor documentation", tags: ["nas", "storage"] },

  // ─── Wireless Access Points ───────────────────────────────────────
  { vendor: "Ruckus", product: "ZoneDirector", protocol: "https", port: 443, username: "super", password: "sp-admin", accessLevel: "admin", source: "Vendor documentation", tags: ["wireless", "network"] },
  { vendor: "Ruckus", product: "Unleashed", protocol: "https", port: 443, username: "super", password: "sp-admin", accessLevel: "admin", source: "Vendor documentation", tags: ["wireless", "network"] },
  { vendor: "Meraki", product: "MR AP", protocol: "web_admin", port: 80, username: "", password: "", accessLevel: "admin", notes: "Cloud-managed — local admin often disabled", source: "Vendor documentation", tags: ["wireless", "network", "cloud"] },
  { vendor: "Fortinet", product: "FortiAP", protocol: "ssh", port: 22, username: "admin", password: "", accessLevel: "admin", notes: "Empty password on factory reset", source: "Vendor documentation", tags: ["wireless", "network"] },
  { vendor: "Aruba", product: "Instant AP", protocol: "https", port: 4343, username: "admin", password: "admin", accessLevel: "admin", source: "Vendor documentation", tags: ["wireless", "network"] },

  // ─── Load Balancers & ADC ─────────────────────────────────────────
  { vendor: "F5", product: "BIG-IP", protocol: "https", port: 443, username: "admin", password: "admin", accessLevel: "admin", source: "Vendor documentation", tags: ["load_balancer", "adc", "network"] },
  { vendor: "F5", product: "BIG-IP", protocol: "ssh", port: 22, username: "root", password: "default", accessLevel: "root", source: "Vendor documentation", tags: ["load_balancer", "adc", "network"] },
  { vendor: "Citrix", product: "NetScaler", protocol: "https", port: 443, username: "nsroot", password: "nsroot", accessLevel: "admin", source: "Vendor documentation", tags: ["load_balancer", "adc", "network"] },
  { vendor: "Citrix", product: "NetScaler", protocol: "ssh", port: 22, username: "nsroot", password: "nsroot", accessLevel: "admin", source: "Vendor documentation", tags: ["load_balancer", "adc", "network"] },
  { vendor: "HAProxy", product: "HAProxy", protocol: "http", port: 8404, username: "admin", password: "admin", accessLevel: "admin", notes: "Stats page default", source: "Common misconfiguration", tags: ["load_balancer", "network", "open_source"] },
  { vendor: "Kemp", product: "LoadMaster", protocol: "https", port: 443, username: "bal", password: "1fourall", accessLevel: "admin", source: "Vendor documentation", tags: ["load_balancer", "adc", "network"] },

  // ─── Containers & Orchestration ───────────────────────────────────
  { vendor: "Kubernetes", product: "Dashboard", protocol: "https", port: 8443, username: "", password: "", accessLevel: "admin", notes: "Often exposed without auth", source: "Common misconfiguration", tags: ["container", "orchestration", "devops"] },
  { vendor: "Rancher", product: "Rancher", protocol: "https", port: 443, username: "admin", password: "admin", accessLevel: "admin", source: "Vendor documentation", tags: ["container", "orchestration", "devops"] },
  { vendor: "Docker", product: "Docker API", protocol: "http", port: 2375, username: "", password: "", accessLevel: "root", notes: "Unauthenticated Docker API", source: "Common misconfiguration", tags: ["container", "devops"] },
  { vendor: "Docker", product: "Docker Registry", protocol: "http", port: 5000, username: "", password: "", accessLevel: "admin", notes: "Unauthenticated registry", source: "Common misconfiguration", tags: ["container", "registry", "devops"] },
  { vendor: "HashiCorp", product: "Vault", protocol: "http", port: 8200, username: "", password: "", accessLevel: "admin", notes: "Dev mode — no auth", source: "HashiCorp documentation", tags: ["secrets", "devops"] },
  { vendor: "HashiCorp", product: "Nomad", protocol: "http", port: 4646, username: "", password: "", accessLevel: "admin", notes: "No ACL by default", source: "HashiCorp documentation", tags: ["orchestration", "devops"] },

  // ─── CI/CD & DevOps ───────────────────────────────────────────────
  { vendor: "JFrog", product: "Artifactory", protocol: "http", port: 8081, username: "admin", password: "password", accessLevel: "admin", source: "JFrog documentation", tags: ["artifact_repo", "devops"] },
  { vendor: "Nexus", product: "Repository Manager", protocol: "http", port: 8081, username: "admin", password: "admin123", accessLevel: "admin", source: "Sonatype documentation", tags: ["artifact_repo", "devops"] },
  { vendor: "TeamCity", product: "TeamCity", protocol: "http", port: 8111, username: "admin", password: "admin", accessLevel: "admin", source: "JetBrains documentation", tags: ["ci_cd", "devops"] },
  { vendor: "Bamboo", product: "Bamboo", protocol: "http", port: 8085, username: "admin", password: "admin", accessLevel: "admin", source: "Atlassian documentation", tags: ["ci_cd", "devops"] },
  { vendor: "GoCD", product: "GoCD", protocol: "http", port: 8153, username: "admin", password: "admin", accessLevel: "admin", source: "Vendor documentation", tags: ["ci_cd", "devops", "open_source"] },
  { vendor: "Argo", product: "Argo CD", protocol: "https", port: 443, username: "admin", password: "", accessLevel: "admin", notes: "Password is the pod name on first install", source: "Argo documentation", tags: ["ci_cd", "devops", "kubernetes"] },

  // ─── Email & Collaboration ────────────────────────────────────────
  { vendor: "Zimbra", product: "Zimbra", protocol: "https", port: 7071, username: "admin", password: "admin", accessLevel: "admin", notes: "Admin console", source: "Vendor documentation", tags: ["email", "collaboration"] },
  { vendor: "Roundcube", product: "Roundcube", protocol: "http", port: 80, username: "admin", password: "admin", accessLevel: "admin", source: "Common misconfiguration", tags: ["email", "webmail"] },
  { vendor: "Mattermost", product: "Mattermost", protocol: "http", port: 8065, username: "admin", password: "admin", accessLevel: "admin", source: "Common misconfiguration", tags: ["collaboration", "chat"] },

  // ─── Additional IoT / Embedded ────────────────────────────────────
  { vendor: "Ubiquiti", product: "AirOS", protocol: "ssh", port: 22, username: "ubnt", password: "ubnt", accessLevel: "admin", source: "Vendor documentation", tags: ["wireless", "iot", "network"] },
  { vendor: "Ubiquiti", product: "UniFi Protect", protocol: "https", port: 443, username: "ubnt", password: "ubnt", accessLevel: "admin", source: "Vendor documentation", tags: ["surveillance", "iot", "camera"] },
  { vendor: "FLIR", product: "Thermal Camera", protocol: "web_admin", port: 80, username: "admin", password: "admin", accessLevel: "admin", source: "Vendor documentation", tags: ["camera", "iot", "surveillance"] },
  { vendor: "Bosch", product: "IP Camera", protocol: "web_admin", port: 80, username: "", password: "", accessLevel: "admin", notes: "No password on factory reset", source: "Vendor documentation", tags: ["camera", "iot", "surveillance"] },
  { vendor: "Crestron", product: "Control System", protocol: "web_admin", port: 80, username: "admin", password: "admin", accessLevel: "admin", source: "Vendor documentation", tags: ["iot", "building_automation", "av"] },
  { vendor: "Extron", product: "Control System", protocol: "web_admin", port: 80, username: "admin", password: "extron", accessLevel: "admin", source: "Vendor documentation", tags: ["iot", "building_automation", "av"] },
  { vendor: "AMX", product: "NX Controller", protocol: "web_admin", port: 80, username: "administrator", password: "password", accessLevel: "admin", source: "Vendor documentation", tags: ["iot", "building_automation", "av"] },

  // ─── Physical Access Control ──────────────────────────────────────
  { vendor: "HID", product: "VertX", protocol: "web_admin", port: 80, username: "root", password: "pass", accessLevel: "admin", notes: "Physical access controller", source: "Security research", tags: ["physical_access", "iot"] },
  { vendor: "Lenel", product: "OnGuard", protocol: "https", port: 443, username: "admin", password: "admin", accessLevel: "admin", notes: "Access control management", source: "Vendor documentation", tags: ["physical_access", "iot"] },
  { vendor: "Genetec", product: "Security Center", protocol: "https", port: 443, username: "admin", password: "", accessLevel: "admin", notes: "Set during installation", source: "Vendor documentation", tags: ["physical_access", "surveillance", "iot"] },

  // ─── Additional Databases ─────────────────────────────────────────
  { vendor: "Cassandra", product: "Apache Cassandra", protocol: "other", port: 9042, username: "cassandra", password: "cassandra", accessLevel: "admin", source: "Apache documentation", tags: ["database", "nosql"] },
  { vendor: "InfluxDB", product: "InfluxDB", protocol: "http", port: 8086, username: "admin", password: "admin", accessLevel: "admin", source: "Vendor documentation", tags: ["database", "timeseries"] },
  { vendor: "Neo4j", product: "Neo4j", protocol: "http", port: 7474, username: "neo4j", password: "neo4j", accessLevel: "admin", notes: "Forces password change on first login", source: "Neo4j documentation", tags: ["database", "graph"] },
  { vendor: "Memcached", product: "Memcached", protocol: "other", port: 11211, username: "", password: "", accessLevel: "admin", notes: "No auth by default", source: "Common misconfiguration", tags: ["database", "cache"] },
  { vendor: "ClickHouse", product: "ClickHouse", protocol: "http", port: 8123, username: "default", password: "", accessLevel: "admin", notes: "Empty password by default", source: "ClickHouse documentation", tags: ["database", "analytics"] },

  // ─── Additional Server Management ─────────────────────────────────
  { vendor: "Lenovo", product: "XClarity", protocol: "https", port: 443, username: "USERID", password: "PASSW0RD", accessLevel: "admin", source: "Lenovo documentation", tags: ["bmc", "server_management"] },
  { vendor: "Cisco", product: "CIMC", protocol: "https", port: 443, username: "admin", password: "password", accessLevel: "admin", notes: "Cisco Integrated Management Controller", source: "Vendor documentation", tags: ["bmc", "server_management"] },
  { vendor: "Oracle", product: "ILOM", protocol: "https", port: 443, username: "root", password: "changeme", accessLevel: "root", source: "Oracle documentation", tags: ["bmc", "server_management"] },
  { vendor: "Fujitsu", product: "iRMC", protocol: "https", port: 443, username: "admin", password: "admin", accessLevel: "admin", source: "Vendor documentation", tags: ["bmc", "server_management"] },
];

/**
 * Match discovered technologies against the default credentials database.
 * Returns credentials that operators and automated tools can use during active testing.
 */
export function matchCredentialsForTechnology(tech: {
  name?: string;
  vendor?: string;
  version?: string;
  cpe?: string;
  port?: number;
  protocol?: string;
}): typeof BUILTIN_DEFAULT_CREDS {
  const matches: typeof BUILTIN_DEFAULT_CREDS = [];
  const techName = (tech.name || "").toLowerCase();
  const techVendor = (tech.vendor || "").toLowerCase();
  const techCpe = (tech.cpe || "").toLowerCase();

  for (const cred of BUILTIN_DEFAULT_CREDS) {
    const credVendor = cred.vendor.toLowerCase();
    const credProduct = cred.product.toLowerCase();
    let matched = false;

    // Match by vendor + product name in technology name or CPE
    if (techName.includes(credVendor) || techName.includes(credProduct)) matched = true;
    if (techVendor.includes(credVendor)) matched = true;
    if (techCpe.includes(credVendor) || techCpe.includes(credProduct.replace(/\s+/g, "_"))) matched = true;

    // Match by port if protocol matches
    if (tech.port && cred.port === tech.port && tech.protocol && cred.protocol === tech.protocol.toLowerCase()) {
      // Port+protocol match is a weaker signal, combine with partial name match
      if (techName.includes(credVendor.split(" ")[0]) || techName.includes(credProduct.split(" ")[0])) matched = true;
    }

    if (matched) matches.push(cred);
  }

  return matches;
}

/**
 * Match credentials for a list of technologies discovered on an asset.
 * Returns deduplicated credentials grouped by service.
 */
export function matchCredentialsForAsset(technologies: Array<{
  name?: string;
  vendor?: string;
  version?: string;
  cpe?: string;
  port?: number;
  protocol?: string;
}>): Array<{
  service: string;
  port?: number;
  credentials: Array<{ vendor: string; product: string; protocol: string; username: string; password: string; accessLevel: string; notes?: string }>;
}> {
  const serviceMap = new Map<string, {
    port?: number;
    credentials: Map<string, { vendor: string; product: string; protocol: string; username: string; password: string; accessLevel: string; notes?: string }>;
  }>();

  for (const tech of technologies) {
    const matches = matchCredentialsForTechnology(tech);
    for (const cred of matches) {
      const serviceKey = `${cred.vendor}:${cred.product}:${cred.port || "any"}`;
      if (!serviceMap.has(serviceKey)) {
        serviceMap.set(serviceKey, { port: cred.port, credentials: new Map() });
      }
      const credKey = `${cred.username}:${cred.password}`;
      if (!serviceMap.get(serviceKey)!.credentials.has(credKey)) {
        serviceMap.get(serviceKey)!.credentials.set(credKey, {
          vendor: cred.vendor,
          product: cred.product,
          protocol: cred.protocol,
          username: cred.username,
          password: cred.password,
          accessLevel: cred.accessLevel,
          notes: cred.notes,
        });
      }
    }
  }

  return Array.from(serviceMap.entries()).map(([key, val]) => ({
    service: key.split(":").slice(0, 2).join(" "),
    port: val.port,
    credentials: Array.from(val.credentials.values()),
  }));
}

/**
 * Seed the database with built-in credentials (run once on first startup).
 */
export async function seedBuiltinCredentials(): Promise<number> {
  const db = await getDb();
  if (!db) return 0;

  // Check if already seeded
  const [existing] = await db.select({ count: sql<number>`COUNT(*)` }).from(oemDefaultCredentials);
  if (Number(existing?.count || 0) > 0) return 0;

  let inserted = 0;
  // Batch insert in groups of 10
  for (let i = 0; i < BUILTIN_DEFAULT_CREDS.length; i += 10) {
    const batch = BUILTIN_DEFAULT_CREDS.slice(i, i + 10);
    try {
      await db.insert(oemDefaultCredentials).values(
        batch.map(c => ({
          vendor: c.vendor,
          product: c.product,
          version: c.version || null,
          protocol: c.protocol,
          port: c.port || null,
          username: c.username,
          password: c.password,
          accessLevel: c.accessLevel || null,
          notes: c.notes || null,
          cveReference: c.cveReference || null,
          source: c.source || null,
          tags: c.tags,
        }))
      );
      inserted += batch.length;
    } catch (err) {
      console.error("[OemCreds] Batch insert failed, trying individual:", err);
      for (const c of batch) {
        try {
          await db.insert(oemDefaultCredentials).values({
            vendor: c.vendor, product: c.product, version: c.version || null,
            protocol: c.protocol, port: c.port || null, username: c.username,
            password: c.password, accessLevel: c.accessLevel || null,
            notes: c.notes || null, cveReference: c.cveReference || null,
            source: c.source || null, tags: c.tags,
          });
          inserted++;
        } catch { /* skip duplicates */ }
      }
    }
  }
  console.log(`[OemCreds] Seeded ${inserted} default credentials`);
  return inserted;
}

/**
 * Search the DB for credentials matching a query (for AI assistant and operator lookup).
 */
export async function searchCredentials(query: string): Promise<any[]> {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(oemDefaultCredentials).where(
    or(
      like(oemDefaultCredentials.vendor, `%${query}%`),
      like(oemDefaultCredentials.product, `%${query}%`),
      like(oemDefaultCredentials.protocol, `%${query}%`),
    )
  ).limit(50);
}

/**
 * Match credentials for multiple assets (used by the domain intel pipeline).
 * Returns a flat array of matched credentials with the asset they matched against.
 */
export function matchCredentialsForAssets(assets: Array<{
  hostname: string;
  technologies: string[];
  technologyVersions?: Record<string, string>;
  openPorts?: number[];
}>): Array<{
  vendor: string;
  product: string;
  protocol: string;
  port: number | null;
  username: string;
  password: string;
  accessLevel: string;
  tags: string[];
  matchedTechnology: string;
  matchedAsset: string;
}> {
  const results: Array<{
    vendor: string;
    product: string;
    protocol: string;
    port: number | null;
    username: string;
    password: string;
    accessLevel: string;
    tags: string[];
    matchedTechnology: string;
    matchedAsset: string;
  }> = [];

  const seen = new Set<string>();

  for (const asset of assets) {
    for (const techName of asset.technologies) {
      const version = asset.technologyVersions?.[techName];
      const matches = matchCredentialsForTechnology({
        name: techName,
        version: version || undefined,
      });

      for (const cred of matches) {
        // Deduplicate: same cred for same asset
        const dedupeKey = `${asset.hostname}|${cred.vendor}|${cred.product}|${cred.username}|${cred.password}`;
        if (seen.has(dedupeKey)) continue;
        seen.add(dedupeKey);

        results.push({
          vendor: cred.vendor,
          product: cred.product,
          protocol: cred.protocol,
          port: cred.port,
          username: cred.username,
          password: cred.password,
          accessLevel: cred.accessLevel,
          tags: cred.tags,
          matchedTechnology: techName + (version ? ` ${version}` : ''),
          matchedAsset: asset.hostname,
        });
      }
    }
  }

  return results;
}

/**
 * Persist matched credentials to the database for reference by operators, AI chat, and automated tools.
 */
export async function persistMatchedCredentials(
  domain: string,
  credentials: Array<{
    vendor: string;
    product: string;
    protocol: string;
    port: number | null;
    username: string;
    password: string;
    accessLevel: string;
    tags: string[];
    matchedTechnology: string;
    matchedAsset: string;
  }>
): Promise<number> {
  const db = await getDb();
  if (!db || credentials.length === 0) return 0;

  let persisted = 0;
  for (const cred of credentials) {
    try {
      await db.insert(oemDefaultCredentials).values({
        vendor: cred.vendor,
        product: cred.product,
        protocol: cred.protocol,
        port: cred.port,
        username: cred.username,
        password: cred.password,
        accessLevel: cred.accessLevel,
        tags: JSON.stringify(cred.tags),
        notes: `Auto-matched from ${domain} scan: ${cred.matchedTechnology} on ${cred.matchedAsset}`,
      }).onDuplicateKeyUpdate({
        set: {
          notes: `Auto-matched from ${domain} scan: ${cred.matchedTechnology} on ${cred.matchedAsset}`,
        },
      });
      persisted++;
    } catch (err: any) {
      // Ignore duplicates or constraint violations
      if (!err.message?.includes('Duplicate')) {
        console.error(`[OEM Creds] Failed to persist ${cred.vendor}/${cred.product}: ${err.message}`);
      }
    }
  }
  return persisted;
}
