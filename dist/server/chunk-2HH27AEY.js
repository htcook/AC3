// server/lib/digitalocean-infra.ts
var DO_API = "https://api.digitalocean.com/v2";
function getToken() {
  const token = process.env.DIGITALOCEAN_ACCESS_TOKEN;
  if (!token) throw new Error("DIGITALOCEAN_ACCESS_TOKEN is not configured");
  return token;
}
async function doFetch(path, opts = {}) {
  const res = await fetch(`${DO_API}${path}`, {
    ...opts,
    headers: {
      Authorization: `Bearer ${getToken()}`,
      "Content-Type": "application/json",
      ...opts.headers
    }
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`DO API ${res.status}: ${body}`);
  }
  if (res.status === 204) return null;
  return res.json();
}
function mapDroplet(d) {
  const pub = d.networks?.v4?.find((n) => n.type === "public");
  const priv = d.networks?.v4?.find((n) => n.type === "private");
  return {
    id: d.id,
    name: d.name,
    status: d.status,
    region: d.region?.slug ?? d.region,
    sizeSlug: d.size_slug ?? d.size?.slug ?? "",
    ipv4Public: pub?.ip_address ?? null,
    ipv4Private: priv?.ip_address ?? null,
    tags: d.tags ?? [],
    createdAt: d.created_at,
    memory: d.memory,
    vcpus: d.vcpus,
    disk: d.disk
  };
}
async function listDroplets(tag) {
  const qs = tag ? `?tag_name=${encodeURIComponent(tag)}` : "";
  const data = await doFetch(`/droplets${qs}`);
  return (data.droplets ?? []).map(mapDroplet);
}
async function createDroplet(opts) {
  const data = await doFetch("/droplets", {
    method: "POST",
    body: JSON.stringify({
      name: opts.name,
      region: opts.region,
      size: opts.size,
      image: opts.image,
      ssh_keys: opts.sshKeys ?? [],
      tags: opts.tags ?? [],
      user_data: opts.userData ?? "",
      monitoring: opts.monitoring ?? true,
      backups: false
    })
  });
  return mapDroplet(data.droplet);
}
async function deleteDroplet(id) {
  await doFetch(`/droplets/${id}`, { method: "DELETE" });
}
async function getDroplet(id) {
  const data = await doFetch(`/droplets/${id}`);
  return mapDroplet(data.droplet);
}
async function healthCheckAll(tag) {
  const droplets = await listDroplets(tag);
  const results = [];
  for (const d of droplets) {
    let httpReachable = false;
    if (d.ipv4Public && d.status === "active") {
      try {
        const r = await fetch(`http://${d.ipv4Public}/`, { signal: AbortSignal.timeout(5e3) });
        httpReachable = r.ok || r.status < 500;
      } catch {
      }
    }
    results.push({ dropletId: d.id, name: d.name, ip: d.ipv4Public, status: d.status, httpReachable, checkedAt: Date.now() });
  }
  return results;
}
function mapFirewall(fw) {
  return {
    id: fw.id,
    name: fw.name,
    status: fw.status,
    dropletIds: fw.droplet_ids ?? [],
    inboundRules: (fw.inbound_rules ?? []).map((r) => ({ protocol: r.protocol, ports: r.ports, sources: r.sources })),
    outboundRules: (fw.outbound_rules ?? []).map((r) => ({ protocol: r.protocol, ports: r.ports, destinations: r.destinations }))
  };
}
async function listFirewalls() {
  const data = await doFetch("/firewalls");
  return (data.firewalls ?? []).map(mapFirewall);
}
async function deleteFirewall(id) {
  await doFetch(`/firewalls/${id}`, { method: "DELETE" });
}
async function listSshKeys() {
  const data = await doFetch("/account/keys");
  return (data.ssh_keys ?? []).map((k) => ({ id: k.id, name: k.name, fingerprint: k.fingerprint, publicKey: k.public_key }));
}
function generateRedirectorUserData(opts) {
  const adminCidr = opts.adminCidr ?? "0.0.0.0/0";
  const base = `#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get upgrade -y -qq
apt-get install -y -qq ufw fail2ban socat
sed -i 's/#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#\\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
systemctl restart sshd
ufw default deny incoming
ufw default allow outgoing
ufw allow from ${adminCidr} to any port 22
`;
  if (opts.type === "http") {
    return `${base}
apt-get install -y -qq nginx certbot python3-certbot-nginx
cat > /etc/nginx/sites-available/redirector <<'NGINX'
server {
    listen 80;
    server_name _;
    location / {
        proxy_pass http://${opts.backendHost}:${opts.backendPort};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
NGINX
ln -sf /etc/nginx/sites-available/redirector /etc/nginx/sites-enabled/default
nginx -t && systemctl restart nginx
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable
`;
  }
  if (opts.type === "smtp") {
    return `${base}
debconf-set-selections <<< "postfix postfix/main_mailer_type select Internet Site"
debconf-set-selections <<< "postfix postfix/mailname string $(hostname -f)"
apt-get install -y -qq postfix
postconf -e "relayhost = [${opts.backendHost}]:${opts.backendPort}"
postconf -e "smtp_tls_security_level = may"
systemctl restart postfix
ufw allow 25/tcp
ufw allow 587/tcp
ufw --force enable
`;
  }
  if (opts.type === "dns") {
    return `${base}
cat > /etc/systemd/system/dns-redir.service <<EOF
[Unit]
Description=DNS Redirector
After=network.target
[Service]
ExecStart=/usr/bin/socat UDP4-LISTEN:53,reuseaddr,fork UDP4:${opts.backendHost}:${opts.backendPort}
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable --now dns-redir
ufw allow 53/tcp
ufw allow 53/udp
ufw --force enable
`;
  }
  return `${base}
cat > /etc/systemd/system/c2-redir.service <<EOF
[Unit]
Description=C2 Redirector
After=network.target
[Service]
ExecStart=/usr/bin/socat TCP4-LISTEN:443,reuseaddr,fork TCP4:${opts.backendHost}:${opts.backendPort}
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable --now c2-redir
ufw allow 443/tcp
ufw --force enable
`;
}
function generateTeamServerUserData(opts = {}) {
  const port = opts.calderaPort ?? 8888;
  const adminCidr = opts.adminCidr ?? "0.0.0.0/0";
  return `#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get upgrade -y -qq
apt-get install -y -qq ufw fail2ban docker.io docker-compose-plugin
sed -i 's/#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd
ufw default deny incoming
ufw default allow outgoing
ufw allow from ${adminCidr} to any port 22
ufw allow from ${adminCidr} to any port ${port}
ufw --force enable
systemctl enable --now docker
echo "Team server ready \u2014 port ${port}"
`;
}

export {
  listDroplets,
  createDroplet,
  deleteDroplet,
  getDroplet,
  healthCheckAll,
  listFirewalls,
  deleteFirewall,
  listSshKeys,
  generateRedirectorUserData,
  generateTeamServerUserData
};
