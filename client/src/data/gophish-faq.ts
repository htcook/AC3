import type { FAQItem } from '@/components/FAQ';

export const gophishFAQItems: FAQItem[] = [
  // --- Emails Going to Spam ---
  {
    id: 'gp-spam-1',
    question: 'My phishing emails are going directly to spam/junk folders. How do I fix this?',
    answer: `This is one of the most common issues in phishing simulations. Follow these steps in order:

1. **Set up SPF records**: Add a TXT record to your sending domain's DNS:
   v=spf1 ip4:YOUR_SERVER_IP include:_spf.google.com ~all

2. **Configure DKIM signing**: Install OpenDKIM on your mail server and add the DKIM TXT record to DNS. This cryptographically signs your emails.

3. **Add a DMARC policy**: Add a DMARC TXT record:
   v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com

4. **Warm up the sending domain**: Start by sending 10-20 emails per day to legitimate addresses and gradually increase volume over 2-3 weeks.

5. **Use a reputable sending domain**: Avoid newly registered domains. Domains with at least 30 days of age and some legitimate email history perform better.

6. **Check blacklists**: Verify your IP is not on any email blacklists using mxtoolbox.com/blacklists.aspx`,
    category: 'Email Delivery',
    tags: ['spam', 'SPF', 'DKIM', 'DMARC', 'deliverability', 'email'],
    severity: 'critical',
  },
  {
    id: 'gp-spam-2',
    question: 'Emails are being blocked by Microsoft 365 / Exchange Online Protection',
    answer: `Microsoft 365 has aggressive filtering. To improve delivery:

1. **Whitelist in Exchange Admin Center**: Go to Mail Flow → Rules → Create a new rule to bypass spam filtering for your sending IP/domain.

2. **Add to Safe Senders**: Ask the target organization's IT team to add your sending domain to the organization-wide safe senders list (for authorized engagements only).

3. **Use the SCL header trick**: In GoPhish, add a custom header X-MS-Exchange-Organization-SCL: -1 (only works if you have Exchange admin access).

4. **Avoid trigger words**: Remove words like "urgent", "click here", "verify your account" from subject lines. Use more subtle social engineering.

5. **Send from a subdomain**: Use phishing.yourdomain.com instead of yourdomain.com to avoid impacting your primary domain reputation.

6. **Stagger sending**: Don't send all emails at once. Use GoPhish's "Send By" date to spread delivery over hours.`,
    category: 'Email Delivery',
    tags: ['Microsoft 365', 'Exchange', 'spam filter', 'whitelisting'],
    severity: 'high',
  },
  {
    id: 'gp-spam-3',
    question: 'How do I test email deliverability before launching a campaign?',
    answer: `Before launching a full campaign, always test deliverability:

1. **Send test emails**: Use GoPhish's "Send Test Email" feature in the campaign creation wizard. Send to your own test accounts on the target email platform.

2. **Check headers**: Examine the received email headers for SPF/DKIM/DMARC pass/fail results. Look for "Authentication-Results" header.

3. **Use mail-tester.com**: Send a test email to the address provided by mail-tester.com. It gives a score out of 10 and identifies issues.

4. **Monitor bounce rates**: If more than 5% of emails bounce, stop and investigate. High bounce rates damage sender reputation.

5. **Check with MXToolbox**: Run your domain through mxtoolbox.com to verify DNS records, blacklist status, and SMTP connectivity.

6. **Test across providers**: Send test emails to Gmail, Outlook, Yahoo, and the target organization's email platform.`,
    category: 'Email Delivery',
    tags: ['testing', 'deliverability', 'pre-launch', 'mail-tester'],
    severity: 'medium',
  },

  // --- SMTP Issues ---
  {
    id: 'gp-smtp-1',
    question: 'SMTP connection failed: "dial tcp: connection refused" error',
    answer: `This error means GoPhish cannot connect to the SMTP server. Common causes:

1. **Wrong port**: Verify the SMTP port in your sending profile. Common ports:
   - 25 (unencrypted, often blocked by ISPs)
   - 465 (SSL/TLS)
   - 587 (STARTTLS, recommended)

2. **Firewall blocking**: Check that your server's firewall allows outbound connections on the SMTP port:
   sudo ufw allow out 587/tcp
   sudo ufw allow out 465/tcp

3. **SMTP server down**: Verify the SMTP server is running:
   telnet smtp.yourdomain.com 587

4. **DNS resolution**: Ensure the SMTP hostname resolves correctly:
   nslookup smtp.yourdomain.com

5. **Local Postfix**: If using local Postfix relay, verify it's running:
   sudo systemctl status postfix
   sudo postfix check`,
    category: 'SMTP Configuration',
    tags: ['SMTP', 'connection refused', 'firewall', 'port'],
    severity: 'critical',
  },
  {
    id: 'gp-smtp-2',
    question: 'SMTP authentication failed: "535 Authentication credentials invalid"',
    answer: `Authentication failures typically have these causes:

1. **Wrong credentials**: Double-check the username and password in your GoPhish sending profile. For Gmail, you need an App Password, not your regular password.

2. **2FA blocking**: If the SMTP account has two-factor authentication enabled, you must use an application-specific password.

3. **Account lockout**: Too many failed attempts may lock the account. Wait 15-30 minutes and try again.

4. **Less secure apps**: Some providers (Gmail, Yahoo) require enabling "Less Secure App Access" or generating an App Password.

5. **For local Postfix relay**: If using local relay (localhost:25), you typically don't need authentication. Set username and password to empty in the sending profile.

6. **Check sending profile**: In GoPhish, go to Sending Profiles and verify:
   - Host: smtp.provider.com:587
   - Username: your-email@domain.com
   - Password: your-app-password
   - Check "Ignore Certificate Errors" if using self-signed certs`,
    category: 'SMTP Configuration',
    tags: ['SMTP', 'authentication', 'credentials', 'password'],
    severity: 'high',
  },
  {
    id: 'gp-smtp-3',
    question: 'Emails are sending but recipients never receive them (silent failure)',
    answer: `Silent delivery failures are tricky. Here's how to diagnose:

1. **Check GoPhish campaign status**: Look at the campaign timeline. If emails show "Sent" but not "Opened", they may be silently dropped.

2. **Check mail server logs**: If using Postfix:
   sudo tail -f /var/log/mail.log
   Look for "status=sent", "status=deferred", or "status=bounced".

3. **Check for greylisting**: Some mail servers temporarily reject emails from unknown senders. The email should be retried automatically after 5-15 minutes.

4. **Verify reverse DNS (PTR record)**: Your server IP should have a PTR record matching your sending domain. Check with:
   dig -x YOUR_SERVER_IP

5. **Check email size**: Very large emails (>10MB) may be silently dropped. Keep templates under 1MB.

6. **Monitor SMTP conversation**: Use telnet to manually test SMTP delivery and watch for error codes:
   telnet smtp.target.com 25
   EHLO yourdomain.com
   MAIL FROM:<sender@yourdomain.com>
   RCPT TO:<target@target.com>`,
    category: 'SMTP Configuration',
    tags: ['silent failure', 'delivery', 'greylisting', 'PTR record'],
    severity: 'high',
  },

  // --- Landing Page Issues ---
  {
    id: 'gp-landing-1',
    question: 'Landing page is not capturing credentials when users submit the form',
    answer: `If your landing page form submissions aren't being recorded:

1. **Enable credential capture**: In GoPhish, edit the landing page and ensure both "Capture Submitted Data" and "Capture Passwords" checkboxes are enabled.

2. **Check form action**: The form's action attribute must be empty or point to the GoPhish tracking URL. GoPhish automatically rewrites forms, but custom HTML may break this.

3. **Form field names**: GoPhish captures fields by their "name" attribute. Ensure your form inputs have name attributes:
   <input type="text" name="username" />
   <input type="password" name="password" />

4. **JavaScript interference**: If your landing page uses JavaScript form submission (e.g., AJAX), GoPhish may not intercept it. Use standard HTML form submission instead.

5. **Redirect URL**: Set a redirect URL in the landing page settings so users are redirected after submission. Without this, the page may appear broken after submit.

6. **Test the landing page**: Use GoPhish's preview feature to test the page before launching a campaign. Submit test credentials and verify they appear in the campaign results.`,
    category: 'Landing Pages',
    tags: ['credentials', 'capture', 'form', 'landing page'],
    severity: 'critical',
  },
  {
    id: 'gp-landing-2',
    question: 'Landing page looks broken or has missing images/CSS',
    answer: `Broken landing pages usually have resource loading issues:

1. **Use absolute URLs**: When importing a site, change all relative URLs (./style.css) to absolute URLs (https://target.com/style.css).

2. **Import site feature**: Use GoPhish's "Import Site" button which automatically fetches and converts resources. Enter the target URL and click Import.

3. **Inline CSS**: For best results, inline all CSS styles directly in the HTML rather than using external stylesheets.

4. **Base64 encode images**: Convert small images to base64 and embed them directly in the HTML:
   <img src="data:image/png;base64,..." />

5. **HTTPS mixed content**: If your GoPhish server uses HTTPS, all resources must also use HTTPS. Mixed content will be blocked by browsers.

6. **Test in multiple browsers**: Some CSS features may render differently across browsers. Test in Chrome, Firefox, and Edge.`,
    category: 'Landing Pages',
    tags: ['CSS', 'images', 'broken', 'rendering'],
    severity: 'medium',
  },

  // --- Campaign Issues ---
  {
    id: 'gp-campaign-1',
    question: 'Campaign is stuck in "Queued" status and not sending emails',
    answer: `A campaign stuck in "Queued" status usually indicates a sending issue:

1. **Check SMTP profile**: Verify your sending profile is correctly configured. Go to Sending Profiles → Test and send a test email.

2. **Launch date**: If you set a future "Launch Date", the campaign won't start until that time. Check the campaign settings.

3. **GoPhish process**: Ensure the GoPhish process is running and not crashed:
   sudo systemctl status gophish
   sudo journalctl -u gophish -f

4. **Port conflicts**: If GoPhish's phishing server (default port 80/443) conflicts with another service, campaigns may fail silently.

5. **Target group**: Verify the target group has valid email addresses. Invalid addresses will cause the entire batch to fail.

6. **Restart GoPhish**: Sometimes a restart resolves queuing issues:
   sudo systemctl restart gophish`,
    category: 'Campaigns',
    tags: ['queued', 'stuck', 'not sending', 'campaign'],
    severity: 'high',
  },
  {
    id: 'gp-campaign-2',
    question: 'How do I track which users clicked links vs. submitted credentials?',
    answer: `GoPhish provides detailed tracking at each stage of the phishing funnel:

1. **Campaign Timeline**: Click on a campaign to see the timeline. Each event is tracked:
   - Email Sent: Email was delivered
   - Email Opened: Tracking pixel was loaded (not 100% reliable)
   - Clicked Link: User clicked the phishing URL
   - Submitted Data: User submitted the form
   - Reported: User reported the email (if configured)

2. **Results tab**: The Results tab shows a table with each target and their status. You can filter by status.

3. **API access**: Use the GoPhish API to programmatically access results:
   GET /api/campaigns/{id}/results

4. **CSV export**: Click "Export CSV" on the campaign page to download all results.

5. **Unique tracking**: Each target gets a unique tracking URL (with ?rid= parameter). This ensures accurate per-user tracking.

6. **Real-time updates**: The campaign page auto-refreshes. You can also use the API for real-time monitoring.`,
    category: 'Campaigns',
    tags: ['tracking', 'clicks', 'credentials', 'results', 'analytics'],
    severity: 'low',
  },
  {
    id: 'gp-campaign-3',
    question: 'Campaign shows "Error" status for some targets',
    answer: `Individual target errors usually indicate delivery problems:

1. **Invalid email**: The target email address may be invalid or the mailbox doesn't exist. Verify addresses before launching.

2. **Bounce back**: The target's mail server rejected the email. Check GoPhish logs for bounce details:
   sudo journalctl -u gophish | grep -i error

3. **Rate limiting**: Some mail servers limit incoming emails. If you're sending to many addresses at the same domain, stagger delivery.

4. **Connection timeout**: The target's mail server may be slow or unreachable. Increase the timeout in your sending profile.

5. **Per-target status**: Click on the individual target in the campaign results to see the specific error message.

6. **Retry strategy**: GoPhish doesn't automatically retry failed sends. You may need to create a new campaign targeting only the failed addresses.`,
    category: 'Campaigns',
    tags: ['error', 'bounce', 'failed', 'target'],
    severity: 'medium',
  },

  // --- Template Issues ---
  {
    id: 'gp-template-1',
    question: 'Template variables like {{.FirstName}} are not being replaced in emails',
    answer: `GoPhish uses Go template syntax for variable substitution. Common issues:

1. **Correct syntax**: Use double curly braces with a dot prefix:
   {{.FirstName}}, {{.LastName}}, {{.Email}}, {{.Position}}
   {{.URL}} - The phishing URL (required for tracking)
   {{.TrackingURL}} - The tracking pixel URL
   {{.From}} - The sender address

2. **Case sensitive**: Variables are case-sensitive. Use {{.FirstName}} not {{.firstname}}.

3. **Target group data**: Variables are populated from the target group. Ensure your targets have First Name, Last Name, Email, and Position filled in.

4. **HTML entities**: If editing in HTML mode, ensure the curly braces aren't being HTML-encoded. {{.FirstName}} should NOT be &lbrace;&lbrace;.FirstName&rbrace;&rbrace;

5. **Test before sending**: Always send a test email to verify variables are replaced correctly.

6. **Custom headers**: You can also use {{.BaseURL}} and {{.RId}} for advanced template customization.`,
    category: 'Templates',
    tags: ['variables', 'template', 'FirstName', 'substitution'],
    severity: 'medium',
  },
  {
    id: 'gp-template-2',
    question: 'Email template HTML is rendering incorrectly in recipient email clients',
    answer: `Email HTML rendering is notoriously inconsistent across clients:

1. **Use table-based layout**: Modern CSS (flexbox, grid) doesn't work in most email clients. Use HTML tables for layout.

2. **Inline CSS**: Most email clients strip <style> tags. Use inline styles on each element:
   <td style="padding: 10px; font-family: Arial, sans-serif;">

3. **Avoid JavaScript**: Email clients block all JavaScript. Use only HTML and CSS.

4. **Image hosting**: Host images on a public URL. Don't use base64 in emails (it works in landing pages but not emails).

5. **Test across clients**: Use a service like Litmus or Email on Acid to preview across clients. At minimum, test in Gmail, Outlook, and Apple Mail.

6. **Keep it simple**: The most effective phishing emails are often simple text-based emails that mimic internal communications. Avoid complex designs.`,
    category: 'Templates',
    tags: ['HTML', 'rendering', 'email client', 'CSS'],
    severity: 'low',
  },

  // --- General ---
  {
    id: 'gp-general-1',
    question: 'GoPhish admin panel is not accessible (connection refused on port 3333)',
    answer: `If you can't access the GoPhish admin panel:

1. **Check if GoPhish is running**:
   sudo systemctl status gophish
   ps aux | grep gophish

2. **Check the listening port**:
   sudo netstat -tlnp | grep gophish
   The admin server should be listening on 0.0.0.0:3333

3. **Firewall rules**: Ensure port 3333 is open:
   sudo ufw allow 3333/tcp
   sudo ufw status

4. **Config file**: Check /opt/gophish/config.json for the correct admin_server settings:
   "admin_server": { "listen_url": "0.0.0.0:3333", "use_tls": true }

5. **SSL certificate**: If using self-signed certs, your browser may block the connection. Try accessing with https:// and accept the certificate warning.

6. **Restart GoPhish**:
   sudo systemctl restart gophish
   sudo journalctl -u gophish -f`,
    category: 'Server',
    tags: ['admin panel', 'connection refused', 'port 3333', 'access'],
    severity: 'critical',
  },
  {
    id: 'gp-general-2',
    question: 'How do I reset the GoPhish admin password?',
    answer: `If you've lost the GoPhish admin password:

1. **First-time setup**: On first launch, GoPhish generates a random password and prints it to the console. Check the logs:
   sudo journalctl -u gophish | grep -i password

2. **Database reset**: GoPhish stores credentials in its SQLite database. You can reset by:
   - Stop GoPhish: sudo systemctl stop gophish
   - Delete the database: rm /opt/gophish/gophish.db
   - Restart: sudo systemctl start gophish
   - A new password will be generated (WARNING: this deletes all data)

3. **API key**: If you still have API access, you can use the API to manage the instance. The API key is in config.json or the admin panel settings.

4. **Current credentials for this deployment**:
   Username: admin
   Password: Check the Credentials page in Ace Strike dashboard`,
    category: 'Server',
    tags: ['password', 'reset', 'admin', 'login'],
    severity: 'medium',
  },
  {
    id: 'gp-general-3',
    question: 'GoPhish SSL certificate errors when accessing the admin panel',
    answer: `SSL certificate warnings are expected with self-signed certificates:

1. **Self-signed certs**: GoPhish generates self-signed certificates by default. Browsers will show a warning. Click "Advanced" → "Proceed" to continue.

2. **Let's Encrypt**: For a proper certificate, use certbot:
   sudo certbot certonly --standalone -d yourdomain.com
   Then update config.json with the certificate paths.

3. **Nginx proxy**: If using Nginx as a reverse proxy (recommended), configure SSL at the Nginx level and proxy to GoPhish's HTTP port.

4. **Disable TLS for admin**: For internal-only access, you can disable TLS in config.json:
   "admin_server": { "use_tls": false }
   WARNING: Only do this on trusted networks.

5. **Certificate path**: If using custom certs, update config.json:
   "cert_path": "/path/to/cert.pem",
   "key_path": "/path/to/key.pem"`,
    category: 'Server',
    tags: ['SSL', 'certificate', 'HTTPS', 'self-signed'],
    severity: 'low',
  },
];
