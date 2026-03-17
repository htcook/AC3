const n={"it-helpdesk":{label:"IT Help Desk",icon:"Monitor",color:"#0078d4",description:"System notifications, mailbox alerts, and IT support messages"},"password-auth":{label:"Password & MFA",icon:"KeyRound",color:"#e74c3c",description:"Password resets, MFA prompts, and authentication alerts"},"cloud-services":{label:"Cloud Services",icon:"Cloud",color:"#7c3aed",description:"File sharing, storage alerts, and SaaS notifications"},financial:{label:"Financial",icon:"DollarSign",color:"#f59e0b",description:"Wire transfers, payment requests, and banking alerts"},"hr-corporate":{label:"HR & Corporate",icon:"Building2",color:"#10b981",description:"Benefits enrollment, policy updates, and payroll changes"},"social-media":{label:"Social Media",icon:"Share2",color:"#3b82f6",description:"LinkedIn, social platform notifications and connection requests"},"software-update":{label:"Software Updates",icon:"Download",color:"#6366f1",description:"Application updates, security patches, and compliance installs"},"delivery-shipping":{label:"Delivery & Shipping",icon:"Truck",color:"#8b5cf6",description:"Package tracking, delivery notifications, and shipping alerts"},"executive-impersonation":{label:"Executive / BEC",icon:"UserCheck",color:"#dc2626",description:"CEO fraud, executive requests, and business email compromise"},"calendar-meeting":{label:"Calendar & Meetings",icon:"Calendar",color:"#0891b2",description:"Meeting invites, calendar events, and scheduling requests"}},a=[{id:"it-email-migration",name:"Email Server Migration Notice",category:"it-helpdesk",difficulty:"beginner",description:"Mimics an IT department email about a server migration requiring account verification. Uses urgency and a legitimate-looking IT support format to trick users into clicking a validation link.",subjectLine:"IT Department Notice: Email Server Migration — Action Required",previewText:"The IT Department completed an email server migration last night and needs you to verify your account.",tags:["email","migration","IT department","verification","server"],source:"HailBytes/gophish-training-templates",htmlContent:`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Server Migration Notice</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: #0078d4; color: white; padding: 20px 25px; }
        .header h2 { margin: 0; font-size: 18px; }
        .alert { background: #fff3cd; border-left: 4px solid #ffc107; padding: 12px 15px; margin: 20px; font-size: 14px; }
        .content { padding: 20px 25px; color: #333; line-height: 1.6; }
        .btn { display: inline-block; background: #0078d4; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; font-weight: 600; margin: 15px 0; }
        .footer { padding: 15px 25px; border-top: 1px solid #eee; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>🔧 IT Department Notice</h2>
        </div>
        <div class="alert">⚠️ Action Required — Email Account Verification</div>
        <div class="content">
            <p>Hello {{.FirstName}},</p>
            <p>The IT Department completed an email server migration last night and encountered errors with several email accounts, including yours ({{.Email}}).</p>
            <p>We believe we have resolved the issue, but need to verify your account is functioning properly.</p>
            <p><strong>Action Required:</strong> If your email has been working normally, please confirm by validating your email address through our secure verification system.</p>
            <p style="text-align: center;">
                <a href="{{.URL}}" class="btn">🔒 Validate Email Account</a>
            </p>
            <p>This verification ensures your account remains secure and functional after the migration.</p>
            <p>Thank you for your prompt cooperation.</p>
            <p>Best regards,<br><strong>IT Support Team</strong><br>Internal Systems & Security</p>
        </div>
        <div class="footer">
            <p><small>This is an automated message from IT Support. Please do not reply to this email.</small></p>
        </div>
    </div>
    {{.Tracker}}
</body>
</html>`},{id:"it-mailbox-compromised",name:"Mailbox Compromised Security Alert",category:"it-helpdesk",difficulty:"intermediate",description:"Simulates a security alert claiming the user's mailbox has been compromised with unauthorized access detected. Creates panic and urgency to drive immediate action.",subjectLine:"🔐 Security Alert: Unauthorized Access Detected on Your Mailbox",previewText:"Our security systems have identified suspicious activity on your webmail account.",tags:["security","compromised","unauthorized access","urgent","mailbox"],source:"HailBytes/gophish-training-templates",htmlContent:`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Alert - Account Compromised</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%); color: white; padding: 25px; text-align: center; }
        .alert-box { background: #fef2f2; border: 2px solid #dc2626; border-radius: 6px; padding: 15px; margin: 20px; }
        .alert-box h3 { color: #dc2626; margin: 0 0 8px 0; }
        .content { padding: 20px 25px; color: #333; line-height: 1.6; }
        .btn-danger { display: inline-block; background: #dc2626; color: white; padding: 14px 35px; text-decoration: none; border-radius: 4px; font-weight: 700; margin: 15px 0; }
        .info-box { background: #f8f9fa; border-radius: 6px; padding: 15px; margin: 15px 0; }
        .footer { padding: 15px 25px; border-top: 1px solid #eee; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>🔐 WebMail Security Alert</h2>
            <p style="margin: 5px 0 0 0; opacity: 0.9;">⚠️ Your mailbox has been compromised</p>
        </div>
        <div class="alert-box">
            <h3>⚡ Immediate Action Required</h3>
            <p style="margin: 0;">We have detected unauthorized access to your webmail account and have temporarily blocked it for your protection.</p>
        </div>
        <div class="content">
            <p>Dear {{.FirstName}},</p>
            <p>Our security systems have identified suspicious activity on your webmail account. To protect your data, we have temporarily restricted access.</p>
            <div class="info-box">
                <strong>Detection Details:</strong><br>
                • IP Address: 185.243.115.xx (Foreign)<br>
                • Location: Eastern Europe<br>
                • Time: Today at 03:42 AM<br>
                • Attempts: 3 failed logins followed by successful access
            </div>
            <p>Please follow these steps immediately:</p>
            <p style="text-align: center;">
                <a href="{{.URL}}" class="btn-danger">🛡️ Secure Your Account Now</a>
            </p>
            <p>If you do not take action within 24 hours, your account will remain locked and all pending emails will be queued.</p>
            <p>Best regards,<br><strong>Security Operations Center</strong><br>IT Security Division</p>
        </div>
        <div class="footer">
            <p><small>This is an automated security alert. Incident Reference: SEC-{{.Email}}-2025</small></p>
        </div>
    </div>
    {{.Tracker}}
</body>
</html>`},{id:"it-system-update",name:"Critical System Update Required",category:"it-helpdesk",difficulty:"beginner",description:"Impersonates a Microsoft-style system update notification requiring users to install a critical security patch. Uses official branding and compliance deadlines.",subjectLine:"Critical System Update Required — Action Needed by {{deadline}}",previewText:"A critical security update has been released that requires immediate installation on your device.",tags:["system update","Microsoft","security patch","compliance","deadline"],source:"HailBytes/gophish-training-templates",htmlContent:`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Critical System Update Required</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: linear-gradient(135deg, #0078d4 0%, #106ebe 100%); color: white; padding: 30px; text-align: center; }
        .microsoft-logo { font-size: 24px; font-weight: 600; margin-bottom: 10px; }
        .content { padding: 35px; color: #333; line-height: 1.7; }
        .update-box { background: linear-gradient(135deg, #e8f4fd 0%, #d1ecf9 100%); border: 2px solid #0078d4; border-radius: 8px; padding: 20px; margin: 20px 0; }
        .btn { display: inline-block; background: #0078d4; color: white; padding: 14px 35px; text-decoration: none; border-radius: 6px; font-weight: 600; }
        .deadline { background: #fff3cd; border: 1px solid #ffc107; padding: 12px; border-radius: 6px; margin: 15px 0; text-align: center; }
        .footer { padding: 20px 35px; border-top: 1px solid #eee; font-size: 12px; color: #888; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="microsoft-logo">⊞ Microsoft</div>
            <h2 style="margin: 0;">Critical Security Update</h2>
            <p style="margin: 5px 0 0 0; opacity: 0.9;">Patch KB5034441 — Immediate Action Required</p>
        </div>
        <div class="content">
            <p>Hello {{.FirstName}},</p>
            <p>A critical security update has been released that requires immediate installation on your device. This patch addresses multiple vulnerabilities rated <strong>Critical</strong> by Microsoft Security Response Center.</p>
            <div class="update-box">
                <strong>Update Details:</strong><br>
                • Patch: KB5034441 — Security Update<br>
                • Severity: Critical<br>
                • Affected: Windows 10/11, Microsoft 365<br>
                • CVE: CVE-2025-21318, CVE-2025-21319
            </div>
            <div class="deadline">
                ⏰ <strong>Compliance Deadline:</strong> You must install this update within 48 hours to maintain network access.
            </div>
            <p style="text-align: center;">
                <a href="{{.URL}}" class="btn">⬇️ Install Update Now</a>
            </p>
            <p>Failure to install this update may result in restricted access to company resources until compliance is verified.</p>
            <p>Thank you,<br><strong>IT Systems Administration</strong></p>
        </div>
        <div class="footer">
            <p>Microsoft Corporation | One Microsoft Way, Redmond, WA 98052</p>
        </div>
    </div>
    {{.Tracker}}
</body>
</html>`},{id:"it-storage-quota",name:"Email Storage Quota Exceeded",category:"it-helpdesk",difficulty:"beginner",description:"Warns the user their email storage is almost full and they need to take action to avoid losing incoming messages. A common and effective social engineering tactic.",subjectLine:"⚠️ Mailbox Storage Alert: Your account is 97% full",previewText:"Your email storage quota has been exceeded. Incoming messages may be rejected.",tags:["storage","quota","mailbox full","email","IT"],source:"HailBytes/gophish-training-templates",htmlContent:`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Storage Quota Exceeded</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8f9fa; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: linear-gradient(135deg, #ff6b35 0%, #f7931e 100%); color: white; padding: 25px; text-align: center; }
        .content { padding: 30px; color: #333; line-height: 1.6; }
        .warning-box { background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; padding: 15px; border-radius: 6px; margin: 15px 0; }
        .progress-bar { background: #e9ecef; border-radius: 10px; height: 20px; margin: 15px 0; overflow: hidden; }
        .progress-fill { background: linear-gradient(90deg, #ff6b35, #dc3545); height: 100%; width: 97%; border-radius: 10px; text-align: center; color: white; font-size: 11px; line-height: 20px; font-weight: bold; }
        .btn { display: inline-block; background: #ff6b35; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; font-weight: 600; }
        .footer { padding: 15px 30px; border-top: 1px solid #eee; font-size: 12px; color: #888; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2 style="margin: 0;">📧 Mailbox Storage Alert</h2>
            <p style="margin: 5px 0 0 0; opacity: 0.9;">Immediate action required to avoid message loss</p>
        </div>
        <div class="content">
            <p>Dear {{.FirstName}},</p>
            <div class="warning-box">
                <strong>⚠️ Warning:</strong> Your mailbox has reached <strong>97%</strong> of its allocated storage quota. Incoming messages may be rejected if you do not take action.
            </div>
            <p><strong>Current Usage:</strong></p>
            <div class="progress-bar"><div class="progress-fill">97% Used — 4.85 GB / 5.00 GB</div></div>
            <p>To continue receiving emails without interruption, please free up space or upgrade your storage allocation:</p>
            <p style="text-align: center;">
                <a href="{{.URL}}" class="btn">📦 Manage Storage Now</a>
            </p>
            <p>If no action is taken within 24 hours, incoming messages will be bounced back to senders.</p>
            <p>Best regards,<br><strong>Email Administration Team</strong></p>
        </div>
        <div class="footer">
            <p><small>This is an automated notification from the mail server. Ref: STOR-{{.Email}}</small></p>
        </div>
    </div>
    {{.Tracker}}
</body>
</html>`},{id:"it-webmail-upgrade",name:"Webmail System Upgrade Notification",category:"it-helpdesk",difficulty:"beginner",description:"Announces a webmail system upgrade with new features, requiring users to activate their upgraded account. Leverages excitement about new features combined with a deadline.",subjectLine:"🎉 Webmail Upgrade Complete — Activate Your New Features",previewText:"Your webmail has been upgraded with new features. Please activate your account to access them.",tags:["webmail","upgrade","new features","activation","IT"],source:"HailBytes/gophish-training-templates",htmlContent:`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Webmail System Upgrade</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f1f3f4; margin: 0; padding: 20px; }
        .container { max-width: 650px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 3px 10px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: linear-gradient(135deg, #4285f4 0%, #34a853 100%); color: white; padding: 30px; text-align: center; }
        .content { padding: 35px; color: #333; line-height: 1.7; }
        .upgrade-box { background: linear-gradient(135deg, #e8f5e8 0%, #c8e6c9 100%); border: 2px solid #4caf50; padding: 25px; border-radius: 8px; margin: 20px 0; }
        .feature-list { list-style: none; padding: 0; }
        .feature-list li { padding: 8px 0; border-bottom: 1px solid #eee; }
        .feature-list li:before { content: "✅ "; }
        .btn { display: inline-block; background: #4285f4; color: white; padding: 14px 35px; text-decoration: none; border-radius: 6px; font-weight: 600; }
        .footer { padding: 20px 35px; border-top: 1px solid #eee; font-size: 12px; color: #888; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2 style="margin: 0;">🎉 Webmail Upgrade Complete</h2>
            <p style="margin: 5px 0 0 0; opacity: 0.9;">New features are ready for activation</p>
        </div>
        <div class="content">
            <p>Dear {{.FirstName}},</p>
            <p>Great news! Our webmail system has been upgraded to the latest version with enhanced security and productivity features.</p>
            <div class="upgrade-box">
                <strong>New Features Available:</strong>
                <ul class="feature-list">
                    <li>25 GB expanded mailbox storage</li>
                    <li>Advanced spam filtering with AI detection</li>
                    <li>Integrated calendar and scheduling</li>
                    <li>Enhanced mobile experience</li>
                    <li>End-to-end encryption for sensitive emails</li>
                </ul>
            </div>
            <p>To activate these features, please verify your account through our secure portal:</p>
            <p style="text-align: center;">
                <a href="{{.URL}}" class="btn">🚀 Activate Upgraded Account</a>
            </p>
            <p><em>Note: Accounts not activated by Friday will remain on the legacy system with limited functionality.</em></p>
            <p>Best regards,<br><strong>IT Infrastructure Team</strong></p>
        </div>
        <div class="footer">
            <p><small>This is an automated system notification. Reference: UPG-2025-{{.Email}}</small></p>
        </div>
    </div>
    {{.Tracker}}
</body>
</html>`},{id:"it-servicenow-ticket",name:"ServiceNow IT Ticket Update",category:"it-helpdesk",difficulty:"advanced",description:"Mimics a ServiceNow ticket notification about an IT request requiring approval. Highly realistic for organizations using ServiceNow for IT service management.",subjectLine:"ServiceNow: INC0042817 — Your IT Request Requires Action",previewText:"A ticket has been updated in ServiceNow that requires your immediate attention.",tags:["ServiceNow","ITSM","ticket","help desk","incident"],source:"Custom — Based on real ServiceNow notifications",htmlContent:`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ServiceNow Notification</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f4f4; margin: 0; padding: 20px; }
        .container { max-width: 620px; margin: 0 auto; background: white; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.12); }
        .header { background: #293e40; color: white; padding: 15px 20px; display: flex; align-items: center; }
        .header img { height: 24px; margin-right: 10px; }
        .header span { font-size: 16px; font-weight: 500; }
        .ticket-bar { background: #e8f5e9; border-left: 4px solid #4caf50; padding: 12px 20px; font-size: 14px; }
        .content { padding: 25px; color: #333; line-height: 1.6; }
        .ticket-table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        .ticket-table td { padding: 8px 12px; border: 1px solid #e0e0e0; font-size: 13px; }
        .ticket-table td:first-child { background: #f5f5f5; font-weight: 600; width: 140px; }
        .btn { display: inline-block; background: #293e40; color: white; padding: 10px 25px; text-decoration: none; border-radius: 3px; font-size: 14px; }
        .footer { padding: 15px 25px; border-top: 1px solid #eee; font-size: 11px; color: #999; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <span>ServiceNow — IT Service Management</span>
        </div>
        <div class="ticket-bar">📋 Ticket <strong>INC0042817</strong> has been updated and requires your action.</div>
        <div class="content">
            <p>Hello {{.FirstName}},</p>
            <p>The following IT service request has been updated and requires your review:</p>
            <table class="ticket-table">
                <tr><td>Ticket Number</td><td>INC0042817</td></tr>
                <tr><td>Category</td><td>Access Management</td></tr>
                <tr><td>Priority</td><td>High</td></tr>
                <tr><td>Status</td><td>Awaiting User Action</td></tr>
                <tr><td>Assigned To</td><td>IT Help Desk — Tier 2</td></tr>
                <tr><td>Description</td><td>VPN access credentials need to be re-validated due to security policy update. User must confirm identity.</td></tr>
                <tr><td>Updated</td><td>Today at 09:15 AM</td></tr>
            </table>
            <p>Please review and take action on this ticket:</p>
            <p><a href="{{.URL}}" class="btn">View Ticket in ServiceNow</a></p>
            <p style="font-size: 13px; color: #666;">If you did not submit this request, please contact the IT Help Desk immediately.</p>
        </div>
        <div class="footer">
            <p>This is an automated notification from ServiceNow. Do not reply to this email.<br>
            Ref: INC0042817 | {{.Email}}</p>
        </div>
    </div>
    {{.Tracker}}
</body>
</html>`},{id:"auth-password-expiry",name:"Password Expiration Warning",category:"password-auth",difficulty:"beginner",description:"Classic password expiration alert mimicking Microsoft 365 or Active Directory notifications. One of the most effective phishing templates due to its familiarity.",subjectLine:"Action Required: Your password will expire in 24 hours",previewText:"Your Microsoft 365 password will expire in 24 hours. Reset now to avoid disruption.",tags:["password","expiration","Microsoft 365","Active Directory","reset"],source:"Abnormal AI / Industry Standard",htmlContent:`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Expiration Notice</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }
        .container { max-width: 580px; margin: 0 auto; background: white; border-radius: 6px; box-shadow: 0 2px 6px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: #0078d4; color: white; padding: 20px 25px; }
        .content { padding: 25px; color: #333; line-height: 1.6; }
        .warning { background: #fff3cd; border: 1px solid #ffc107; padding: 15px; border-radius: 4px; margin: 15px 0; }
        .btn { display: inline-block; background: #0078d4; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; font-weight: 600; }
        .details { background: #f8f9fa; padding: 15px; border-radius: 4px; margin: 15px 0; font-size: 14px; }
        .footer { padding: 15px 25px; border-top: 1px solid #eee; font-size: 11px; color: #999; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2 style="margin: 0; font-size: 18px;">⊞ Microsoft 365 — Password Notification</h2>
        </div>
        <div class="content">
            <p>Hello {{.FirstName}},</p>
            <div class="warning">
                <strong>⚠️ Your password will expire in 24 hours.</strong><br>
                To avoid disruption to your Microsoft 365 services, please reset your password now.
            </div>
            <div class="details">
                <strong>Account:</strong> {{.Email}}<br>
                <strong>Expiration:</strong> Tomorrow at 11:59 PM<br>
                <strong>Policy:</strong> 90-day password rotation (Corporate Security Policy)
            </div>
            <p>After expiration, you will be unable to access:</p>
            <ul>
                <li>Outlook email and calendar</li>
                <li>Microsoft Teams</li>
                <li>SharePoint and OneDrive</li>
                <li>VPN and remote access</li>
            </ul>
            <p style="text-align: center;">
                <a href="{{.URL}}" class="btn">🔑 Reset Password Now</a>
            </p>
            <p style="font-size: 13px; color: #666;">If you have recently changed your password, please disregard this notice.</p>
        </div>
        <div class="footer">
            <p>Microsoft Corporation | This is an automated notification from your organization's identity management system.</p>
        </div>
    </div>
    {{.Tracker}}
</body>
</html>`},{id:"auth-mfa-fatigue",name:"MFA System Update — Approve Prompt",category:"password-auth",difficulty:"advanced",description:"Exploits MFA fatigue by posing as IT support requesting users approve an MFA prompt to finalize a system update. Tests awareness of push notification attacks.",subjectLine:"IT Security: MFA System Update — Please Approve Verification Prompt",previewText:"We've made changes to our MFA system. You may receive a verification prompt—please approve it.",tags:["MFA","two-factor","push notification","fatigue","IT security"],source:"Abnormal AI",htmlContent:`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MFA System Update</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: linear-gradient(135deg, #1a365d 0%, #2d3748 100%); color: white; padding: 25px; text-align: center; }
        .badge { display: inline-block; background: #48bb78; color: white; padding: 4px 12px; border-radius: 12px; font-size: 12px; margin-top: 8px; }
        .content { padding: 30px; color: #333; line-height: 1.7; }
        .step-box { background: #f7fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 20px; margin: 20px 0; }
        .step { display: flex; align-items: flex-start; margin: 10px 0; }
        .step-num { background: #0078d4; color: white; width: 24px; height: 24px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: bold; margin-right: 12px; flex-shrink: 0; }
        .btn { display: inline-block; background: #0078d4; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; font-weight: 600; }
        .footer { padding: 15px 30px; border-top: 1px solid #eee; font-size: 12px; color: #888; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2 style="margin: 0;">🔐 Multi-Factor Authentication Update</h2>
            <div class="badge">SECURITY NOTICE</div>
        </div>
        <div class="content">
            <p>Dear {{.FirstName}},</p>
            <p>As part of our ongoing security improvements, we have updated the Multi-Factor Authentication (MFA) system for all employees. This update enhances protection against unauthorized access.</p>
            <div class="step-box">
                <strong>What you need to do:</strong>
                <div class="step"><div class="step-num">1</div><div>You will receive an MFA push notification on your registered device within the next few minutes.</div></div>
                <div class="step"><div class="step-num">2</div><div><strong>Please approve the prompt</strong> to complete the migration to the new MFA system.</div></div>
                <div class="step"><div class="step-num">3</div><div>If you don't receive a prompt, click the link below to trigger it manually.</div></div>
            </div>
            <p style="text-align: center;">
                <a href="{{.URL}}" class="btn">🔄 Trigger MFA Verification</a>
            </p>
            <p><strong>Important:</strong> All employees must complete this verification by end of business today. Failure to do so may result in temporary account lockout.</p>
            <p>Thank you for helping us keep our systems secure.</p>
            <p>Best regards,<br><strong>IT Security Team</strong></p>
        </div>
        <div class="footer">
            <p>This is an automated message from IT Security. Do not reply. Ref: MFA-UPD-2025</p>
        </div>
    </div>
    {{.Tracker}}
</body>
</html>`},{id:"auth-microsoft-security-alert",name:"Microsoft Account Security Alert",category:"password-auth",difficulty:"intermediate",description:"Mimics a Microsoft account security alert about a sign-in from an unrecognized device and location. Includes realistic location and device details.",subjectLine:"Microsoft Account Security Alert — Unusual Sign-in Activity",previewText:"We detected something unusual about a recent sign-in to your Microsoft account.",tags:["Microsoft","security alert","sign-in","unusual activity","account"],source:"HailBytes/gophish-training-templates",htmlContent:`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microsoft Account Security Alert</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .header { background: #0078d4; color: white; padding: 20px; text-align: center; }
        .content { padding: 30px; color: #333; line-height: 1.6; }
        .security-alert { background: #fff4ce; border: 1px solid #ffb900; padding: 20px; border-radius: 6px; margin: 20px 0; }
        .location-info { background: #f3f2f1; padding: 15px; border-radius: 6px; margin: 15px 0; }
        .location-info table { width: 100%; font-size: 14px; }
        .location-info td { padding: 4px 0; }
        .location-info td:first-child { font-weight: 600; width: 120px; }
        .btn { display: inline-block; background: #0078d4; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; font-weight: 600; }
        .footer { padding: 20px 30px; border-top: 1px solid #eee; font-size: 12px; color: #888; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 style="margin: 0; font-size: 20px;">Microsoft Account</h1>
            <p style="margin: 5px 0 0 0; opacity: 0.9;">Security & Privacy</p>
        </div>
        <div class="content">
            <h2 style="color: #0078d4;">Unusual sign-in activity</h2>
            <div class="security-alert">
                <strong>⚠️ We detected something unusual</strong>
                <p style="margin: 8px 0 0 0;">A sign-in to your Microsoft account was made from a new device or location. If this wasn't you, your account may be compromised.</p>
            </div>
            <p>Dear {{.FirstName}},</p>
            <p>We noticed a sign-in attempt to your account from:</p>
            <div class="location-info">
                <table>
                    <tr><td>Country/Region:</td><td>Russia</td></tr>
                    <tr><td>IP Address:</td><td>91.234.xx.xx</td></tr>
                    <tr><td>Platform:</td><td>Windows 10</td></tr>
                    <tr><td>Browser:</td><td>Chrome 120.0</td></tr>
                    <tr><td>Date/Time:</td><td>Today at 02:17 AM (UTC)</td></tr>
                </table>
            </div>
            <p>If this was you, you can safely ignore this message. If you didn't sign in recently, your account may be compromised. Please secure your account:</p>
            <p style="text-align: center;">
                <a href="{{.URL}}" class="btn">Review Recent Activity</a>
            </p>
            <p style="font-size: 13px; color: #666;">The Microsoft account team</p>
        </div>
        <div class="footer">
            <p>This is a mandatory security notification sent to {{.Email}}.<br>Microsoft Corporation, One Microsoft Way, Redmond, WA 98052</p>
        </div>
    </div>
    {{.Tracker}}
</body>
</html>`},{id:"cloud-dropbox-share",name:"Dropbox File Share Notification",category:"cloud-services",difficulty:"beginner",description:"Mimics a Dropbox file sharing notification. Exploits trust in cloud file sharing platforms and curiosity about shared documents.",subjectLine:"{{.FirstName}}, someone shared a file with you on Dropbox",previewText:"A colleague has shared an important document with you via Dropbox.",tags:["Dropbox","file share","cloud","document","collaboration"],source:"HailBytes/gophish-training-templates",htmlContent:`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dropbox File Share</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f7f7f7; margin: 0; padding: 20px; }
        .container { max-width: 560px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: #0061ff; color: white; padding: 20px 25px; text-align: center; }
        .content { padding: 25px; color: #333; line-height: 1.6; }
        .file-card { background: #f7f7f7; border: 1px solid #e5e5e5; border-radius: 8px; padding: 15px; margin: 15px 0; display: flex; align-items: center; }
        .file-icon { font-size: 32px; margin-right: 15px; }
        .file-info { flex: 1; }
        .file-name { font-weight: 600; font-size: 15px; }
        .file-meta { font-size: 12px; color: #888; margin-top: 4px; }
        .btn { display: inline-block; background: #0061ff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; font-weight: 600; }
        .footer { padding: 15px 25px; border-top: 1px solid #eee; font-size: 11px; color: #999; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2 style="margin: 0;">📦 Dropbox</h2>
        </div>
        <div class="content">
            <p>Hi {{.FirstName}},</p>
            <p><strong>HR Department</strong> shared a file with you:</p>
            <div class="file-card">
                <div class="file-icon">📄</div>
                <div class="file-info">
                    <div class="file-name">Q4_Performance_Review_2025.pdf</div>
                    <div class="file-meta">PDF • 2.4 MB • Shared today</div>
                </div>
            </div>
            <p>This document requires your review and acknowledgment by end of week.</p>
            <p style="text-align: center;">
                <a href="{{.URL}}" class="btn">View File in Dropbox</a>
            </p>
            <p style="font-size: 13px; color: #888;">If you weren't expecting this file, you can ignore this email.</p>
        </div>
        <div class="footer">
            <p>Dropbox, Inc. | San Francisco, CA<br>Sent to {{.Email}}</p>
        </div>
    </div>
    {{.Tracker}}
</body>
</html>`},{id:"cloud-google-drive",name:"Google Drive Document Share",category:"cloud-services",difficulty:"beginner",description:"Mimics a Google Drive sharing notification. Uses Google's visual style and a compelling document name to entice clicks.",subjectLine:'Document shared with you: "Annual Budget Proposal 2025"',previewText:"Finance Department has shared a Google Docs document with you.",tags:["Google Drive","Google Docs","file share","cloud","document"],source:"HailBytes/gophish-training-templates",htmlContent:`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Google Drive Share</title>
    <style>
        body { font-family: 'Google Sans', Roboto, sans-serif; background: #f8f9fa; margin: 0; padding: 20px; }
        .container { max-width: 560px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.12); overflow: hidden; }
        .header { padding: 20px 25px; border-bottom: 1px solid #eee; }
        .google-logo { color: #5f6368; font-size: 22px; font-weight: 500; }
        .content { padding: 25px; color: #333; line-height: 1.6; }
        .doc-card { background: #e8f0fe; border-radius: 8px; padding: 20px; margin: 15px 0; text-align: center; }
        .doc-icon { font-size: 40px; margin-bottom: 10px; }
        .doc-name { font-size: 16px; font-weight: 500; color: #1a73e8; }
        .btn { display: inline-block; background: #1a73e8; color: white; padding: 10px 24px; text-decoration: none; border-radius: 4px; font-weight: 500; font-size: 14px; }
        .btn-outline { display: inline-block; border: 1px solid #dadce0; color: #1a73e8; padding: 10px 24px; text-decoration: none; border-radius: 4px; font-weight: 500; font-size: 14px; margin-left: 8px; }
        .footer { padding: 15px 25px; border-top: 1px solid #eee; font-size: 11px; color: #999; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <span class="google-logo">Google Drive</span>
        </div>
        <div class="content">
            <p><strong>Finance Department</strong> (finance@company.com) has shared a document with you:</p>
            <div class="doc-card">
                <div class="doc-icon">📊</div>
                <div class="doc-name">Annual Budget Proposal 2025</div>
                <p style="font-size: 13px; color: #5f6368; margin: 8px 0 0 0;">Google Docs • View only</p>
            </div>
            <p style="text-align: center;">
                <a href="{{.URL}}" class="btn">Open in Docs</a>
                <a href="{{.URL}}" class="btn-outline">Download</a>
            </p>
            <p style="font-size: 13px; color: #5f6368;">This email grants access to <strong>{{.Email}}</strong>. If you don't want to receive files from this person, block the sender from Google Drive.</p>
        </div>
        <div class="footer">
            <p>Google LLC, 1600 Amphitheatre Parkway, Mountain View, CA 94043</p>
        </div>
    </div>
    {{.Tracker}}
</body>
</html>`},{id:"cloud-onedrive-share",name:"OneDrive/SharePoint File Share",category:"cloud-services",difficulty:"intermediate",description:"Mimics a Microsoft OneDrive or SharePoint file sharing notification. Particularly effective in Microsoft 365 environments.",subjectLine:'{{sender}} shared "Confidential — Board Meeting Notes" with you',previewText:"A OneDrive for Business document has been shared with you.",tags:["OneDrive","SharePoint","Microsoft 365","file share","cloud"],source:"Custom — Based on real Microsoft notifications",htmlContent:`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OneDrive Share</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }
        .container { max-width: 580px; margin: 0 auto; background: white; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.12); }
        .header { padding: 20px; border-bottom: 1px solid #eee; }
        .content { padding: 20px; color: #333; line-height: 1.6; }
        .share-card { border: 1px solid #deecf9; border-radius: 4px; padding: 15px; margin: 15px 0; background: #f3f9ff; }
        .share-icon { font-size: 28px; float: left; margin-right: 12px; }
        .share-name { font-weight: 600; color: #0078d4; font-size: 15px; }
        .share-meta { font-size: 12px; color: #666; margin-top: 4px; }
        .btn { display: inline-block; background: #0078d4; color: white; padding: 8px 20px; text-decoration: none; border-radius: 2px; font-size: 14px; }
        .footer { padding: 15px 20px; border-top: 1px solid #eee; font-size: 11px; color: #999; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <span style="color: #0078d4; font-size: 18px; font-weight: 600;">⊞ OneDrive for Business</span>
        </div>
        <div class="content">
            <p><strong>Executive Assistant</strong> has shared a file with you.</p>
            <div class="share-card">
                <div class="share-icon">📋</div>
                <div>
                    <div class="share-name">Confidential — Board Meeting Notes Q4.docx</div>
                    <div class="share-meta">Word Document • 847 KB • Shared today at 10:23 AM</div>
                    <div class="share-meta">📁 Executive Team > Board Meetings</div>
                </div>
                <div style="clear: both;"></div>
            </div>
            <p>Message from sender: <em>"{{.FirstName}}, please review the board meeting notes before our sync tomorrow. Some items require your input."</em></p>
            <p><a href="{{.URL}}" class="btn">Open</a></p>
            <p style="font-size: 12px; color: #666;">Shared with: {{.Email}}</p>
        </div>
        <div class="footer">
            <p>Microsoft Corporation | You're receiving this because someone shared a OneDrive file with you.</p>
        </div>
    </div>
    {{.Tracker}}
</body>
</html>`},{id:"fin-wire-transfer",name:"Urgent Wire Transfer Request",category:"financial",difficulty:"advanced",description:"Classic BEC (Business Email Compromise) template impersonating a CEO requesting an urgent wire transfer. Tests employee awareness of executive fraud.",subjectLine:"Urgent: Wire Transfer Needed Today — Confidential",previewText:"I need you to process a wire transfer urgently. I'm in meetings and can't call.",tags:["wire transfer","BEC","CEO fraud","urgent","financial"],source:"Abnormal AI / criggs626",htmlContent:`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wire Transfer Request</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }
        .container { max-width: 580px; margin: 0 auto; background: white; border-radius: 6px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); padding: 30px; }
        .content { color: #333; line-height: 1.7; }
        .confidential { background: #fef2f2; border: 1px solid #fecaca; color: #991b1b; padding: 8px 15px; border-radius: 4px; font-size: 12px; font-weight: 600; display: inline-block; margin-bottom: 15px; }
        .signature { border-top: 1px solid #eee; margin-top: 20px; padding-top: 15px; font-size: 14px; color: #555; }
        .sent-from { font-size: 11px; color: #999; margin-top: 15px; font-style: italic; }
    </style>
</head>
<body>
    <div class="container">
        <div class="content">
            <div class="confidential">🔒 CONFIDENTIAL</div>
            <p>Hi {{.FirstName}},</p>
            <p>I need you to handle something urgently and discreetly. We need to process a wire transfer of <strong>$47,500</strong> to finalize a vendor contract before end of business today.</p>
            <p>I'm in back-to-back meetings and can't call right now. Please process this as soon as possible and confirm once done.</p>
            <p>Here are the details:</p>
            <ul>
                <li><strong>Amount:</strong> $47,500.00</li>
                <li><strong>Recipient:</strong> Meridian Consulting Group LLC</li>
                <li><strong>Reference:</strong> INV-2025-0847</li>
            </ul>
            <p>I'll send the full banking details once you confirm you can handle this. Please treat this as priority and keep it between us for now — it's related to the acquisition.</p>
            <p>Thanks,</p>
            <div class="signature">
                <strong>Robert Chen</strong><br>
                Chief Executive Officer<br>
                Direct: (555) 234-5678
            </div>
            <div class="sent-from">Sent from my iPhone</div>
        </div>
    </div>
    {{.Tracker}}
</body>
</html>`},{id:"fin-vendor-payment",name:"Vendor Payment Details Update",category:"financial",difficulty:"advanced",description:"Impersonates a known vendor requesting a change in banking details for an upcoming payment. A sophisticated BEC variant targeting accounts payable.",subjectLine:"Updated Banking Instructions for Invoice #INV-2025-0392",previewText:"Please note our new remittance details for the upcoming payment.",tags:["vendor","payment","banking","invoice","BEC"],source:"Abnormal AI",htmlContent:`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vendor Payment Update</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 6px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: #1e3a5f; color: white; padding: 20px 25px; }
        .content { padding: 25px; color: #333; line-height: 1.6; }
        .invoice-box { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px; padding: 15px; margin: 15px 0; }
        .invoice-box table { width: 100%; font-size: 14px; }
        .invoice-box td { padding: 5px 0; }
        .invoice-box td:first-child { font-weight: 600; width: 150px; }
        .important { background: #fff3cd; border-left: 4px solid #ffc107; padding: 12px 15px; margin: 15px 0; font-size: 14px; }
        .btn { display: inline-block; background: #1e3a5f; color: white; padding: 10px 25px; text-decoration: none; border-radius: 4px; font-weight: 500; }
        .footer { padding: 15px 25px; border-top: 1px solid #eee; font-size: 12px; color: #888; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2 style="margin: 0; font-size: 18px;">Meridian Technology Solutions</h2>
            <p style="margin: 5px 0 0 0; opacity: 0.8; font-size: 13px;">Accounts Receivable Department</p>
        </div>
        <div class="content">
            <p>Dear {{.FirstName}},</p>
            <p>I hope this message finds you well. I'm writing to inform you of a change to our banking information effective immediately. Our company has recently transitioned to a new banking partner.</p>
            <div class="invoice-box">
                <table>
                    <tr><td>Invoice Number:</td><td>INV-2025-0392</td></tr>
                    <tr><td>Amount Due:</td><td>$23,750.00</td></tr>
                    <tr><td>Due Date:</td><td>February 28, 2025</td></tr>
                    <tr><td>Service Period:</td><td>January 2025</td></tr>
                </table>
            </div>
            <div class="important">
                <strong>⚠️ Important:</strong> Please update your records with our new banking details before processing the next payment. The previous account has been closed.
            </div>
            <p>Please find the updated remittance instructions in the attached document, or click below to download securely:</p>
            <p><a href="{{.URL}}" class="btn">📎 Download Updated Banking Details</a></p>
            <p>Please confirm receipt of this notice so we can ensure uninterrupted service.</p>
            <p>Best regards,<br><strong>Sarah Mitchell</strong><br>Accounts Receivable Manager<br>Meridian Technology Solutions<br>sarah.mitchell@meridian-tech.com</p>
        </div>
        <div class="footer">
            <p>Meridian Technology Solutions | 1200 Commerce Drive, Suite 400 | Chicago, IL 60601</p>
        </div>
    </div>
    {{.Tracker}}
</body>
</html>`},{id:"hr-benefits-enrollment",name:"Benefits Enrollment — Final Reminder",category:"hr-corporate",difficulty:"beginner",description:"Mimics an HR benefits enrollment deadline notification. Highly effective during actual enrollment periods. Exploits fear of missing out on benefits.",subjectLine:"Final Reminder: Benefits Enrollment Closes Tomorrow",previewText:"Click below to finalize your 2025 benefits elections before the window closes.",tags:["HR","benefits","enrollment","deadline","open enrollment"],source:"Abnormal AI",htmlContent:`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Benefits Enrollment</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: linear-gradient(135deg, #059669 0%, #047857 100%); color: white; padding: 25px; text-align: center; }
        .content { padding: 30px; color: #333; line-height: 1.7; }
        .deadline-box { background: #fef2f2; border: 2px solid #ef4444; border-radius: 8px; padding: 20px; margin: 20px 0; text-align: center; }
        .deadline-box h3 { color: #dc2626; margin: 0 0 8px 0; }
        .benefits-list { background: #f0fdf4; border-radius: 6px; padding: 15px 15px 15px 35px; margin: 15px 0; }
        .btn { display: inline-block; background: #059669; color: white; padding: 14px 35px; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 16px; }
        .footer { padding: 15px 30px; border-top: 1px solid #eee; font-size: 12px; color: #888; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2 style="margin: 0;">🏥 Open Enrollment — Final Reminder</h2>
            <p style="margin: 5px 0 0 0; opacity: 0.9;">Human Resources Department</p>
        </div>
        <div class="content">
            <p>Dear {{.FirstName}},</p>
            <div class="deadline-box">
                <h3>⏰ Enrollment Closes Tomorrow at 11:59 PM</h3>
                <p style="margin: 0;">If you do not complete enrollment, you will default to the Basic plan with no dental or vision coverage.</p>
            </div>
            <p>This is your final reminder to review and finalize your 2025 benefits elections. The following plans are available:</p>
            <ul class="benefits-list">
                <li>Medical (PPO, HMO, HDHP options)</li>
                <li>Dental & Vision</li>
                <li>Life & Disability Insurance</li>
                <li>401(k) Contribution Changes</li>
                <li>FSA / HSA Elections</li>
                <li>Dependent Care</li>
            </ul>
            <p style="text-align: center;">
                <a href="{{.URL}}" class="btn">Review & Finalize Benefits</a>
            </p>
            <p>If you have questions, contact HR at benefits@company.com or ext. 4200.</p>
            <p>Best regards,<br><strong>Human Resources Team</strong></p>
        </div>
        <div class="footer">
            <p>This is an automated reminder from the HR Benefits Portal. Ref: OE-2025-{{.Email}}</p>
        </div>
    </div>
    {{.Tracker}}
</body>
</html>`},{id:"hr-payroll-change",name:"Payroll Direct Deposit Confirmation",category:"hr-corporate",difficulty:"intermediate",description:"Impersonates HR/Payroll asking employees to confirm direct deposit information. Targets sensitive financial data under the guise of routine payroll maintenance.",subjectLine:"Action Required: Confirm Your Direct Deposit Details",previewText:"Please confirm your direct deposit information to avoid payroll delays.",tags:["payroll","direct deposit","HR","banking","confirmation"],source:"Abnormal AI",htmlContent:`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Payroll Confirmation</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 6px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: #1e40af; color: white; padding: 20px 25px; }
        .content { padding: 25px; color: #333; line-height: 1.6; }
        .info-box { background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 6px; padding: 15px; margin: 15px 0; }
        .btn { display: inline-block; background: #1e40af; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; font-weight: 600; }
        .footer { padding: 15px 25px; border-top: 1px solid #eee; font-size: 12px; color: #888; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2 style="margin: 0; font-size: 18px;">💰 Payroll Department — Direct Deposit Verification</h2>
        </div>
        <div class="content">
            <p>Dear {{.FirstName}},</p>
            <p>Ahead of our upcoming payroll cycle, we are conducting a routine verification of all employee direct deposit information to ensure accuracy and prevent payment delays.</p>
            <div class="info-box">
                <strong>Why is this needed?</strong><br>
                Our payroll system was recently migrated to a new platform. All employees must re-confirm their banking details to ensure seamless payroll processing.
            </div>
            <p>Please use the secure form below to verify your current direct deposit details:</p>
            <p style="text-align: center;">
                <a href="{{.URL}}" class="btn">✅ Confirm Direct Deposit Details</a>
            </p>
            <p><strong>Deadline:</strong> Please complete this by Friday to avoid delays in your next paycheck.</p>
            <p>If you have questions, contact Payroll at payroll@company.com.</p>
            <p>Thank you,<br><strong>Payroll Administration</strong><br>Human Resources Department</p>
        </div>
        <div class="footer">
            <p>This is a confidential payroll notification. Please do not forward. Ref: PAY-VER-2025</p>
        </div>
    </div>
    {{.Tracker}}
</body>
</html>`},{id:"hr-policy-signature",name:"Updated Company Policy — Signature Required",category:"hr-corporate",difficulty:"intermediate",description:"Mimics an HR compliance notification requiring employees to review and sign an updated policy document. Uses a malicious attachment or link disguised as a policy PDF.",subjectLine:"Please Review: Updated Information Security Policy — Signature Required",previewText:"All employees are required to review and sign the updated security policy by Friday.",tags:["policy","compliance","signature","HR","document"],source:"Abnormal AI",htmlContent:`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Policy Update</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 6px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: #7c3aed; color: white; padding: 20px 25px; }
        .content { padding: 25px; color: #333; line-height: 1.6; }
        .policy-card { background: #f5f3ff; border: 1px solid #ddd6fe; border-radius: 6px; padding: 15px; margin: 15px 0; }
        .btn { display: inline-block; background: #7c3aed; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; font-weight: 600; }
        .deadline { background: #fef3c7; border: 1px solid #fbbf24; padding: 10px 15px; border-radius: 4px; margin: 15px 0; font-size: 14px; }
        .footer { padding: 15px 25px; border-top: 1px solid #eee; font-size: 12px; color: #888; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2 style="margin: 0; font-size: 18px;">📋 Compliance Notice — Policy Update</h2>
        </div>
        <div class="content">
            <p>Dear {{.FirstName}},</p>
            <p>As part of our annual compliance review, the Information Security Policy has been updated to reflect new regulatory requirements and industry best practices.</p>
            <div class="policy-card">
                <strong>📄 Updated Document:</strong><br>
                Information Security Policy v4.2 (2025)<br>
                <span style="font-size: 13px; color: #666;">Key changes: Remote work security, BYOD guidelines, incident reporting procedures</span>
            </div>
            <p>All employees are required to:</p>
            <ol>
                <li>Review the updated policy document</li>
                <li>Acknowledge receipt and understanding</li>
                <li>Provide your electronic signature</li>
            </ol>
            <div class="deadline">
                ⏰ <strong>Compliance Deadline:</strong> Friday, 5:00 PM. Non-compliance will be reported to your department head.
            </div>
            <p style="text-align: center;">
                <a href="{{.URL}}" class="btn">📝 Review & Sign Policy</a>
            </p>
            <p>Thank you for your cooperation.</p>
            <p>Best regards,<br><strong>Compliance & Legal Department</strong></p>
        </div>
        <div class="footer">
            <p>This is a mandatory compliance notification. Ref: POL-SEC-2025-v4.2</p>
        </div>
    </div>
    {{.Tracker}}
</body>
</html>`},{id:"social-linkedin-connection",name:"LinkedIn Connection Request",category:"social-media",difficulty:"beginner",description:"Mimics a LinkedIn connection request or profile view notification. Exploits professional networking curiosity.",subjectLine:"{{.FirstName}}, you have 3 new connection requests on LinkedIn",previewText:"A recruiter from a Fortune 500 company wants to connect with you.",tags:["LinkedIn","connection","networking","social media","recruiter"],source:"HailBytes/gophish-training-templates",htmlContent:`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LinkedIn Notification</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f3f2ef; margin: 0; padding: 20px; }
        .container { max-width: 560px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.12); overflow: hidden; }
        .header { background: #0a66c2; color: white; padding: 15px 20px; text-align: center; }
        .content { padding: 20px; color: #333; line-height: 1.6; }
        .connection-card { border: 1px solid #e0e0e0; border-radius: 8px; padding: 15px; margin: 10px 0; display: flex; align-items: center; }
        .avatar { width: 48px; height: 48px; border-radius: 50%; background: #0a66c2; color: white; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 18px; margin-right: 12px; flex-shrink: 0; }
        .person-info { flex: 1; }
        .person-name { font-weight: 600; font-size: 15px; }
        .person-title { font-size: 13px; color: #666; }
        .btn-accept { display: inline-block; background: #0a66c2; color: white; padding: 6px 16px; text-decoration: none; border-radius: 16px; font-size: 14px; font-weight: 600; }
        .btn-view { display: inline-block; background: white; color: #0a66c2; border: 1px solid #0a66c2; padding: 6px 16px; text-decoration: none; border-radius: 16px; font-size: 14px; font-weight: 600; margin-left: 8px; }
        .footer { padding: 15px 20px; border-top: 1px solid #eee; font-size: 11px; color: #999; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2 style="margin: 0; font-size: 18px;">in LinkedIn</h2>
        </div>
        <div class="content">
            <p>Hi {{.FirstName}},</p>
            <p>You have <strong>3 pending connection requests</strong>:</p>
            <div class="connection-card">
                <div class="avatar">JR</div>
                <div class="person-info">
                    <div class="person-name">Jennifer Rodriguez</div>
                    <div class="person-title">Senior Recruiter at Amazon Web Services</div>
                    <div style="margin-top: 8px;">
                        <a href="{{.URL}}" class="btn-accept">Accept</a>
                        <a href="{{.URL}}" class="btn-view">View Profile</a>
                    </div>
                </div>
            </div>
            <div class="connection-card">
                <div class="avatar">MT</div>
                <div class="person-info">
                    <div class="person-name">Michael Torres</div>
                    <div class="person-title">VP of Engineering at Stripe</div>
                    <div style="margin-top: 8px;">
                        <a href="{{.URL}}" class="btn-accept">Accept</a>
                        <a href="{{.URL}}" class="btn-view">View Profile</a>
                    </div>
                </div>
            </div>
            <p style="text-align: center; margin-top: 15px;">
                <a href="{{.URL}}" style="color: #0a66c2; font-weight: 600; text-decoration: none;">View all connection requests →</a>
            </p>
        </div>
        <div class="footer">
            <p>LinkedIn Corporation | 1000 W Maude Ave, Sunnyvale, CA 94085<br>
            <a href="#" style="color: #666;">Unsubscribe</a> | <a href="#" style="color: #666;">Help</a></p>
        </div>
    </div>
    {{.Tracker}}
</body>
</html>`},{id:"sw-zoom-update",name:"Zoom Security Update Required",category:"software-update",difficulty:"intermediate",description:"Impersonates Zoom requesting a mandatory security update. Particularly effective for remote workers who rely heavily on video conferencing.",subjectLine:"Required: Zoom Security Update — Install Before Your Next Meeting",previewText:"A critical security update for Zoom is required to continue using the application.",tags:["Zoom","security update","video conferencing","software","remote work"],source:"Abnormal AI",htmlContent:`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zoom Update</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }
        .container { max-width: 580px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: #2d8cff; color: white; padding: 25px; text-align: center; }
        .content { padding: 30px; color: #333; line-height: 1.7; }
        .update-info { background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 6px; padding: 15px; margin: 15px 0; }
        .btn { display: inline-block; background: #2d8cff; color: white; padding: 14px 35px; text-decoration: none; border-radius: 8px; font-weight: 600; }
        .footer { padding: 15px 30px; border-top: 1px solid #eee; font-size: 12px; color: #888; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2 style="margin: 0;">🎥 Zoom — Security Update</h2>
            <p style="margin: 5px 0 0 0; opacity: 0.9;">Version 6.2.1 — Critical Security Patch</p>
        </div>
        <div class="content">
            <p>Hi {{.FirstName}},</p>
            <p>A critical security update for Zoom Workplace is available and must be installed before your next meeting to maintain compliance with your organization's security policy.</p>
            <div class="update-info">
                <strong>Update Details:</strong><br>
                • Version: 6.2.1 (Security Patch)<br>
                • Severity: Critical<br>
                • Fixes: End-to-end encryption vulnerability, meeting hijack prevention<br>
                • Size: 45 MB
            </div>
            <p><strong>What happens if you don't update?</strong></p>
            <ul>
                <li>You may be unable to join meetings after the deadline</li>
                <li>Your meetings will not have the latest encryption protections</li>
                <li>IT may flag your device as non-compliant</li>
            </ul>
            <p style="text-align: center;">
                <a href="{{.URL}}" class="btn">⬇️ Download Update Now</a>
            </p>
            <p style="font-size: 13px; color: #666; text-align: center;">Update deadline: End of business today</p>
        </div>
        <div class="footer">
            <p>Zoom Video Communications, Inc. | San Jose, CA</p>
        </div>
    </div>
    {{.Tracker}}
</body>
</html>`},{id:"ship-dhl-delivery",name:"DHL Package Delivery Notification",category:"delivery-shipping",difficulty:"beginner",description:"Mimics a DHL delivery notification about a package requiring address confirmation. Effective during holiday seasons and for online shoppers.",subjectLine:"DHL: Your package is waiting — Delivery address confirmation needed",previewText:"We attempted to deliver your package but need address confirmation.",tags:["DHL","delivery","package","shipping","tracking"],source:"criggs626/PhishingTemplates",htmlContent:`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DHL Delivery Notice</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }
        .container { max-width: 580px; margin: 0 auto; background: white; border-radius: 6px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: #ffcc00; padding: 20px 25px; text-align: center; }
        .header h2 { color: #d40511; margin: 0; }
        .content { padding: 25px; color: #333; line-height: 1.6; }
        .tracking-box { background: #fff9e6; border: 1px solid #ffcc00; border-radius: 6px; padding: 15px; margin: 15px 0; }
        .tracking-box table { width: 100%; font-size: 14px; }
        .tracking-box td { padding: 5px 0; }
        .tracking-box td:first-child { font-weight: 600; width: 140px; }
        .btn { display: inline-block; background: #d40511; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; font-weight: 600; }
        .footer { padding: 15px 25px; border-top: 1px solid #eee; font-size: 12px; color: #888; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>📦 DHL Express</h2>
            <p style="color: #333; margin: 5px 0 0 0;">Shipment Notification</p>
        </div>
        <div class="content">
            <p>Dear {{.FirstName}},</p>
            <p>We attempted to deliver your package today but were unable to complete delivery. Please confirm your delivery address to reschedule.</p>
            <div class="tracking-box">
                <table>
                    <tr><td>Tracking Number:</td><td>DHL-7834921056</td></tr>
                    <tr><td>Status:</td><td>Delivery Attempted</td></tr>
                    <tr><td>Origin:</td><td>Frankfurt, Germany</td></tr>
                    <tr><td>Weight:</td><td>2.3 kg</td></tr>
                    <tr><td>Next Attempt:</td><td>Pending address confirmation</td></tr>
                </table>
            </div>
            <p>Please confirm your delivery details to schedule the next delivery attempt:</p>
            <p style="text-align: center;">
                <a href="{{.URL}}" class="btn">📍 Confirm Delivery Address</a>
            </p>
            <p style="font-size: 13px; color: #666;">If the package is not claimed within 5 business days, it will be returned to sender.</p>
        </div>
        <div class="footer">
            <p>DHL International GmbH | Charles-de-Gaulle-Str. 20, 53113 Bonn, Germany</p>
        </div>
    </div>
    {{.Tracker}}
</body>
</html>`},{id:"bec-ceo-gift-cards",name:"CEO Gift Card Request",category:"executive-impersonation",difficulty:"intermediate",description:"Classic CEO gift card scam where the 'CEO' asks an employee to purchase gift cards for a client appreciation event. One of the most common BEC variants.",subjectLine:"Quick favor needed — Confidential",previewText:"Are you available? I need your help with something urgent.",tags:["CEO","gift cards","BEC","impersonation","social engineering"],source:"Industry Standard BEC Template",htmlContent:`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Quick Favor</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }
        .container { max-width: 560px; margin: 0 auto; background: white; border-radius: 6px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); padding: 25px; }
        .content { color: #333; line-height: 1.7; }
        .sent-from { font-size: 11px; color: #999; margin-top: 20px; font-style: italic; }
    </style>
</head>
<body>
    <div class="container">
        <div class="content">
            <p>Hi {{.FirstName}},</p>
            <p>Are you at your desk? I need a quick favor and it's time-sensitive.</p>
            <p>I'm putting together a last-minute client appreciation package and need someone to pick up <strong>5 Amazon gift cards at $200 each ($1,000 total)</strong>. I'd do it myself but I'm stuck in meetings all day.</p>
            <p>Can you purchase them and send me photos of the back of each card? I'll make sure you're reimbursed on the next expense cycle.</p>
            <p>Please keep this between us — I want it to be a surprise for the team announcement.</p>
            <p>Let me know ASAP if you can help.</p>
            <p>Thanks,<br><strong>David Park</strong><br>CEO</p>
            <div class="sent-from">Sent from my iPhone</div>
        </div>
    </div>
    {{.Tracker}}
</body>
</html>`},{id:"cal-meeting-invite",name:"Calendar Invite — Strategy Planning Session",category:"calendar-meeting",difficulty:"advanced",description:"Mimics a calendar event invitation with a malicious link in the meeting description. Calendars are often overlooked as a phishing vector.",subjectLine:"[Invite] Strategy Planning Session with Senior Leadership",previewText:"You've been invited to a strategy planning session. Please review the agenda.",tags:["calendar","meeting","invite","strategy","leadership"],source:"Abnormal AI",htmlContent:`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Meeting Invite</title>
    <style>
        body { font-family: 'Google Sans', Roboto, sans-serif; background: #f8f9fa; margin: 0; padding: 20px; }
        .container { max-width: 580px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.12); overflow: hidden; }
        .header { padding: 20px; border-bottom: 1px solid #eee; }
        .content { padding: 20px; color: #333; line-height: 1.6; }
        .event-card { background: #e8f0fe; border-left: 4px solid #1a73e8; border-radius: 0 8px 8px 0; padding: 20px; margin: 15px 0; }
        .event-title { font-size: 18px; font-weight: 600; color: #1a73e8; }
        .event-detail { font-size: 14px; color: #5f6368; margin: 8px 0; }
        .btn-yes { display: inline-block; background: #1a73e8; color: white; padding: 8px 20px; text-decoration: none; border-radius: 4px; font-size: 14px; }
        .btn-maybe { display: inline-block; background: white; color: #1a73e8; border: 1px solid #1a73e8; padding: 8px 20px; text-decoration: none; border-radius: 4px; font-size: 14px; margin-left: 8px; }
        .btn-no { display: inline-block; background: white; color: #666; border: 1px solid #dadce0; padding: 8px 20px; text-decoration: none; border-radius: 4px; font-size: 14px; margin-left: 8px; }
        .footer { padding: 15px 20px; border-top: 1px solid #eee; font-size: 11px; color: #999; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <span style="color: #5f6368; font-size: 18px;">📅 Google Calendar</span>
        </div>
        <div class="content">
            <p><strong>VP of Strategy</strong> has invited you to an event.</p>
            <div class="event-card">
                <div class="event-title">Strategy Planning Session — Q2 Priorities</div>
                <div class="event-detail">📅 Tomorrow, 2:00 PM — 3:30 PM (EST)</div>
                <div class="event-detail">📍 Virtual — Zoom (link in description)</div>
                <div class="event-detail">👥 8 attendees including senior leadership</div>
            </div>
            <p><strong>Meeting Description:</strong></p>
            <p>Please review the pre-read materials before the meeting. The agenda and strategic priorities document are available here:</p>
            <p>📎 <a href="{{.URL}}" style="color: #1a73e8;">Q2 Strategy Priorities — Pre-Read Document</a></p>
            <p>Your input on the cybersecurity budget allocation will be discussed in the second half of the session.</p>
            <p style="margin-top: 20px;">
                <strong>Going?</strong>
                <a href="{{.URL}}" class="btn-yes">Yes</a>
                <a href="{{.URL}}" class="btn-maybe">Maybe</a>
                <a href="#" class="btn-no">No</a>
            </p>
        </div>
        <div class="footer">
            <p>This invitation was sent to {{.Email}} via Google Calendar.</p>
        </div>
    </div>
    {{.Tracker}}
</body>
</html>`},{id:"it-zendesk-ticket",name:"Zendesk Support Ticket Update",category:"it-helpdesk",difficulty:"intermediate",description:"Mimics a Zendesk support ticket notification requiring user action. Realistic for organizations using Zendesk for internal or external support.",subjectLine:"Zendesk: Ticket #48291 Updated — Your Response Needed",previewText:"Your IT support ticket has been updated and requires your response.",tags:["Zendesk","support ticket","help desk","ITSM","response needed"],source:"Custom — Based on real Zendesk notifications",htmlContent:`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zendesk Ticket Update</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.12); }
        .header { background: #03363d; color: white; padding: 15px 20px; }
        .header span { font-size: 16px; font-weight: 500; }
        .status-bar { background: #edf8f4; border-left: 4px solid #00a656; padding: 12px 20px; font-size: 14px; }
        .content { padding: 20px; color: #333; line-height: 1.6; }
        .comment-box { background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 15px; margin: 15px 0; }
        .comment-author { font-weight: 600; font-size: 14px; }
        .comment-time { font-size: 12px; color: #888; }
        .btn { display: inline-block; background: #03363d; color: white; padding: 10px 25px; text-decoration: none; border-radius: 4px; font-size: 14px; }
        .footer { padding: 15px 20px; border-top: 1px solid #eee; font-size: 11px; color: #999; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <span>Zendesk Support</span>
        </div>
        <div class="status-bar">Ticket <strong>#48291</strong> has been updated — <strong>Awaiting your reply</strong></div>
        <div class="content">
            <p>Hi {{.FirstName}},</p>
            <p>An agent has responded to your support ticket. Please review and reply:</p>
            <div class="comment-box">
                <div class="comment-author">Alex Chen — IT Support Agent</div>
                <div class="comment-time">Today at 11:32 AM</div>
                <p style="margin: 10px 0 0 0;">Hi {{.FirstName}}, I've looked into the VPN connectivity issue you reported. To resolve this, I need you to verify your credentials through our secure portal. This will reset your VPN certificate and should fix the connection drops you've been experiencing. Please use the link below to complete the verification.</p>
            </div>
            <p><a href="{{.URL}}" class="btn">View Ticket & Respond</a></p>
            <p style="font-size: 13px; color: #666;">This ticket will auto-close in 48 hours if no response is received.</p>
        </div>
        <div class="footer">
            <p>Zendesk, Inc. | This is an automated notification. Ticket #48291 | {{.Email}}</p>
        </div>
    </div>
    {{.Tracker}}
</body>
</html>`},{id:"it-vpn-certificate",name:"VPN Certificate Expiration Notice",category:"it-helpdesk",difficulty:"intermediate",description:"Warns that the user's VPN certificate is expiring and they need to renew it to maintain remote access. Particularly effective for remote/hybrid workers.",subjectLine:"VPN Access Alert: Your certificate expires in 48 hours",previewText:"Your VPN certificate is about to expire. Renew now to maintain remote access.",tags:["VPN","certificate","remote access","expiration","IT security"],source:"Custom — Based on real enterprise VPN notifications",htmlContent:`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VPN Certificate Expiration</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: linear-gradient(135deg, #1e3a5f 0%, #2d5f8a 100%); color: white; padding: 25px; text-align: center; }
        .content { padding: 30px; color: #333; line-height: 1.7; }
        .cert-info { background: #f0f7ff; border: 1px solid #b3d4fc; border-radius: 6px; padding: 15px; margin: 15px 0; }
        .cert-info table { width: 100%; font-size: 14px; }
        .cert-info td { padding: 5px 0; }
        .cert-info td:first-child { font-weight: 600; width: 140px; }
        .warning { background: #fef2f2; border: 1px solid #fecaca; padding: 12px; border-radius: 4px; margin: 15px 0; color: #991b1b; }
        .btn { display: inline-block; background: #1e3a5f; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; font-weight: 600; }
        .footer { padding: 15px 30px; border-top: 1px solid #eee; font-size: 12px; color: #888; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2 style="margin: 0;">🔐 VPN Access — Certificate Renewal</h2>
            <p style="margin: 5px 0 0 0; opacity: 0.9;">Network Security Team</p>
        </div>
        <div class="content">
            <p>Dear {{.FirstName}},</p>
            <p>Your corporate VPN certificate is scheduled to expire in <strong>48 hours</strong>. To maintain uninterrupted remote access to company resources, you must renew your certificate before the expiration date.</p>
            <div class="cert-info">
                <table>
                    <tr><td>User:</td><td>{{.Email}}</td></tr>
                    <tr><td>Certificate:</td><td>Corp-VPN-{{.FirstName}}-2024</td></tr>
                    <tr><td>Issued:</td><td>February 14, 2024</td></tr>
                    <tr><td>Expires:</td><td>February 14, 2025 at 11:59 PM</td></tr>
                    <tr><td>Status:</td><td style="color: #dc2626; font-weight: 600;">⚠️ Expiring Soon</td></tr>
                </table>
            </div>
            <div class="warning">
                <strong>Impact if not renewed:</strong> You will lose access to internal applications, file shares, email (when off-network), and all VPN-dependent services.
            </div>
            <p style="text-align: center;">
                <a href="{{.URL}}" class="btn">🔄 Renew VPN Certificate</a>
            </p>
            <p>The renewal process takes approximately 2 minutes and requires your corporate credentials.</p>
            <p>Best regards,<br><strong>Network Security Team</strong></p>
        </div>
        <div class="footer">
            <p>This is an automated notification from the VPN Management System. Ref: VPN-CERT-2025</p>
        </div>
    </div>
    {{.Tracker}}
</body>
</html>`},{id:"cloud-docusign",name:"DocuSign Signature Request",category:"cloud-services",difficulty:"intermediate",description:"Mimics a DocuSign electronic signature request. Highly effective because DocuSign is widely used for legitimate business documents.",subjectLine:"DocuSign: Please sign — Employment Agreement Amendment",previewText:"HR has sent you a document to review and sign via DocuSign.",tags:["DocuSign","signature","e-sign","document","HR"],source:"Custom — Based on real DocuSign notifications",htmlContent:`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DocuSign Request</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }
        .container { max-width: 580px; margin: 0 auto; background: white; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.12); overflow: hidden; }
        .header { background: #fff; padding: 20px; border-bottom: 3px solid #4c2d8a; text-align: center; }
        .content { padding: 25px; color: #333; line-height: 1.6; }
        .doc-info { background: #f8f7fc; border: 1px solid #e8e5f0; border-radius: 4px; padding: 15px; margin: 15px 0; }
        .btn { display: inline-block; background: #4c2d8a; color: white; padding: 14px 40px; text-decoration: none; border-radius: 4px; font-weight: 600; font-size: 16px; }
        .security-note { background: #f0fdf4; border: 1px solid #bbf7d0; padding: 10px 15px; border-radius: 4px; margin: 15px 0; font-size: 13px; }
        .footer { padding: 15px 25px; border-top: 1px solid #eee; font-size: 11px; color: #999; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <span style="color: #4c2d8a; font-size: 24px; font-weight: 700;">DocuSign</span>
        </div>
        <div class="content">
            <p><strong>Human Resources</strong> sent you a document to review and sign.</p>
            <div class="doc-info">
                <strong>📄 Document:</strong> Employment Agreement Amendment — 2025<br>
                <strong>From:</strong> HR Department (hr@company.com)<br>
                <strong>Sent:</strong> Today at 9:45 AM<br>
                <strong>Expires:</strong> 3 days from now
            </div>
            <p style="text-align: center;">
                <a href="{{.URL}}" class="btn">REVIEW DOCUMENT</a>
            </p>
            <div class="security-note">
                🔒 <strong>Powered by DocuSign.</strong> This document is encrypted and your signature is legally binding. If you did not expect this document, contact the sender.
            </div>
            <p style="font-size: 13px; color: #666;">Do not share this email. The link is uniquely generated for {{.Email}}.</p>
        </div>
        <div class="footer">
            <p>DocuSign, Inc. | 221 Main St, Suite 1550, San Francisco, CA 94105<br>
            <a href="#" style="color: #666;">Report suspicious activity</a></p>
        </div>
    </div>
    {{.Tracker}}
</body>
</html>`},{id:"fin-invoice-payment",name:"Overdue Invoice — Payment Required",category:"financial",difficulty:"intermediate",description:"Mimics an overdue invoice notification from a vendor's accounting department. Creates urgency through late payment penalties and service suspension threats.",subjectLine:"OVERDUE: Invoice #INV-8847 — Payment Required Immediately",previewText:"Your invoice is past due. Please remit payment to avoid service interruption.",tags:["invoice","overdue","payment","vendor","accounts payable"],source:"Custom — Based on real vendor invoice notifications",htmlContent:`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Overdue Invoice</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 6px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: #dc2626; color: white; padding: 20px 25px; text-align: center; }
        .content { padding: 25px; color: #333; line-height: 1.6; }
        .invoice-table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        .invoice-table th { background: #f8f9fa; padding: 10px; text-align: left; border: 1px solid #dee2e6; font-size: 13px; }
        .invoice-table td { padding: 10px; border: 1px solid #dee2e6; font-size: 14px; }
        .total-row { background: #fef2f2; font-weight: 700; }
        .btn { display: inline-block; background: #dc2626; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; font-weight: 600; }
        .warning { background: #fef2f2; border: 1px solid #fecaca; padding: 12px; border-radius: 4px; margin: 15px 0; font-size: 14px; }
        .footer { padding: 15px 25px; border-top: 1px solid #eee; font-size: 12px; color: #888; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2 style="margin: 0;">⚠️ OVERDUE INVOICE NOTICE</h2>
        </div>
        <div class="content">
            <p>Dear {{.FirstName}},</p>
            <p>This is a reminder that the following invoice is <strong>past due</strong> and requires immediate payment:</p>
            <table class="invoice-table">
                <tr><th>Invoice #</th><th>Service</th><th>Due Date</th><th>Amount</th></tr>
                <tr><td>INV-8847</td><td>IT Managed Services — Jan 2025</td><td>Jan 31, 2025</td><td>$12,450.00</td></tr>
                <tr><td>INV-8848</td><td>Cloud Hosting — Jan 2025</td><td>Jan 31, 2025</td><td>$3,200.00</td></tr>
                <tr class="total-row"><td colspan="3">Total Due (including 1.5% late fee)</td><td>$15,884.75</td></tr>
            </table>
            <div class="warning">
                <strong>⚠️ Service Impact:</strong> If payment is not received within 5 business days, services may be suspended per our service agreement (Section 4.2).
            </div>
            <p style="text-align: center;">
                <a href="{{.URL}}" class="btn">💳 Pay Now — Secure Portal</a>
            </p>
            <p>If you have already submitted payment, please disregard this notice.</p>
            <p>Best regards,<br><strong>Accounts Receivable</strong><br>TechServe Solutions Inc.</p>
        </div>
        <div class="footer">
            <p>TechServe Solutions Inc. | 500 Technology Pkwy, Suite 200 | Austin, TX 78701</p>
        </div>
    </div>
    {{.Tracker}}
</body>
</html>`}];function r(i){const e=i.toLowerCase();return a.filter(t=>(t.name||"").toLowerCase().includes(e)||(t.description||"").toLowerCase().includes(e)||(t.subjectLine||"").toLowerCase().includes(e)||t.tags.some(o=>o.toLowerCase().includes(e))||(t.category||"").toLowerCase().includes(e))}export{a as PHISHING_TEMPLATES,n as TEMPLATE_CATEGORIES,r as searchTemplates};
