

# **PRODUCT REQUIREMENTS DOCUMENT (PRD)**

### **NTRO Secure System Hardening & Compliance Automation**

---

## **1. Overview**

### **1.1 Product Name**

**NTRO Secure Endpoint Hardening & Compliance System (SEHCS)**

### **1.2 Purpose**

The purpose of SEHCS is to **automate, enforce, monitor, and audit** the security baseline described in *Annexure A (Windows Hardening)* and *Annexure B (Linux Hardening)* for NTRO-managed systems.
It ensures that all endpoints comply with NTRO's cybersecurity posture regarding:

* Account/Password policies
* Local security settings
* System hardening
* Filesystem restrictions
* Network and firewall posture
* Logging and auditing
* Privilege management
* Service-level controls

### **1.3 Target Users**

* NTRO Security Operations Centre (SOC)
* System Administrators (Windows/Linux)
* Compliance Reporting Teams
* Endpoint Security Automation Teams

### **1.4 Key Outcomes**

* 100% automated compliance with Annexure A & B
* Real-time monitoring & reporting
* Zero manual intervention for configuration enforcement
* Automated remediation for drift

---

## **2. Problem Statement**

Currently, security controls outlined in Annexure A and B must be applied manually across thousands of endpoints.
This leads to:

* Human error & configuration drift
* Inconsistent compliance across systems
* Difficult audit traceability
* No central monitoring or real-time reporting

There is a need for a software solution that **automatically enforces, validates, and reports compliance** in a unified dashboard.

---

## **3. Product Scope**

### **3.1 In Scope**

* Compliance rule engine for Windows & Linux
* Automated hardening application
* Real-time monitoring agents
* Central management dashboard
* Audit-ready reports
* Alerting for deviations
* Auto-remediation workflows
* Policy export/import
* Role-based access control

### **3.2 Out of Scope**

* Antivirus or malware detection
* Network monitoring
* Hardware inventory management
* Cloud or mobile devices (Phase 2)

---

# **4. Detailed Requirements (Derived from Annexure A & B)**

---

# **4.1 Windows Hardening Requirements (Annexure A)**

## **4.1.1 Account Policies**

* Enforce password history = 24
* Maximum age = 90 days
* Minimum age = 1 day
* Minimum length ≥ 12 characters
* Complexity required
* Reversible encryption disabled
* Account lockout after ≤ 5 attempts; duration ≥ 15 minutes
* Admin lockout must be enabled

## **4.1.2 Local Policies**

### User Rights Assignment

* Restrict “Access Credential Manager” to no one
* “Allow log on locally” → Admins, Users
* “Access this computer from network” → Admins, RDP Users
* Backup/Change system time roles defined

## **4.1.3 Security Options**

* Block Microsoft accounts
* Disable Guest account
* Limit blank passwords
* Rename admin & guest accounts
* Logon message text & title configurable
* CTRL+ALT+DEL required
* Machine inactivity & lockout thresholds

## **4.1.4 System Settings**

### User Account Control (UAC)

* Secure desktop prompts
* Enforce elevation restrictions
* Admin approval mode enabled

### System Services

Disable 25+ unnecessary services (Bluetooth, RDP, SNMP, RemoteRegistry, WinRM, W3SVC, Xbox services, UPnP, etc.)

## **4.1.5 Firewall Requirements**

Private & Public profiles must enforce:

* Firewall ON
* Inbound = Block
* Outbound = Allow
* Logging enabled with minimum 16MB log size
* Log dropped + successful packets

## **4.1.6 Advanced Audit Policies**

* Credential validation
* Security group changes
* Account lockouts
* Logon/logoff events
* Removable storage
* File share events
* Process creation
* Policy modifications
* System integrity
* SMBv1 disabled

## **4.1.7 Microsoft Defender Application Guard**

* Enforce isolation
* Disable camera/microphone
* Disable downloads
* Controlled clipboard access

---

# **4.2 Linux Hardening Requirements (Annexure B)**

## **4.2.1 Filesystem Requirements**

* Disable unused filesystem modules (cramfs, udf, hfs, overlayfs, usb-storage, etc.)
* Enforce separate partitions for:

  * /tmp, /dev/shm, /home, /var, /var/tmp, /var/log, /var/log/audit
* Apply nodev, nosuid, noexec based on partition
* Mandatory audit partitioning

## **4.2.2 Package & Boot Hardening**

* Bootloader password required
* Restrict bootloader config access
* Enable ASLR
* Restrict ptrace
* Disable core dumps
* Remove prelink
* Disable auto error reporting

## **4.2.3 Login & Banner Controls**

* MOTD/issue/issue.net configured and access controlled
* Local & remote login warnings

## **4.2.4 Service-Level Hardening**

Disable 20+ server services (autofs, avahi, dhcpd, dns, ftp, ldapd, nfs, rpcbind, samba, snmp, tftp, apache/nginx, xinetd, X11 etc.)
Disable insecure client packages (telnet, ftp, rsh, talk, etc.)

## **4.2.5 Time Sync**

Use either:

* systemd-timesyncd
* chrony
  Ensure:
* Authorized timeserver
* Daemon enabled

## **4.2.6 Cron Hardening**

* Cron must be active
* Permissions secured for all cron directories

## **4.2.7 Network Hardening**

* Disable IPv6 or identify status
* Disable wireless & Bluetooth
* Disable network modules (dccp, tipc, rds, sctp)
* Enforce kernel sysctl rules (ICMP ignore, redirect disable, syn cookies, rp_filter, etc.)

## **4.2.8 Firewall Hardening**

* UFW installed
* iptables-persistent removed
* UFW enabled with default deny
* Loopback rules enforced
* Explicit rules for open ports

## **4.2.9 SSH Hardening**

* Permissions on sshd_config
* Strong ciphers/KEX/MACs
* No root login
* No empty passwords
* Banner configured
* MaxAuthTries, MaxSessions, LoginGraceTime configured
* Forwarding disabled

## **4.2.10 Privilege Escalation (sudo)**

* Sudo installed
* Sudo logs enabled
* Password required
* Re-authentication not disabled
* Timeout configurable

## **4.2.11 PAM Hardening**

* pam_unix, pam_faillock, pam_pwquality, pam_pwhistory enforced
* Password length, quality, dictionary check
* Root history enforcement

## **4.2.12 User & Account Policies**

* Password expiry
* Mask for root & users
* Only root has UID/GID 0
* System accounts locked
* Shell timeout

## **4.2.13 Logging & Auditing**

### journald

* Rotation, access, single logging system

### rsyslog

* Installed, active, sending logs to central server
* logrotate configured

### auditd

* auditd installed, active, immutable rules
* 20+ specific audit rules enforcing changes to:

  * sudoers
  * privileged commands
  * network configs
  * user/group configs
  * file access
  * log tampering
  * kernel module loading

### File Access for Audit Logs

* Permissions for logs
* Owner/group restricted
* Integrity checking required (AIDE)

## **4.2.14 System Maintenance**

* Permissions on passwd, group, shadow, gshadow
* No world writable files
* No orphaned files
* No duplicate UIDs/GIDs/usernames
* Dotfiles secured

---

# **5. Functional Requirements**

### **5.1 Agent**

* Lightweight OS-specific agent
* Runs in user space
* Local enforcement engine
* Hourly & on-demand scans
* Auto-remediation mode

### **5.2 Rule Engine**

* YAML/JSON policy files
* Version-controlled
* Rules mapped directly from Annexure A & B
* Supports custom overrides for specific machines

### **5.3 Dashboard**

* Real-time compliance score
* Drill-down by device, OS, rule category
* Export to CSV/PDF
* Alerting for:

  * Non-compliance
  * Drift
  * Auditd failures
  * Firewall changes

### **5.4 Reporting**

* Weekly, monthly compliance reports
* Audit log export compatible with NTRO audit formats
* Change history & timestamps

### **5.5 Security**

* TLS encrypted communication
* Signed policies
* Role-based access (Admin, Auditor, Read-only)

---

# **6. Non-Functional Requirements**

| Category         | Requirement                                     |
| ---------------- | ----------------------------------------------- |
| Performance      | Agent CPU usage < 5%                            |
| Reliability      | 99.9% uptime                                    |
| Security         | Zero-trust architecture                         |
| Scalability      | 50,000 endpoints                                |
| Interoperability | Windows 10+, Server 2016+; RHEL, Ubuntu, Debian |
| Maintainability  | Modular rule sets                               |
| Auditability     | All actions logged                              |

---

# **7. Acceptance Criteria**

* 100% coverage of all Annexure A & B controls
* Dashboard showing ≥ 95% compliance across pilot devices
* All non-compliance auto-remediated OR alert raised
* Successful audit data export
* No conflict with existing security tools

---

# **8. Future Enhancements (Phase 2)**

* Mobile device hardening
* Cloud VM policy application
* AI-based anomaly detection
* Integration with SOC SIEM

