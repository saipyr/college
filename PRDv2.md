# PRDv2 – Annexure Gap Analysis and Action Plan

## Summary
- Compared implemented policies and server/agent functionality to Annexure_A and Annexure_B requirements.
- Identified missing or partial controls and operational gaps; grouped by Windows, Linux, and cross‑cutting requirements.
- Provides concrete next actions without code changes.

## References (implementation)
- Server endpoints and security: `remotecli/server/app.py`
- Policy packs: `remotecli/policies/windows_policy_full.yaml`, `remotecli/policies/linux_policy_full.yaml`
- Agent execution: `remotecli/agent/agent.py`
- Coverage storage and mapping: `remotecli/storage.py`

## Windows (Annexure A) – Missing/Partial
- Account Policies
  - Password complexity verification/remediation is present, but full policy set still missing: reversible encryption is covered; minimum age covered; ensure “limit blank passwords” and “rename admin/guest accounts” (Security Options) with checks and remediation.
  - Admin lockout explicitly required; current rules cover threshold/duration, but add explicit “Admin account lockout must be enabled”.
- Local Policies (User Rights Assignment)
  - Additional rights not implemented: “Access Credential Manager” restricted; backup/restore privileges; “Change system time” scoping; “Allow log on through Remote Desktop Services”; “Deny log on locally/over network” for non‑admin accounts; etc.
- Security Options
  - Block Microsoft accounts; CTRL+ALT+DEL required; inactivity/lock screens; rename admin/guest; limit blank passwords; machine inactivity limit.
- System Services (25+)
  - Baseline incomplete: add rules for SNMP Trap, Remote Assistance, ICS, Function Discovery, SSDP (partially covered), Windows Media Network Sharing, Telnet Client/Server (server disabled covered), UPnP variants, etc.
- Firewall
  - Defaults enforced; add explicit inbound/outbound policy verification per profile, per Annexure text, including exceptions baselines (if defined).
- Advanced Audit Policies
  - Add missing categories: Logon/Logoff events (distinct from Account Logon), Policy modifications breadth, Object Access (File System/Registry), Detailed tracking (if Annexure requires), Removable storage is covered.
- Microsoft Defender Application Guard
  - Not implemented: isolation enforcement, camera/mic/download restrictions, clipboard controls.

## Linux (Annexure B) – Missing/Partial
- Filesystem
  - Blacklist list incomplete: add overlayfs, usb‑storage and others per Annexure; audit partitioning is present but ensure mandatory enforcement (fstab validation with mount options for `/dev/shm`, `/home`, `/var/tmp`).
- Boot & Kernel Hardening
  - Restrict bootloader config access (file perms/ownership checks); remove prelink; disable auto error reporting (apport/abrt per distro).
- Service‑Level Hardening
  - Extend to 20+ services per Annexure (autofs, avahi, dhcpd, dns, ldapd, nfs, rpcbind, samba, snmp, tftp, apache/nginx, xinetd, X11) with detection/remediation.
- Time Sync
  - Authorized timeserver enforcement and status checks beyond service enabled.
- Cron Hardening
  - Permissions secured for cron directories (e.g., `/etc/cron.*`), ownership and mode checks.
- Network Hardening
  - Wireless/Bluetooth disable; broaden kernel module blacklist (dccp, tipc, rds, sctp covered; add others per Annexure); expand sysctl coverage (ICMP ignore, redirect disable, SYN cookies, rp_filter, etc. already partially enforced).
- SSH Hardening
  - Permissions on `sshd_config`; “no empty passwords” explicit rule; additional Annexure fields (MaxStartups, ClientAliveInterval/CountMax) if required.
- Logging & Auditing
  - journald: access and single logging system checks (beyond rotation); rsyslog: forwarding is present, add remote server verification; logrotate: specific policies per logs.
  - auditd: currently 4+ rules; Annexure needs ≥20 specific: sudoers, privileged commands (covered), network configs, user/group configs, file access, log tampering, kernel module loading, passwd/shadow changes, setuid/setgid binaries, mount/unmount, time changes, and more.
  - Integrity: AIDE installed; add baseline config to monitor critical logs (`/var/log`, `/var/log/audit`) and periodic run schedule.
- System Maintenance
  - Permissions on passwd/group/shadow/gshadow; orphaned files; duplicate UIDs/GIDs/usernames; shell timeout (TMOUT); umask for root/users; only root has UID/GID 0; dotfiles secured. Only “world‑writable files” is currently audited.

## Cross‑Cutting & Non‑Functional – Missing/Partial
- Scalability & Persistence
  - SQLite remains; migrate to Postgres with migrations and pooling; add job queue for ingest/reporting to meet 50k endpoints.
- Reporting Cadence & Export
  - Scheduled PDF is implemented; add weekly/monthly compliance report content per Annexure; NTRO audit export exists in JSON—align format/fields if Annexure specifies a standard.
- Coverage Completeness
  - Populate full control catalog from Annexure and map all rules; add coverage metrics per control category and explicit “% controls covered” indicator.
- Zero‑Trust Posture
  - Optional mTLS exists; enforce device claim binding is implemented; add token refresh/rotation pipeline and revocation propagation.
- Protections & Limits
  - Add strict schema validation, request size limits across all admin endpoints; enhance `/exec` validation and allowlist exceptions handling.
- Agent Resource Guarantees
  - CPU telemetry and throttling present; add memory telemetry and rate controls for heavy scans/remediation; schedule windows to meet <5% sustained usage.

## Proposed Additions (No Code Changes in This Document)
- Windows
  - Implement additional Security Options and Local Policy rights rules; extend service baseline; add missing Advanced Audit categories; add Defender Application Guard rules.
- Linux
  - Extend blacklist and partitioning checks; implement bootloader access, prelink removal, error reporting disable; broaden services; enforce cron directory permissions; complete audit rule pack ≥20; harden SSH and logging/integrity configs.
- Cross‑Cutting
  - Migrate DB; formalize NTRO export format; expand coverage dashboard with control completeness; harden admin endpoints with schemas and payload limits.