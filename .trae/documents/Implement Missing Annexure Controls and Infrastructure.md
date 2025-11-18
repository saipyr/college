## Scope & Goals
- Implement all missing Annexure A (Windows) and Annexure B (Linux) controls identified in PRDv2, with robust enforcement, verification, and reporting.
- Keep policies as the source of truth for control coverage; expand rule packs, map every rule to a control_id, and surface fleet/device coverage.
- Strengthen operational/infrastructure items (DB, telemetry, validation) required to meet non-functional requirements.

## Windows (Annexure A)
### Account/Password Policies
- Add and verify: limit blank password use, rename Administrator/Guest, machine inactivity lock, CTRL+ALT+DEL requirement.
- Confirm admin lockout enforcement explicitly (beyond threshold/duration) and map to control_id.
### Local Policies (User Rights Assignment)
- Expand rights coverage using `secedit /export` checks:
  - Backup/Restore privileges
  - Change system time and timezone scoping
  - Allow/Deny logon locally
  - Allow/Deny logon over network
  - Allow log on through Remote Desktop Services
  - Restrict Access Credential Manager
- Provide safe remediation guidance (avoid risky automated rights changes), but record non-compliance and raise alerts.
### System Services Baseline (25+)
- Add rules to disable: Remote Assistance, ICS (SharedAccess), Function Discovery (fdPHost/FDResPub), SSDP/UPnP variants, Windows Media Network Sharing, Telnet Server/Client, SNMP, and other Annexure-listed services.
- Map each to `WIN.SVC.*` control_ids.
### Firewall & Advanced Audit
- Verify per-profile inbound/outbound defaults and logging with explicit pass criteria.
- Add missing Advanced Audit categories: Logon/Logoff, Object Access (FS/Registry), Policy changes breadth, Detailed tracking (as required), Credential Validation (done), Security Group Management (done), Removable Storage (done), File Share (done), System Integrity (done).
### Microsoft Defender Application Guard
- Add detection and optional enablement rule; if mandated, provide remediation commands and operational guidance.

## Linux (Annexure B)
### Filesystem & Partitions
- Expand blacklist to include overlayfs, usb-storage and any additional Annexure-listed filesystems.
- Enforce required partitions: `/tmp`, `/var`, `/var/log`, `/var/log/audit`, `/home`, `/dev/shm`, `/var/tmp` with mount options nodev/nosuid/noexec where mandated.
### Boot & Kernel Hardening
- Restrict bootloader config access (file perms/owners) per distro.
- Remove prelink and disable auto error reporting (apport/abrt).
### Service-Level Baseline (20+)
- Disable Annexure-listed server services: autofs, avahi, dhcpd, dns, ftp, ldapd, nfs, rpcbind, samba, snmp, tftp, apache/nginx, xinetd, X11, etc.
### Time Sync & Cron
- Enforce authorized timeserver settings (chrony/timesyncd) and active status.
- Secure perms/ownership for `/etc/cron.*` directories.
### Network Hardening
- Disable wireless/Bluetooth; broaden kernel module blacklist (dccp, tipc, rds, sctp already covered).
- Extend sysctl coverage (ICMP ignore, redirects disabled, SYN cookies, rp_filter, etc.).
### SSH Hardening
- Add `sshd_config` permissions checks; enforce no empty passwords; add MaxStartups, ClientAliveInterval/CountMax where required.
### Logging, Auditing, Integrity
- journald: persistent storage directory and safe permissions; single logging system checks.
- rsyslog: remote forwarding verification; config perms hardening.
- logrotate: presence and baseline policy.
- AIDE: baseline includes `/var/log` and `/var/log/audit`; add scheduled run guidance.
- Auditd: ensure ≥20 rules cover passwd/shadow, user/group configs, privileged commands, network configs, log tampering, kernel modules, mounts, time changes, setuid/setgid, su/sudo, sshd_config, admin tools, sensitive files, package management, firewall configs.

## Cross-Cutting & Infrastructure
- Database migration to Postgres with migrations and pooling; add background job queue for findings ingest and report scheduling (to meet 50k endpoints).
- Coverage dashboard enhancements:
  - Show control completeness (% of Annexure controls implemented and passing) for fleet and device.
  - Export coverage to CSV/PDF with control_id and rule_id mapping.
- NTRO audit export format alignment with required fields (timestamps, actor, device, category, control_id/rule_id, compliance status).
- Harden admin endpoints with strict schemas and payload size limits; extend rate limiting and input validation.
- Agent telemetry: add memory metrics and scanning schedule/backoff to maintain <5% CPU footprint; optional maintenance windows.

## Implementation Plan (Phased)
### Phase 1: Policy Pack Expansion
- Windows: add missing Local Policies rights, Security Options, Service baseline, Advanced Audit categories, App Guard.
- Linux: add filesystem mounts/partitions, cron perms, service baseline, SSH parameters, journald/rsyslog/AIDE access policies.
- Map all new rules to control_ids; update seeding/import from policy.
### Phase 2: Server & Storage Enhancements
- Add coverage endpoints/export; expand `/coverage` to include % completeness.
- Begin DB migration scaffolding (config toggle to Postgres, migrations, ORM or migration scripts).
- Tighten admin schemas and limits.
### Phase 3: Agent & Ops
- Add memory telemetry; configurable maintenance windows; expanded backoff.
- Scheduled AIDE runs and journald integrity checks if required.
### Phase 4: Verification & Reporting
- Unit/integration tests for rule evaluation and coverage mapping.
- Generate weekly/monthly reports; align NTRO export.
- Pilot with sample devices; target ≥95% compliance across pilot and iterate.

## Validation & Risk
- Validate rules safely: many Windows rights changes are high-risk; default to guidance with audit/alert unless explicitly allowed.
- Distro differences on Linux (Debian/Ubuntu/RHEL) handled via conditional checks/commands.
- Coverage calculated from latest findings; ensure agents run post-update to refresh data.

## Deliverables
- Updated policy YAML files with control_ids.
- Coverage reports (CSV/PDF) and `/coverage` endpoint enhancements.
- Optional Postgres migration scripts/config.
- Documentation notes for ops (AIDE/journald schedule, AppGuard).