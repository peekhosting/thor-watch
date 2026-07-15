# Security policy

Thor Watch runs as root to read system process metadata, cPanel domain logs,
`/var/log/exim_mainlog`, and `/etc/userdomains`. The realtime email activity
view stores aggregated cPanel usernames and sender account names in the
root-only SQLite database; it does not store message bodies or recipients.
The on-demand MySQL tracker also uses the local MariaDB root connection to read
`INFORMATION_SCHEMA.USER_STATISTICS` and temporarily change the dynamic
`userstat` global variable. It restores the setting that existed before the
tracking window and never stores database credentials.
Please do not publish suspected vulnerabilities in a public issue.

Use the repository's **Security → Report a vulnerability** option to open a
private GitHub Security Advisory. Include the affected version, reproduction
steps, impact, and any suggested mitigation.

The project does not accept reports that require exposing production database
files, access logs, authentication cookies, or WHM session URLs.
