# Security policy

Thor Watch runs as root to read system process metadata and cPanel domain logs.
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
