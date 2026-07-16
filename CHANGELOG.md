# Changelog

## 0.5.0

- Replaced the Trends navigation item with a dedicated long-running process finder
- Added current 30+ and 60+ day process views ordered by elapsed lifetime
- Added bounded collector snapshots for long-running processes, including user, parent PID, resource usage, category, and command

## 0.4.0

- Added a dedicated realtime cPanel/Exim email activity page
- Added five-second outbound message rankings by cPanel user and email account
- Added a 30-minute email sending rhythm chart and specialized live API
- Added incremental Exim log reading with rotation handling and bounded read sizes
- Added 14-day retention cleanup for aggregated email activity

## 0.3.0

- Added an AJAX-driven 60-second Top MySQL Users tracker
- Added per-user query, busy-time, and CPU-time delta reports
- Preserved and restored the pre-existing MariaDB `userstat` setting
- Avoided destructive `FLUSH USER_STATISTICS` by comparing counter snapshots

## 0.2.2

- Added fixed dashboard header and footer navigation
- Added PEEK Hosting developer credit and external website link
- Improved fixed navigation behavior on narrow screens

## 0.2.1

- Standardized the public product name as **Thor Watch**
- Added GitHub community, CI, and automated release files
- Removed server-specific wording from the default configuration

## 0.2.0

- Added an authenticated JSON live-data endpoint
- Added three-second AJAX updates without full-page reloads
- Added a continuously refreshed high-CPU process table
- Added responsive rolling load and CPU canvas charts
- Added collector-lag and AJAX connection indicators

## 0.1.2

- Added a session-preserving **Back to WHM** button to every dashboard and report page

## 0.1.1

- Corrected the WHM AppConfig `entryurl` to prevent a duplicated `/cgi/cgi/` path

## 0.1.0

- Initial root-only WHM dashboard
- Adaptive baseline and burst collection
- SQLite event history and retention
- cPanel user/process/service CPU aggregation
- LiteSpeed/cPanel access-log correlation
- TXT, JSON, and CSV exports
- Safe install, upgrade, and uninstall scripts
