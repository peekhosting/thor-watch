# Contributing to Thor Watch

Thank you for helping improve Thor Watch.

## Development setup

Thor Watch uses only the Python standard library. From the repository root:

```bash
./tests/run.sh
```

The test suite validates collector math, SQLite migrations, access-log
correlation, root-only CGI access, the AJAX endpoint, rendered dashboard
components, Python syntax, and installer shell syntax.

## Pull requests

- Keep the collector lightweight on servers with thousands of processes.
- Do not add state-changing actions such as process killing or firewall blocks
  without a separate security design and explicit confirmation flow.
- Escape all process, URL, query-string, and User-Agent values before rendering.
- Avoid new runtime dependencies unless there is a strong operational reason.
- Include tests for bug fixes and user-visible features.

## Compatibility

Changes should remain compatible with Python 3.6 syntax and cPanel AppConfig.
CI runs the supported source on newer maintained Python runtimes as well.
