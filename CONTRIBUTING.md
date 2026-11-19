# Contributing

Run `python -m unittest -v test_healthcheck.py` and `python mikrotik_healthcheck.py --demo` before opening a pull request.

Keep router operations read-only and explicitly allowlisted. Do not add automatic repairs, packet capture, traffic generation or credential collection. Unsupported menus and incomplete responses must remain visible in coverage, never become a passing health check.

Use synthetic fixtures. For compatibility reports, include RouterOS version and model, but remove real usernames, IPs, MACs, credentials and logs containing private details. Live router tests are optional and require authorization from that router's owner.

For parser changes, add tests for truncated output and multiple RouterOS representations. For new findings, include evidence, limitations and a targeted next step. Keep the HTML report standalone, escaped and usable without Internet access.
