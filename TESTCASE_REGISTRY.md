# ScopeGuard testcase registry

The canonical machine-readable registry is `app/registry.py`. It contains exactly the 40 required IDs below. Each registered check has an independent condition, command specification, deterministic evaluator, applicability rule, required vantage/capability/permission contract, and fixture coverage entry. Applicability is evaluated separately before execution for every condition.

Live execution and evidence coverage are defined in `app/live_adapters.py` and the checked-in matrix `docs/live_capability_matrix.json`. Thirty-four cases have an allowlisted live command adapter. Cases 03, 14, 26, 28, 31, and 32 remain capability-only because they require an authorized internal sensor, Layer-2 access, approved credential-policy evidence, asset inventory, egress vantage, or wireless hardware. A live adapter can still return `INCONCLUSIVE` when a service responds without establishing the testcase predicate.

The direct controlled-service audit is in `docs/security_engine_validation_matrix.json`. It reports actual command-path execution separately from service-specific validation and does not turn unvalidated cases into claims of coverage.

| ID | Testcase |
|---|---|
| 01 | NTP (123) — Open reflection/amplification risk |
| 02 | Passive/active OS, device and origin-IP fingerprinting |
| 03 | Sensitive subnet/VLAN segmentation and isolation |
| 04 | Databases — Anonymous access and known vulnerabilities |
| 05 | Legacy, deprecated and unsupported services/protocols |
| 06 | LDAP — 389 |
| 07 | NetBIOS — 137/138 |
| 08 | SSL/TLS protocol and cryptographic vulnerabilities |
| 09 | TFTP — 69 |
| 10 | Telnet — 23 |
| 11 | Vulnerable software versions |
| 12 | Filtered ports |
| 13 | Default SNMP community string public |
| 14 | ARP/MAC spoofing protections and monitoring |
| 15 | Exposed management and console interfaces |
| 16 | Exposed sensitive network shares |
| 17 | SNMP — 161/162 |
| 18 | FTP — 21 |
| 19 | Open ports and reachable services |
| 20 | WebSocket and MQTT endpoints |
| 21 | SMB — 139/445 |
| 22 | Banner grabbing and service identification |
| 23 | RDP — 3389 |
| 24 | Redis — 6379 |
| 25 | MS-SQL — 1433 |
| 26 | Authentication brute-force resistance |
| 27 | Server software version disclosure |
| 28 | Outbound connection and egress controls |
| 29 | IPv6 exposure and router advertisements |
| 30 | VPN endpoints and configuration |
| 31 | Rogue or unauthorized network devices |
| 32 | Wireless security |
| 33 | HTTP/HTTPS services — 80/443/8080 and discovered ports |
| 34 | SSH — 22 |
| 35 | Host-down and reachability validation |
| 36 | RPC/DCOM — 135/593 |
| 37 | VNC — 5900+ |
| 38 | ICMP information disclosure |
| 39 | SSH-based vulnerabilities/configuration |
| 40 | DNS — 53 |
