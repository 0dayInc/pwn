# Plugins

PWN ships with **66+** plugins under `PWN::Plugins::*`.

## Browsing Plugins

```ruby
PWN::Plugins.constants.sort
PWN::Plugins::BurpSuite.methods(false).sort   # preferred web proxy/scanner
```

## Major Categories & Highlights

### Web / Proxy / Scanning
- **burp_suite** (preferred) — Headless + live interaction with Burp Suite Professional
- **zaproxy** — OWASP ZAP support (fallback)
- **transparent_browser** — Headless/visible browser automation, spidering, JS execution
- **spider**
- **nmap_it** — Nmap wrapper + parsing
- **nessus_cloud**, **nexpose_vuln_scan**, **openvas**

### Exploitation & Post-Exploitation
- **metasploit**
- **assembly**
- **fuzz**
- **packet**
- **beef** (Browser Exploitation Framework)
- **tor**

### Recon / OSINT
- **shodan**
- **hunter**
- **ip_info**
- **github**
- **hacker_one**

### Data & Auth
- **authentication_helper**, **basic_auth**, **oauth2**
- **dao_ldap**, **dao_mongo**, **dao_postgres**, **dao_sqlite3**
- **vault**

### Mobile / Hardware / Misc
- **android**
- **serial**, **bus_pirate**, **msr206**
- **ocr**, **pdf_parse**, **voice**
- **blockchain**, **bounty** (HackerOne), **defect_dojo**

### Utility
- **file_fu**, **json_pathify**, **log**, **pwn_logger**, **thread_pool**
- **monkey_patch**, **xxd**, **char**, **vin**, **ssn**, **credit_card**

Full list (current as of build):
`android assembly authentication_helper baresip basic_auth beef black_duck_binary_analysis burp_suite bus_pirate char credit_card dao_ldap dao_mongo dao_postgres dao_sqlite3 defect_dojo detect_os ein file_fu fuzz git github hacker_one hunter ip_info irc jenkins jira_data_center json_pathify log mail_agent metasploit monkey_patch msr206 nessus_cloud nexpose_vuln_scan nmap_it oauth2 ocr open_api openvas packet pdf_parse pony ps pwn_logger rabbit_mq repl scannable_codes serial shodan slack_client sock spider ssn thread_pool tor transparent_browser twitter_api uri_scheme vault vin voice vsphere xxd zaproxy`

Each plugin has self-documenting method signatures viewable via the REPL or source in `lib/pwn/plugins/`.

See individual plugin pages or source for details. Many plugins accept common options and return rich Ruby objects.

[[Diagrams]]
