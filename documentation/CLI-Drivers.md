# CLI Drivers — `bin/pwn_*`

53 headless executables, each a thin `OptionParser` wrapper over one plugin
(or one workflow). They exist so CI/CD can call PWN without a REPL or an LLM.

![Driver anatomy](diagrams/driver-framework.svg)

## Full list

```text
pwn                              pwn_jenkins_thinBackup_aws_s3
pwn_android_war_dialer           pwn_jenkins_update_plugins
pwn_autoinc_version              pwn_jenkins_useradd
pwn_aws_describe_resources       pwn_mail_agent
pwn_bdba_groups                  pwn_msf_postgres_login
pwn_bdba_scan                    pwn_nessus_cloud_scan_crud
pwn_burp_suite_pro_active_rest_api_scan   pwn_nessus_cloud_vulnscan
pwn_burp_suite_pro_active_scan   pwn_nexpose
pwn_char_base64_encoding         pwn_nmap_discover_tcp_udp
pwn_char_dec_encoding            pwn_openvas_vulnscan
pwn_char_hex_escaped_encoding    pwn_pastebin_sample_filter
pwn_char_html_entity_encoding    pwn_phone
pwn_char_unicode_escaped_encoding  pwn_rdoc_to_jsonl
pwn_char_url_encoding            pwn_sast
pwn_crt_sh                       pwn_serial_check_voicemail
pwn_defectdojo_engagement_create pwn_serial_msr206
pwn_defectdojo_importscan        pwn_serial_qualcomm_commands
pwn_defectdojo_reimportscan      pwn_serial_son_micro_sm132_rfid
pwn_diff_csv_files_w_column_exclude  pwn_setup
pwn_domain_reversewhois          pwn_shodan_graphql_introspection
pwn_fuzz_net_app_proto           pwn_shodan_search
pwn_gqrx_scanner                 pwn_simple_http_server
pwn_jenkins_create_job           pwn_web_cache_deception
pwn_jenkins_create_view          pwn_www_checkip
pwn_jenkins_install_plugin       pwn_www_uri_buster
```

Run any with `--help` for its flags.

## `pwn_setup` — post-install doctor & capability provisioner

The one driver that isn't a plugin wrapper. It grows a bare `gem install pwn`
into a fully-armed host by installing OS headers / external tools for whatever
capability profile you ask for. Also reachable as `pwn setup` and
`pwn --setup[=PROFILE]`.

```bash
pwn_setup                        # read-only doctor; exit 1 if degraded
pwn_setup --list-profiles
pwn_setup --profile web --yes    # CI-friendly, non-interactive
pwn_setup --deps --dry-run       # print the apt/dnf/pacman/brew/port commands only
```

See [Installation](Installation.md) for the full profile table and
`PWN::Setup` API.

## Typical CI usage

```yaml
# .gitlab-ci.yml
sast:
  image: 0dayinc/pwn:latest
  script:
    - pwn_setup --profile net --yes
    - pwn_setup --check                                   # gate: exit 1 if degraded
    - pwn_sast -d "$CI_PROJECT_DIR" -o sast_out/
    - pwn_defectdojo_importscan -f sast_out/report.json -e "$DD_ENGAGEMENT"
```

## Write your own

See [Drivers](Drivers.md) — copy any file in `bin/`, swap the plugin call,
`rake install`, done.

[← Home](Home.md)
