# CLI Drivers — `bin/pwn_*`

52 headless executables, each a thin `OptionParser` wrapper over one plugin
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
pwn_diff_csv_files_w_column_exclude  pwn_shodan_graphql_introspection
pwn_domain_reversewhois          pwn_shodan_search
pwn_fuzz_net_app_proto           pwn_simple_http_server
pwn_gqrx_scanner                 pwn_web_cache_deception
pwn_jenkins_create_job           pwn_www_checkip
pwn_jenkins_create_view          pwn_www_uri_buster
pwn_jenkins_install_plugin       pwn_xss_dom_vectors
                                 pwn_zaproxy_active_rest_api_scan
                                 pwn_zaproxy_active_scan
```

Run any with `--help` for its flags.

## Typical CI usage

```yaml
# .gitlab-ci.yml
sast:
  image: 0dayinc/pwn:latest
  script:
    - pwn_sast -d "$CI_PROJECT_DIR" -o sast_out/
    - pwn_defectdojo_importscan -f sast_out/report.json -e "$DD_ENGAGEMENT"
```

## Write your own

See [Drivers](Drivers.md) — copy any file in `bin/`, swap the plugin call,
`rake install`, done.

[← Home](Home.md)
