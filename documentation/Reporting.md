# `PWN::Reports` - Findings Pipeline

![Reporting pipeline](diagrams/reporting-pipeline.svg)

> **Install:** `pwn setup --profile vision` - imagemagick · graphviz ·
> rmagick / gruff headers. See [Installation](Installation.md).

## Generators  (`lib/pwn/reports/*.rb`)

| Module | Consumes | Emits |
|---|---|---|
| `Reports::SAST` | `PWN::SAST::Factory` output | HTML (with `HTMLHeader`/`HTMLFooter`) + JSON |
| `Reports::Fuzz` | `PWN::Plugins::Fuzz` crash log | HTML + JSON |
| `Reports::URIBuster` | `pwn_www_uri_buster` output | HTML |
| `Reports::Phone` | `PWN::Plugins::BareSIP` recon | HTML |
| `Reports::HTMLHeader` / `HTMLFooter` | - | shared chrome for all HTML reports |

## Delivery integrations

| Plugin | Purpose |
|---|---|
| `PWN::Plugins::DefectDojo` | `importscan` / `reimportscan` / `engagement_create` (also `bin/pwn_defectdojo_*`) |
| `PWN::Plugins::JiraDataCenter` | Create issues from findings |
| `PWN::Plugins::SlackClient` / `MailAgent` | Notify |

## Example

```ruby
findings = PWN::SAST::Factory.start(dir_path: './src')
PWN::Reports::SAST.generate(
  dir_path: './src', results_hash: findings, output_dir: './out'
)
PWN::Plugins::DefectDojo.importscan(
  engagement_id: 42, file: './out/report.json', scan_type: 'PWN SAST'
)
```

[← Home](Home.md) · [SAST](SAST.md) · [Fuzzing](Fuzzing.md)
