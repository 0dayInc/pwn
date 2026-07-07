# Reporting

`PWN::Reports` generates structured output from scans, agent runs, SAST results, and manual findings.

## Capabilities

- Vulnerability report templating (Markdown + other formats)
- Integration with defect trackers (`PWN::Plugins::DefectDojo`, Jira, etc.)
- Automated report generation after agent tasks or plugin runs
- Custom report drivers

## Template

See example report templates in the PWN repo (or generate with `PWN::Reports`). Full pipeline in [Diagrams](Diagrams.md).

## Usage Patterns

Typically invoked at the end of reconnaissance → scanning → exploitation → analysis workflows:

```ruby
PWN::Reports.generate(...)
```

The `pwn-ai` agent is frequently instructed to "analyze findings and produce a report."

Combined with `PWN::Plugins::HackerOne` / bounty modules for streamlined disclosure workflows.

[[Diagrams]]
