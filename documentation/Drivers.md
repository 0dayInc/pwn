# Drivers & Custom Automation

`PWN::Driver` and the `/opt/pwn/bin/` directory provide patterns for packaging reusable security automation.

## What is a Driver?

A self-contained Ruby script or gem that:
- Loads the `pwn` environment
- Orchestrates multiple plugins, AI calls, or custom logic
- Can be scheduled via cron or run standalone

## Examples

Look in `/opt/pwn/bin/` (shipped with the gem).

## Creating New Drivers

1. Study existing examples in `bin/`.
2. Use `PWN::Driver` helpers where appropriate.
3. Leverage the full plugin + AI surface.
4. Distill recurring successful patterns into **Skills**.

Drivers + Skills + Agent = extremely powerful autonomous red teaming / research platform.

[[Diagrams]]
