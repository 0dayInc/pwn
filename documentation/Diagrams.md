# PWN Data-Flow Diagrams

27 SVG diagrams, all rendered from Graphviz sources in
[`diagrams/dot/`](diagrams/dot/) with a single shared visual theme
(see [`_THEME.md`](diagrams/dot/_THEME.md)). Rebuild everything with:

```bash
cd documentation/diagrams && ./build.sh
```

Every diagram uses strict layer→layer edges (`newrank=true` + `{rank=same}`
groups) so lines never criss-cross.

---

## 1 · Architecture

### Overall PWN Architecture
[source](diagrams/dot/overall-pwn-architecture.dot) · doc: [How PWN Works](How-PWN-Works.md)
![overall-pwn-architecture](diagrams/overall-pwn-architecture.svg)

### `~/.pwn/` Persistence Map
[source](diagrams/dot/persistence-filesystem.dot) · doc: [Persistence](Persistence.md)
![persistence-filesystem](diagrams/persistence-filesystem.svg)

### Plugin Ecosystem (66 modules)
[source](diagrams/dot/plugin-ecosystem.dot) · doc: [Plugins](Plugins.md)
![plugin-ecosystem](diagrams/plugin-ecosystem.svg)

---

## 2 · Entry Points

### `pwn` REPL Prototyping
[source](diagrams/dot/pwn-repl-prototyping.dot) · doc: [pwn REPL](pwn-REPL.md)
![pwn-repl-prototyping](diagrams/pwn-repl-prototyping.svg)

### REPL History → Reusable Driver / Skill
[source](diagrams/dot/history-to-drivers.dot) · doc: [Drivers](Drivers.md)
![history-to-drivers](diagrams/history-to-drivers.svg)

### Driver Anatomy (`bin/pwn_*`)
[source](diagrams/dot/driver-framework.dot) · doc: [CLI Drivers](CLI-Drivers.md)
![driver-framework](diagrams/driver-framework.svg)

---

## 3 · AI Agent

### pwn-ai Closed Self-Improvement Loop
[source](diagrams/dot/pwn-ai-feedback-learning-loop.dot) · doc: [Skills, Memory & Learning](Skills-Memory-Learning.md)
![pwn-ai-feedback-learning-loop](diagrams/pwn-ai-feedback-learning-loop.svg)

### Mistakes — Negative-Feedback Loop
[source](diagrams/dot/mistakes-negative-feedback.dot) · doc: [Mistakes](Mistakes.md)
![mistakes-negative-feedback](diagrams/mistakes-negative-feedback.svg)

### Multi-Provider LLM Integration
[source](diagrams/dot/ai-integration-tool-calling.dot) · doc: [AI Integration](AI-Integration.md)
![ai-integration-tool-calling](diagrams/ai-integration-tool-calling.svg)

### Agent Tool Registry (10 toolsets · 54 tools)
[source](diagrams/dot/agent-tool-registry.dot) · doc: [Agent Tool Registry](Agent-Tool-Registry.md)
![agent-tool-registry](diagrams/agent-tool-registry.svg)

### Memory · Skills · Sessions Detail
[source](diagrams/dot/memory-skills-detailed.dot) · doc: [Skills, Memory & Learning](Skills-Memory-Learning.md)
![memory-skills-detailed](diagrams/memory-skills-detailed.svg)

### Extrospection — World Awareness
[source](diagrams/dot/extrospection-world-awareness.dot) · doc: [Extrospection](Extrospection.md)
![extrospection-world-awareness](diagrams/extrospection-world-awareness.svg)

### Swarm — Native Multi-Agent
[source](diagrams/dot/swarm-multi-agent.dot) · doc: [Swarm](Swarm.md)
![swarm-multi-agent](diagrams/swarm-multi-agent.svg)

### Cron — Scheduled Jobs
[source](diagrams/dot/cron-scheduling.dot) · doc: [Cron](Cron.md)
![cron-scheduling](diagrams/cron-scheduling.svg)

### Sessions ↔ Cron ↔ Swarm Continuity
[source](diagrams/dot/sessions-cron-automation.dot) · doc: [Sessions](Sessions.md)
![sessions-cron-automation](diagrams/sessions-cron-automation.svg)

---

## 4 · Security Workflows

### End-to-End Penetration Test
[source](diagrams/dot/penetration-testing-workflow.dot)
![penetration-testing-workflow](diagrams/penetration-testing-workflow.svg)

### Web Application Testing
[source](diagrams/dot/web-application-testing.dot) · doc: [BurpSuite](BurpSuite.md)
![web-application-testing](diagrams/web-application-testing.svg)

### Burp ⭐ vs ZAP Selection
[source](diagrams/dot/burp-vs-zap-preference.dot)
![burp-vs-zap-preference](diagrams/burp-vs-zap-preference.svg)

### Network & Infrastructure Testing
[source](diagrams/dot/network-infra-testing.dot) · doc: [NmapIt](NmapIt.md)
![network-infra-testing](diagrams/network-infra-testing.svg)

### SAST / Code Scanning
[source](diagrams/dot/code-scanning-sast.dot) · doc: [SAST](SAST.md)
![code-scanning-sast](diagrams/code-scanning-sast.svg)

### Fuzzing
[source](diagrams/dot/fuzzing-workflow.dot) · doc: [Fuzzing](Fuzzing.md)
![fuzzing-workflow](diagrams/fuzzing-workflow.svg)

### Reverse Engineering & Binary Exploitation
[source](diagrams/dot/reverse-engineering-flow.dot) · doc: [Hardware](Hardware.md)
![reverse-engineering-flow](diagrams/reverse-engineering-flow.svg)

### Zero-Day Research Lifecycle
[source](diagrams/dot/zero-day-research-flow.dot)
![zero-day-research-flow](diagrams/zero-day-research-flow.svg)

### Reporting Pipeline
[source](diagrams/dot/reporting-pipeline.dot) · doc: [Reporting](Reporting.md)
![reporting-pipeline](diagrams/reporting-pipeline.svg)

---

## 5 · Domain-Specific

### AWS Cloud Security (90 services)
[source](diagrams/dot/aws-cloud-security.dot) · doc: [AWS](AWS.md)
![aws-cloud-security](diagrams/aws-cloud-security.svg)

### SDR / Radio Hacking
[source](diagrams/dot/sdr-radio-flow.dot) · doc: [SDR](SDR.md)
![sdr-radio-flow](diagrams/sdr-radio-flow.svg)

### Hardware & Physical-Layer
[source](diagrams/dot/hardware-hacking.dot) · doc: [Hardware](Hardware.md)
![hardware-hacking](diagrams/hardware-hacking.svg)

---

[← Back to Home](Home.md)
