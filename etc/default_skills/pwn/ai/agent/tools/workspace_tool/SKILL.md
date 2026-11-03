---
name: pwn-ai-agent-tools-workspacetool
description: Drive PWN::Ai::Agent::Tools::WorkspaceTool from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Ai::Agent::Tools::WorkspaceTool
  source: pwn/ai/agent/tools/workspace_tool.rb
---

# PWN::Ai::Agent::Tools::WorkspaceTool

Public API for PWN::Ai::Agent::Tools::WorkspaceTool.

## When to use

Call `workspace_tool` when the task needs a provider-hosted tool. Ask Jev is
an Open WebUI workspace tool. Do not reimplement it in shell.

## Source

`pwn/ai/agent/tools/workspace_tool.rb`
