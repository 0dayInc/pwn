---
name: pwn-plugins-jiradatacenter
description: Drive PWN::Plugins::JiraDataCenter from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::JiraDataCenter
  source: pwn/plugins/jira_data_center.rb
---

# PWN::Plugins::JiraDataCenter

This plugin is used for interacting w/ on-prem Jira Server's REST API using the 'rest' browser type of PWN::Plugins::TransparentBrowser. This is based on the following Jira API Specification: https://developer.atlassian.com/server/jira/platform/rest-apis/

## When to use

Call `PWN::Plugins::JiraDataCenter` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/jira_data_center.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::JiraDataCenter.help
PWN::Plugins::JiraDataCenter.get_all_fields(opts)
```

## Public methods

- `get_all_fields`
- `get_user`
- `get_issue`
- `create_issue`
- `update_issue`
- `issue_comment`
- `get_issue_type_metadata`
- `clone_issue`
- `delete_issue`
- `delete_attachment`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/plugins/jira_data_center.rb`

## Verification

`PWN::Plugins::JiraDataCenter.respond_to?(:get_all_fields)` after the
module is loaded. Read the source for parameter names.
