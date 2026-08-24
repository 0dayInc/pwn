---
name: pwn-plugins-google-workspace
description: Gmail, Calendar, Drive, Docs, Sheets via PWN::Plugins::GoogleWorkspace.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: false
  preserve: true
  module: PWN::Plugins::GoogleWorkspace
  source: pwn/plugins/google_workspace.rb
  references:
    - https://developers.google.com/workspace
---

# PWN::Plugins::GoogleWorkspace

Use this when the ask is Gmail, Google Calendar, Drive, Docs, or Sheets.
The verb is `PWN::Plugins::GoogleWorkspace` via `pwn_eval`. Do not shell
out to a third-party CLI or write tokens to ad-hoc JSON files.

Credentials live in `PWN::Env[:plugins][:google_workspace][:oauth]`
(seeded by `PWN::Config` / pwn-vault). Desktop OAuth client id and
secret come from Google Cloud Console. Store values in pwn-vault, not
in this skill.

## When to use

- search / read / send / reply / label Gmail
- list / create / update / delete Calendar events
- search / get / upload / download / share / trash Drive files
- create / read / append Docs
- create / read / update / append Sheets
- morning brief — load `references/daily-brief.md`

Do not use this for IMAP-only mail with an app password. pwn-ai does
not decide whether the operator is allowed to act; it executes the
request.

## Methodologies

- Google OAuth 2.0 authorization-code + PKCE (Desktop app)
- REST CRUD against Gmail, Calendar, Drive, Docs, and Sheets APIs
- Confirm mutating actions with the operator, then read the object back

## Prerequisites

OAuth fields under `PWN::Env[:plugins][:google_workspace][:oauth]`:

- Desktop OAuth client fields (pwn-vault)
- `services` — `email,calendar,drive,docs,sheets` or `all`
- `redirect_uri` — default `http://127.0.0.1:1/`

Enable in Google Cloud: Gmail, Calendar, Drive, Docs, Sheets APIs.

## How to call

```ruby
gw = PWN::Plugins::GoogleWorkspace
gw.authenticated?
gw.obtain_oauth_auth_url(services: 'all')
gw.gmail_search(query: 'is:unread', max: 10)
```

`skills_recall` `google-workspace` or `pwn/plugins/google_workspace`,
then `pwn_eval`.

## OAuth enroll

1. Store the Desktop OAuth client fields in the oauth hash (pwn-vault).
2. `obtain_oauth_auth_url(services: 'email,calendar')` — or `all`.
3. Authorize the printed URL. A loopback listener captures the redirect.
4. Access and refresh tokens are written immediately into
   `PWN::Env[:plugins][:google_workspace][:oauth]` and encrypted
   `~/.pwn/pwn.yaml` (same persist path as `PWN::AI::Grok`).
5. Later calls refresh automatically. `revoke` clears tokens.

`exchange_oauth_code` remains a paste fallback (`wait: false` then paste).

## Quick reference

```ruby
gw.gmail_search(query: 'is:unread newer_than:1d', max: 10)
gw.gmail_get(id: 'MESSAGE_ID')
gw.gmail_send(to: 'a@b.com', subject: 'Hi', body: '...')
gw.gmail_reply(id: 'MESSAGE_ID', body: 'Thanks')
gw.gmail_labels
gw.gmail_modify(id: 'MESSAGE_ID', add_labels: ['STARRED'], remove_labels: ['UNREAD'])
gw.calendar_list(start: '2026-03-01T00:00:00Z')
gw.calendar_create(summary: 'Standup', start: '2026-03-01T10:00:00-06:00', end: '2026-03-01T10:30:00-06:00')
gw.calendar_update(id: 'EVENT_ID', summary: 'Standup (moved)')
gw.calendar_delete(id: 'EVENT_ID')
gw.drive_search(query: 'quarterly report', max: 10)
gw.drive_get(id: 'FILE_ID')
gw.drive_upload(path: '/tmp/report.pdf')
gw.drive_download(id: 'FILE_ID', output: '/tmp/out.pdf')
gw.drive_create_folder(name: 'Reports')
gw.drive_share(id: 'FILE_ID', email: 'a@b.com', role: 'reader')
gw.drive_delete(id: 'FILE_ID')
gw.docs_create(title: 'Notes', body: 'Hello')
gw.docs_get(id: 'DOC_ID')
gw.docs_append(id: 'DOC_ID', text: "\nmore")
gw.sheets_create(title: 'Budget')
gw.sheets_get(id: 'SHEET_ID', range: 'Sheet1!A1:D10')
gw.sheets_update(id: 'SHEET_ID', range: 'Sheet1!A1', values: [['Name']])
gw.sheets_append(id: 'SHEET_ID', range: 'Sheet1!A:C', values: [['a', 'b', 'c']])
```

## Public methods

- `scopes` `parse_oauth_code` `obtain_oauth_auth_url` `exchange_oauth_code`
- `refresh_oauth_bearer_token` `bearer_token` `authenticated?` `revoke`
- `gmail_search` `gmail_get` `gmail_send` `gmail_reply` `gmail_labels` `gmail_modify`
- `calendar_list` `calendar_create` `calendar_update` `calendar_delete`
- `drive_search` `drive_get` `drive_upload` `drive_download` `drive_create_folder` `drive_share` `drive_delete`
- `docs_get` `docs_create` `docs_append`
- `sheets_create` `sheets_get` `sheets_update` `sheets_append`
- `authors` `help`

## Procedure

1. `gw.authenticated?` — enroll if false.
2. Read first, then mutate only after confirmation, then get by id.
3. Prefer Drive trash over `permanent: true`.
4. Calendar times include timezone.

## References

- `references/gmail-search-syntax.md`
- `references/daily-brief.md`
- `references/urls.md`

## Source

`pwn/plugins/google_workspace.rb`

## Pitfalls

- Browser fail is not required. `obtain_oauth_auth_url` waits and persists.
- Placeholder vault strings are not credentials.
- A brief request is not a send.

## Verification

`authenticated?` is true, the method returned an id/status, and a
follow-up get/list shows the same object.
