# Daily Brief (Gmail + Calendar)

Start-of-day or next-day brief from Gmail and Calendar via
`PWN::Plugins::GoogleWorkspace`. Load this when the operator asks for a
morning brief, meeting prep, or "what is on my calendar and what email
needs attention."

## Procedure

### 1. Resolve day and identity

Confirm timezone and target local day. Use a half-open window
`[day_start, next_day_start)` in the account timezone, not a vague
"today" filter. Done when UTC and local bounds are stated.

### 2. Fetch calendar events

```ruby
PWN::Plugins::GoogleWorkspace.calendar_list(
  start: day_start_iso,
  end: next_day_start_iso,
  max: 50
)
```

Include accepted and tentative meetings, all-day events, locations.
Detect overlaps and tight transitions. Done when the window is covered.

### 3. Fetch relevant Gmail

```ruby
PWN::Plugins::GoogleWorkspace.gmail_search(
  query: 'is:unread newer_than:1d -category:promotions -category:social',
  max: 20
)
```

Also search meeting participants / subjects from step 2. Read full
threads with `gmail_get(id:)` when the snippet is not enough. Do not
dump newsletters. Done when each included mail changes prep, priority,
or follow-up.

### 4. Link mail to meetings

Match by participant address, event title, and project. One shared
keyword is not an association. Extract promised docs, unanswered
questions, and decisions. Done when each meeting has prep items or
"no preparation found."

### 5. Build the brief

1. Schedule at a glance
2. Conflicts and tight transitions
3. Meetings requiring preparation
4. Urgent mail and deadlines
5. Follow-ups owed by the operator
6. Waiting on others
7. Coverage gaps (`authenticated?` false, API errors)

Rank by consequence and time, not message count.

### 6. Offer bounded actions

Draft replies, create holds, or send mail only after presenting them.
A brief request is not a send. After an approved mutation, read the
object back by id.

## Pitfalls

- Mixing account timezone with the machine timezone
- Hiding all-day commitments under timed meetings
- Treating tentative meetings as confirmed
- Creating events when the operator only asked for a brief

## Verification

- Day window and calendars covered are stated, or gaps are named
- Every prep item, deadline, and conflict traces to an event or thread id
- No mutation without presentation; approved writes were read back
