---
name: pwn-corpus
description: Drive PWN::Corpus from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Corpus
  source: pwn/corpus.rb
---

# PWN::Corpus

Named wordlist and payload corpora under ~/.pwn/corpora.

## When to use

Call `PWN::Corpus` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/corpus.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Corpus.help
PWN::Corpus.get(opts)
```

## Public methods

- `get`
- `update`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/corpus.rb`

## Verification

`PWN::Corpus.respond_to?(:get)` after the
module is loaded. Read the source for parameter names.
