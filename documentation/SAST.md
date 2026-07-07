# `PWN::SAST` — Static Application Security Testing

48 language-aware rule modules + a `TestCaseEngine` + a `Factory` loader.
Source: `lib/pwn/sast/*.rb`. CLI: `bin/pwn_sast`.

![SAST pipeline](diagrams/code-scanning-sast.svg)

## Run it

```bash
# CLI driver
pwn_sast -d /path/to/src -o /tmp/sast_out
```

```ruby
# REPL / pwn_eval
findings = PWN::SAST::Factory.start(dir_path: '/path/to/src')
PWN::Reports::SAST.generate(dir_path: '/path/to/src',
                            results_hash: findings,
                            output_dir: '/tmp/sast_out')
```

## Rule families (48 modules)

| Family | Modules |
|---|---|
| **Command execution** | `CmdExecutionJava` · `CmdExecutionPython` · `CmdExecutionRuby` · `CmdExecutionGoLang` · `CmdExecutionScala` · `Shell` · `Sudo` |
| **Web / DOM** | `CSRF` · `Redirect` · `ReDOS` · `InnerHTML` · `OuterHTML` · `LocationHash` · `WindowLocationHash` · `PostMessage` · `LocalStorage` · `BeefHook` |
| **Injection / eval** | `SQL` · `Eval` · `DeserialJava` · `Log4J` · `PHPInputMechanisms` · `PHPTypeJuggling` · `TypeScriptTypeJuggling` |
| **Crypto / secrets** | `MD5` · `SSL` · `Keystore` · `PaddingOracle` · `PrivateKey` · `Signature` · `Token` · `Password` · `Base64` · `HTTPAuthorizationHeader` |
| **Memory / native** | `BannedFunctionCallsC` · `UseAfterFree` |
| **Infra / meta** | `AWS` · `AMQPConnectAsGuest` · `ApacheFileSystemUtilAPI` · `PomVersion` · `Version` · `Port` · `Logger` · `ThrowErrors` · `TaskTag` · `Emoticon` |
| **Engine** | `Factory` (loader) · `TestCaseEngine` (probe generator) |

## Write a rule

Each rule implements `self.scan(opts = {})` taking `dir_path:` and returning an
array of `{file:, line:, match:, cwe:, severity:}` hashes. Copy any existing
rule in `lib/pwn/sast/`, add your regex/AST logic, and it's auto-loaded by
`Factory`.

## Downstream

`PWN::Reports::SAST` → HTML + JSON → `PWN::Plugins::DefectDojo.importscan` →
`PWN::Plugins::JiraDataCenter` tickets.

**See also:** [Reporting](Reporting.md) · [CLI Drivers](CLI-Drivers.md)

[← Home](Home.md)
