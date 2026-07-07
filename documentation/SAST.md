# SAST (Static Application Security Testing)

`PWN::SAST` provides a growing collection of static analysis signatures and test case generators.

## Location

`lib/pwn/sast/` — one file per vulnerability class or mechanism.

## Current Coverage (examples)

- Command execution (multiple languages)
- Deserialization (Java, etc.)
- Eval / dangerous functions
- CSRF, redirect, inner HTML, postMessage issues
- Log4j, ReDoS, path traversal patterns
- Credential / secret patterns (keystore, passwords, AWS keys)
- Modern issues: prototype pollution, etc.
- Custom signature engine + factory

## Usage

```ruby
PWN::SAST.constants
PWN::SAST::TestCaseEngine.generate(...)
# Or call specific check modules
```

SAST results feed directly into reporting and can be orchestrated by the `pwn-ai` agent or custom drivers.

See `lib/pwn/sast/` source for the full and growing list of modules.

[[Diagrams]]
