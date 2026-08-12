PWN Contribution Rules:

- loop do
-   'Be Respectful'
-   'Ask Questions'
-   'Fork PWN'
-   'Make Changes'
-   'Create RSpec Tests'
-   'Pass RSpec && RuboCop Tests'
-   'Sign Your Work: https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work'
-   'Submit Pull Requests'
-   'Pass Upstream Tests'
- end

## Documentation after code changes

Whenever code under this repo changes:

1. Clear RuboCop on the paths you touched (`bundle exec rubocop -a <paths>`).
2. Run the full suite (`bundle exec rake`) and fix failures.
3. Only then refresh user docs: `README.md`, `documentation/*`, and
   `documentation/diagrams/dot/*.dot` (rebuild with
   `documentation/diagrams/build.sh`).
4. Keep user-facing markdown in plain US English (ASCII hyphens, no marketing
   filler, no internal agent backlog codes).

Do not commit documentation while lint or tests are still red.
See also `documentation/Contributing.md`.
