# PWN Data Flow Diagrams (DFDs)

This page provides visual SVG Data Flow Diagrams illustrating how the PWN offensive cybersecurity framework operates across its key components and workflows.

## Core Architecture & Learning

- **PWN-AI Feedback Learning Loop**: The closed-loop self-improvement system using Memory, Skills, Metrics, and Learning to evolve capabilities.
  ![PWN AI Feedback Learning Loop](diagrams/pwn-ai-feedback-learning-loop.svg)

- **PWN REPL Prototyping**: Interactive development and rapid prototyping inside the full PWN namespace.
  ![PWN REPL Prototyping](diagrams/pwn-repl-prototyping.svg)

- **History Command to Driver Generation**: How REPL exploration and `history` are turned into reusable Drivers and Skills.
  ![History to Drivers](diagrams/history-to-drivers.svg)

## Primary Security Workflows

- **Penetration Testing Workflow**: End-to-end red teaming from recon to reporting, leveraging all PWN capabilities.
  ![Penetration Testing Workflow](diagrams/penetration-testing-workflow.svg)

- **Network & Infrastructure Testing**: Discovery, enumeration, scanning, packet crafting, and infra-specific testing (AWS, Jenkins, etc.).
  ![Network & Infrastructure Testing](diagrams/network-infra-testing.svg)

- **Web Application Testing**: Proxy-driven spidering, active scanning, manual assisted testing, and API security assessment. (BurpSuite preferred)
  ![Web Application Testing](diagrams/web-application-testing.svg)

- **Code Scanning & SAST**: Static analysis, test case generation, and vulnerability reporting using `PWN::SAST`.
  ![Code Scanning SAST](diagrams/code-scanning-sast.svg)

- **Fuzzing Workflows**: Protocol, file, network, and web fuzzing with monitoring and corpus refinement.
  ![Fuzzing Workflows](diagrams/fuzzing-workflow.svg)

- **Reverse Engineering Flow**: Binary/firmware analysis, patching, targeted fuzzing, and exploit crafting.
  ![Reverse Engineering Flow](diagrams/reverse-engineering-flow.svg)

## Additional Notes

- Diagrams are generated using Graphviz (dot) from source `.dot` files in `diagrams/dot/`.
- These visualize the integration of:
  - `PWN::Plugins` (67+ modules)
  - `PWN::AI::Agent` + tool calling + LLM providers
  - `PWN::Memory`, `PWN::Skills`, and Learning loop
  - `PWN::SAST`, `PWN::Reports`, `PWN::Driver`
- For the source definitions, see `diagrams/dot/*.dot`.
- Update these diagrams by editing the `.dot` files and re-rendering with `dot -Tsvg`.

## Related Wiki Pages

- [How PWN Works](How-PWN-Works.md)
- [pwn-ai Agent](pwn-ai-Agent.md)
- [pwn REPL](pwn-REPL.md)
- [Skills, Memory & Learning](Skills-Memory-Learning.md)
- [Plugins](Plugins.md)
- [SAST](SAST.md)
- [Drivers](Drivers.md)

[[Diagrams]]
