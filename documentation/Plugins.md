# `PWN::Plugins` - All 107 Modules

Every plugin is a plain Ruby module of `public_class_method def self.x(opts = {})`
methods with self-documenting `.help`. Source: `lib/pwn/plugins/*.rb`.

![Plugin ecosystem](diagrams/plugin-ecosystem.svg)

## Discover in the REPL

```ruby
PWN::Plugins.constants.sort
PWN::Plugins::BurpSuite.help
ls PWN::Plugins::NmapIt
show-source PWN::Plugins::Fuzz.http
```

## By category

### Web / Proxy / Browser
| Module | Purpose | Doc |
|---|---|---|
| **`BurpSuite`** ⭐ | Headless + REST control of Burp Pro; active/passive scan | [BurpSuite](BurpSuite.md) |
| `Zaproxy` | OWASP ZAP (fallback) | - |
| **`TransparentBrowser`** | Watir/Chrome headless or visible; devtools; proxy-aware | [Transparent-Browser](Transparent-Browser.md) |
| `Spider` | Recursive crawler | - |
| `OpenAPI` | Swagger/OpenAPI parse + fuzz targets | - |
| `URIScheme` | URI helpers | - |

### Network
| Module | Purpose | Doc |
|---|---|---|
| **`NmapIt`** | Nmap wrapper + XML parse | [NmapIt](NmapIt.md) |
| `Sock` | Raw TCP/UDP client; banner grab | - |
| `Packet` | Craft/sniff L2/L3 (PacketFu) | - |
| `Tor` | Start/rotate Tor for egress | - |
| `IPInfo` | Geo/ASN lookup | - |

### Exploitation
| Module | Purpose | Doc |
|---|---|---|
| **`Metasploit`** | msfrpcd client; run modules; sessions | [Metasploit](Metasploit.md) |
| **`Fuzz`** | Mutation/generation fuzzer | [Fuzzing](Fuzzing.md) |
| `BeEF` | Browser Exploitation Framework hooks | - |
| `Assembly` | asm ↔ opcodes (multi-arch, keystone/capstone) | - |

### OSINT / Recon
| Module | Purpose |
|---|---|
| `Shodan` | host/search/GraphQL introspection |
| `Hunter` | email discovery |
| `Github` | code/secret search |
| `HackerOne` | program/report API |

### Data Access / Parsing
| Module | Purpose |
|---|---|
| `DAOLDAP` · `DAOMongo` · `DAOPostgres` · `DAOSQLite3` | DB clients |
| `JSONPathify` | JSONPath query |
| `PDFParse` · `OCR` | document extraction |
| `ScannableCodes` | QR/barcode gen/read |

### Auth / Secrets
| Module | Purpose |
|---|---|
| `OAuth2` · `BasicAuth` · `AuthenticationHelper` | credential flows |
| `Vault` | Local encrypted configuration and engagement loot helpers; not a HashiCorp Vault client |

### Hardware / Physical
| Module | Purpose | Doc |
|---|---|---|
| `Serial` · `BusPirate` | UART/SPI/I²C | [Hardware](Hardware.md) |
| `MSR206` | magstripe reader/writer | [Hardware](Hardware.md) |
| `Android` | adb push/pull/shell/screencap | [Hardware](Hardware.md) |
| `BareSIP` · `Voice` | VoIP war-dialing / TTS | [Hardware](Hardware.md) |

### CI / DevOps / Vuln-Mgmt
| Module | Purpose |
|---|---|
| `Jenkins` | jobs/views/plugins/users |
| `Git` | repo helpers |
| `vSphere` | VMware inventory |
| `DefectDojo` | import/reimport findings |
| `BlackDuckBinaryAnalysis` | SBOM + CVE match |
| `NessusCloud` · `NexposeVulnScan` · `OpenVAS` | commercial/OSS scanners |
| `JiraDataCenter` | ticket findings |

### Comms
| Module | Purpose |
|---|---|
| `MailAgent` · `Pony` | SMTP send |
| `SlackClient` · `IRC` · `TwitterAPI` | chat/notify |
| `RabbitMQ` | AMQP |

### Utility
`FileFu` · `ThreadPool` · `Log` · `PWNLogger` · `Char` · `XXD` · `DetectOS` ·
`CreditCard` · `SSN` · `EIN` · `VIN` · `PS` · `MonkeyPatch` · `REPL` · `TTYSpinner`

## Full alphabetical list

`AFLplusplus AISandbox Android ArtifactRegistry Assembly AuthenticationHelper BareSIP BasicAuth BeEF BinaryAnalysis BinaryParser BinWorkspace BlackDuckBinaryAnalysis BurpSuite BusPirate Capability CapabilityBroker Char CredentialAttack CreditCard DAOLDAP DAOMongo DAOPostgres DAOSQLite3 Debugger DefectDojo DetectOS Detonate EIN Emulator ExploitDB ExploitDev FileFu Findings Frida Fuzz GDB GDBMI GDBMi Ghidra GhidraHeadless Git Github GoogleWorkspace HackerOne Handler Httpx Hunter IPInfo IRC Jenkins JiraDataCenter Jobs JSONPathify K8s Log MailAgent Metasploit MethodCatalog MitmProxy MonkeyPatch MSR206 NessusCloud NexposeVulnScan NmapIt Nuclei OAuth2 OCR OpenAPI OpenVAS Packet PDFParse Pony PreflightChecker ProcessTube PS PWNLogger RabbitMQ Radare2 Recon REDB REPL ROP Sandbox SBOM ScannableCodes Semgrep Serial Shodan SlackClient Sock Spider Sqlmap SSN ThreadPool Tor TransparentBrowser TTYSpinner TwitterAPI URIScheme Vault VIN Voice Volatility Vsphere XXD Zaproxy`

[← Home](Home.md) · [Diagrams](Diagrams.md)
