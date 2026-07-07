# NmapIt

`PWN::Plugins::NmapIt` provides a convenient Ruby wrapper around Nmap for reconnaissance.

## Features

- Easy target specification (hosts, ranges, CIDR)
- Parsing of XML output into usable Ruby structures
- Service version detection, script execution support
- Integration with other plugins (e.g. feed into TransparentBrowser or Shodan)

Commonly used early in agent workflows:

> "Run NmapIt against 10.0.0.0/24, identify web services, then spider with TransparentBrowser."

See source in `lib/pwn/plugins/nmap_it.rb`.

[[Diagrams]]
