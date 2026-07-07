# `PWN::Plugins::NmapIt`

Thin, composable wrapper over `nmap` with structured XML parsing.

![Network & infra testing](diagrams/network-infra-testing.svg)

```ruby
r = PWN::Plugins::NmapIt.port_scan(
  target: '10.0.0.0/24',
  ports:  '1-1024',
  service_scan: true,
  script:  'default,vuln',
  output_xml: '/tmp/scan.xml'
)
r[:hosts].each { |h| puts "#{h[:ip]} → #{h[:ports].map { |p| p[:portid] }}" }
```

CLI: `pwn_nmap_discover_tcp_udp -t 10.0.0.0/24 -o out/`

Pairs with `extro_observe` to persist banners for later
[correlation](Extrospection.md), and with `PWN::Plugins::Sock` /
`PWN::Plugins::Metasploit` for follow-up.

[← Home](Home.md) · [Plugins](Plugins.md)
