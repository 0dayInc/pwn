# Fuzzing — `PWN::Plugins::Fuzz` · `Sock` · `Packet`

![Fuzzing workflow](diagrams/fuzzing-workflow.svg)

> **Install:** `pwn setup --profile net` — pcaprub headers · tshark ·
> tcpdump. See [Installation](Installation.md).

## Generate

```ruby
payloads = PWN::Plugins::Fuzz.generate(
  seed: "GET / HTTP/1.1\r\nHost: t\r\n\r\n",
  strategy: :radamsa,       # :radamsa | :bitflip | :dictionary
  count: 500
)
enc = PWN::Plugins::Char.url_encode(str: payloads.first)
```

## Deliver

```ruby
payloads.each do |p|
  PWN::Plugins::Sock.connect(target: '10.0.0.5', port: 8080) do |s|
    s.write(p); s.read
  end
end
```

For raw L2/L3: `PWN::Plugins::Packet`.
CLI network fuzzer: `pwn_fuzz_net_app_proto -t HOST -p PORT -f seeds/`

## Monitor & report

`PWN::Plugins::PS` watches the target process; `PWN::Plugins::Log` tails its
log; `PWN::Reports::Fuzz` renders crash → HTML/JSON.

Feed unique crashes back as new seeds (`Log → Fuzz` dashed edge in the diagram).

[← Home](Home.md) · [Reporting](Reporting.md)
