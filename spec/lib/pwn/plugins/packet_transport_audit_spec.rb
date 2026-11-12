# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::Packet, 'offline constructors' do
  let(:options) do
    { ip_saddr: '192.0.2.1', ip_daddr: '192.0.2.2', ipv6_saddr: '2001:db8::1', ipv6_daddr: '2001:db8::2',
      eth_src: '00:11:22:33:44:55', eth_dst: '00:11:22:33:44:66', arp_src_mac: '00:11:22:33:44:55', arp_dst_mac: '00:11:22:33:44:66' }
  end

  before do
    # Never let a constructor discover interfaces or send PacketFu's ARP probe.
    allow(PacketFu::Utils).to receive(:whoami?).and_return({})
  end

  %i[arp eth hsrp icmp icmpv6 ip ipv6 tcp udp].each do |protocol|
    it "constructs #{protocol} without network discovery" do
      packet = described_class.public_send(:"construct_#{protocol}", options)
      expect(packet.to_s).not_to be_empty
      expect(PacketFu::Utils).not_to have_received(:whoami?)
    end
  end

  it 'preserves distinct HSRP state and hello-time values' do
    packet = described_class.construct_hsrp(options.merge(hsrp_state: 16, hsrp_hellotime: 7))
    expect(packet.hsrp_state).to eq(16)
    expect(packet.hsrp_hellotime).to eq(7)
  end

  it 'encodes IPv6 traffic class, flow label, next header and hop limit' do
    packet = described_class.construct_ipv6(options.merge(ipv6_class: 42, ipv6_label: 1234, ipv6_next: 59, ipv6_hop: 7))
    expect(packet.to_s.byteslice(14, 8).unpack('NnCC')).to eq([0x62a004d2, 0, 59, 7])
  end

  it 'uses the ICMPv6 packet class and caller checksum rather than IPv4 fields' do
    packet = described_class.construct_icmpv6(options.merge(icmpv6_type: 129, icmpv6_sum: 0x1234))
    expect(packet).to be_a(PacketFu::ICMPv6Packet)
    expect(packet.to_s.byteslice(54, 4).unpack('CCn')).to eq([129, 0, 0x1234])
  end

  it 'forwards TCP flags and options into the serialized packet' do
    flags = PacketFu::TcpFlags.new(syn: 1)
    packet = described_class.construct_tcp(options.merge(tcp_flags: flags, tcp_opts: "\x01\x01\x01\x01".b))
    expect(packet.tcp_flags.syn).to eq(1)
    expect(packet.tcp_opts).to eq("\x01\x01\x01\x01".b)
  end
end
