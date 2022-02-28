# frozen_string_literal: true

require 'packetfu'
require 'packetfu/protos/arp'
require 'packetfu/protos/eth'
require 'packetfu/protos/hsrp'
require 'packetfu/protos/icmp'
require 'packetfu/protos/ip'
require 'packetfu/protos/ipv6'
require 'packetfu/protos/lldp'
require 'packetfu/protos/tcp'
require 'packetfu/protos/udp'
require 'socket'

module PWN
  module Plugins
    # This plugin is used for interacting with PCAP files to map out and visualize in an
    # automated fashion what comprises a infrastructure, network, and/or application
    module Packet
      # Supported Method Parameters::
      # pcap = PWN::Plugins::Packet.open_pcap_file(
      #   path: 'required - path to packet capture file'
      # )

      public_class_method def self.open_pcap_file(opts = {})
        path = opts[:path].to_s.scrub.strip.chomp if File.exist?(opts[:path].to_s.scrub.strip.chomp)

        PacketFu::PcapFile.read_packets(path)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # pkt = PWN::Plugins::Packet.construct_arp(
      #   ip_saddr: 'required - source ip of packet',
      #   ip_daddr: 'required - destination ip to send packet',
      #   payload: 'optional - packet payload defaults to empty string',
      #   ip_id: 'optional - defaults to 0xfeed',
      #   iface: 'optional - interface to send packet (defaults to eth0)',
      # )

      public_class_method def self.construct_arp(opts = {})
        # Ethernet Header
        eth_src = opts[:eth_src]
        eth_dst = opts[:eth_dst]

        if opts[:eth_proto]
          eth_proto = opts[:eth_proto]
        else
          eth_proto = 0x0806 # ARP
        end

        # ARP Header
        if opts[:arp_hw]
          arp_hw = opts[:arp_hw].to_i
        else
          arp_hw = 1
        end

        if opts[:arp_proto]
          arp_proto = opts[:arp_proto]
        else
          arp_proto = 0x0800 # IPv4
        end

        if opts[:arp_hw_len]
          arp_hw_len = opts[:arp_hw_len].to_i
        else
          arp_hw_len = 6
        end

        if opts[:arp_proto_len]
          arp_proto_len = opts[:arp_proto_len].to_i
        else
          arp_proto_len = 4
        end

        if opts[:arp_opcode]
          arp_opcode = opts[:arp_opcode].to_i
        else
          arp_opcode = 1
        end

        arp_src_mac = opts[:arp_src_mac]
        arp_ip_saddr = opts[:ip_saddr].to_s.scrub.strip.chomp

        arp_dst_mac = opts[:arp_dst_mac]
        arp_ip_daddr = opts[:ip_daddr].to_s.scrub.strip.chomp

        # Payload
        payload = opts[:payload]

        pkt = PacketFu::ARPPacket.new(config: PacketFu::Utils.whoami?)
        # Ethernet Header
        pkt.eth_saddr = eth_src unless eth_src.nil?
        pkt.eth_daddr = eth_dst unless eth_dst.nil?
        pkt.eth_proto = eth_proto
        # ARP Header
        pkt.arp_hw = arp_hw
        pkt.arp_proto = arp_proto
        pkt.arp_hw_len = arp_hw_len
        pkt.arp_proto_len = arp_proto_len
        pkt.arp_opcode = arp_opcode
        pkt.arp_saddr_mac = arp_src_mac
        pkt.arp_saddr_ip = arp_ip_saddr
        pkt.arp_daddr_mac = arp_dst_mac
        pkt.arp_daddr_ip = arp_ip_daddr
        # Payload
        pkt.payload = payload if payload

        pkt
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # pkt = PWN::Plugins::Packet.construct_eth(
      #   ip_saddr: 'required - source ip of packet',
      #   ip_daddr: 'required - destination ip to send packet',
      #   payload: 'optional - packet payload defaults to empty string',
      #   ip_id: 'optional - defaults to 0xfeed',
      #   iface: 'optional - interface to send packet (defaults to eth0)',
      # )

      public_class_method def self.construct_eth(opts = {})
        # Ethernet Header
        eth_src = opts[:eth_src]
        eth_dst = opts[:eth_dst]

        if opts[:eth_proto]
          eth_proto = opts[:eth_proto]
        else
          eth_proto = 0x0800 # IPv4
        end

        # Payload
        payload = opts[:payload]

        pkt = PacketFu::EthPacket.new(config: PacketFu::Utils.whoami?)
        # Ethernet Header
        pkt.eth_saddr = eth_src unless eth_src.nil?
        pkt.eth_daddr = eth_dst unless eth_dst.nil?
        pkt.eth_proto = eth_proto
        # Payload
        pkt.payload = payload if payload

        pkt
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # pkt = PWN::Plugins::Packet.construct_hsrp(
      #   ip_saddr: 'required - source ip of packet',
      #   ip_daddr: 'required - destination ip to send packet',
      #   payload: 'optional - packet payload defaults to empty string',
      #   ip_id: 'optional - defaults to 0xfeed',
      #   iface: 'optional - interface to send packet (defaults to eth0)',
      # )

      public_class_method def self.construct_hsrp(opts = {})
        # Ethernet Header
        eth_src = opts[:eth_src]
        eth_dst = opts[:eth_dst]

        if opts[:eth_proto]
          eth_proto = opts[:eth_proto]
        else
          eth_proto = 0x0800 # IPv4
        end

        # IP Header
        if opts[:ip_v]
          ip_v = opts[:ip_v]
        else
          ip_v = 4
        end

        if opts[:ip_hl]
          ip_hl = opts[:ip_hl]
        else
          ip_hl = 5
        end

        if opts[:ip_tos]
          ip_tos = opts[:ip_tos]
        else
          ip_tos = 0
        end

        if opts[:ip_len]
          ip_len = opts[:ip_len]
        else
          ip_len = 20
        end

        if opts[:ip_id]
          ip_id = opts[:ip_id]
        else
          ip_id = 0xfeed
        end

        if opts[:ip_frag]
          ip_frag = opts[:ip_frag]
        else
          ip_frag = 0
        end

        if opts[:ip_ttl]
          ip_ttl = opts[:ip_ttl]
        else
          ip_ttl = 32
        end

        if opts[:ip_proto]
          ip_proto = opts[:ip_proto]
        else
          ip_proto = 17 # UDP
        end

        if opts[:ip_sum]
          ip_sum = opts[:ip_sum]
        else
          ip_sum = 0xffff
        end

        ip_saddr = opts[:ip_saddr]
        ip_daddr = opts[:ip_daddr]

        # UDP Header
        udp_src_port = opts[:udp_src_port]
        udp_dst_port = opts[:udp_dst_port]

        if opts[:udp_len]
          udp_len = opts[:udp_len]
        else
          udp_len = 8
        end

        if opts[:udp_sum]
          udp_sum = opts[:udp_sum]
        else
          udp_sum = 0x0000
        end

        # HSRP Header
        if opts[:hsrp_version]
          hsrp_version = opts[:hsrp_version]
        else
          hsrp_version = 0
        end

        if opts[:hsrp_opcode]
          hsrp_opcode = opts[:hsrp_opcode]
        else
          hsrp_opcode = 0
        end

        if opts[:hsrp_state]
          hsrp_state = opts[:hsrp_state]
        else
          hsrp_state = 0
        end

        if opts[:hsrp_hellotime]
          hsrp_state = opts[:hsrp_hellotime]
        else
          hsrp_state = 3
        end

        if opts[:hsrp_holdtime]
          hsrp_holdtime = opts[:hsrp_holdtime]
        else
          hsrp_holdtime = 10
        end

        if opts[:hsrp_priority]
          hsrp_priority = opts[:hsrp_priority]
        else
          hsrp_priority = 0
        end

        if opts[:hsrp_group]
          hsrp_group = opts[:hsrp_group]
        else
          hsrp_group = 0
        end

        if opts[:hsrp_reserved]
          hsrp_reserved = opts[:hsrp_reserved]
        else
          hsrp_reserved = 0
        end

        if opts[:hsrp_password]
          hsrp_password = opts[:hsrp_password]
        else
          hsrp_password = "cicso\x00\x00\x00"
        end

        if opts[:hsrp_addr]
          hsrp_addr = opts[:hsrp_addr]
        else
          hsrp_addr = '0.0.0.0'
        end

        # Payload
        payload = opts[:payload]

        pkt = PacketFu::HSRPPacket.new(config: PacketFu::Utils.whoami?)
        # Ethernet Header
        pkt.eth_saddr = eth_src unless eth_src.nil?
        pkt.eth_daddr = eth_dst unless eth_dst.nil?
        pkt.eth_proto = eth_proto
        # IP Header
        pkt.ip_v = ip_v
        pkt.ip_hl = ip_hl
        pkt.ip_tos = ip_tos
        pkt.ip_len = ip_len
        pkt.ip_id = ip_id
        pkt.ip_frag = ip_frag
        pkt.ip_ttl = ip_ttl
        pkt.ip_proto = ip_proto
        pkt.ip_sum = ip_sum
        pkt.ip_saddr = ip_saddr
        pkt.ip_daddr = ip_daddr
        # UDP Header
        pkt.udp_src = udp_src_port if udp_src_port
        pkt.udp_dst = udp_dst_port if udp_dst_port
        pkt.udp_len = udp_len
        pkt.udp_sum = udp_sum
        # HSRP Header
        pkt.hsrp_version = hsrp_version
        pkt.hsrp_opcode = hsrp_opcode
        pkt.hsrp_state = hsrp_state
        pkt.hsrp_hellotime = hsrp_hellotime
        pkt.hsrp_holdtime = hsrp_holdtime
        pkt.hsrp_priority = hsrp_priority
        pkt.hsrp_group = hsrp_group
        pkt.hsrp_reserved = hsrp_reserved
        pkt.hsrp_password = hsrp_password
        pkt.hsrp_addr = hsrp_addr
        # Payload
        pkt.payload = payload if payload

        pkt
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # pkt = PWN::Plugins::Packet.construct_icmp(
      #   ip_saddr: 'required - source ip of packet',
      #   ip_daddr: 'required - destination ip to send packet',
      #   payload: 'optional - packet payload defaults to "*ping*"',
      #   ip_id: 'optional - defaults to 0xfeed',
      #   iface: 'optional - interface to send packet (defaults to eth0)',
      # )

      public_class_method def self.construct_icmp(opts = {})
        # Ethernet Header
        eth_src = opts[:eth_src]
        eth_dst = opts[:eth_dst]

        if opts[:eth_proto]
          eth_proto = opts[:eth_proto]
        else
          eth_proto = 0x0800 # IPv4
        end

        # IP Header
        if opts[:ip_v]
          ip_v = opts[:ip_v]
        else
          ip_v = 4
        end

        if opts[:ip_hl]
          ip_hl = opts[:ip_hl]
        else
          ip_hl = 5
        end

        if opts[:ip_tos]
          ip_tos = opts[:ip_tos]
        else
          ip_tos = 0
        end

        if opts[:ip_len]
          ip_len = opts[:ip_len]
        else
          ip_len = 20
        end

        if opts[:ip_id]
          ip_id = opts[:ip_id]
        else
          ip_id = 0xfeed
        end

        if opts[:ip_frag]
          ip_frag = opts[:ip_frag]
        else
          ip_frag = 0
        end

        if opts[:ip_ttl]
          ip_ttl = opts[:ip_ttl]
        else
          ip_ttl = 32
        end

        if opts[:ip_proto]
          ip_proto = opts[:ip_proto]
        else
          ip_proto = 1 # ICMP
        end

        if opts[:ip_sum]
          ip_sum = opts[:ip_sum]
        else
          ip_sum = 0xffff
        end

        ip_saddr = opts[:ip_saddr]
        ip_daddr = opts[:ip_daddr]

        # ICMP Header
        if opts[:icmp_type]
          icmp_type = opts[:icmp_type]
        else
          icmp_type = 8
        end

        if opts[:icmp_code]
          icmp_code = opts[:icmp_code]
        else
          icmp_code = 0
        end

        if opts[:icmp_sum]
          icmp_sum = opts[:icmp_sum]
        else
          icmp_sum = 0xffff
        end

        # Payload
        opts[:payload] ? payload = opts[:payload] : payload = '*ping*'

        pkt = PacketFu::ICMPPacket.new(config: PacketFu::Utils.whoami?)
        # Ethernet Header
        pkt.eth_saddr = eth_src unless eth_src.nil?
        pkt.eth_daddr = eth_dst unless eth_dst.nil?
        pkt.eth_proto = eth_proto
        # IP Header
        pkt.ip_v = ip_v
        pkt.ip_hl = ip_hl
        pkt.ip_tos = ip_tos
        pkt.ip_len = ip_len
        pkt.ip_id = ip_id
        pkt.ip_frag = ip_frag
        pkt.ip_ttl = ip_ttl
        pkt.ip_proto = ip_proto
        pkt.ip_sum = ip_sum
        pkt.ip_saddr = ip_saddr
        pkt.ip_daddr = ip_daddr
        # ICMP Header
        pkt.icmp_type = icmp_type
        pkt.icmp_code = icmp_code
        pkt.icmp_sum = icmp_sum
        # Payload
        pkt.payload = payload if payload

        pkt
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # pkt = PWN::Plugins::Packet.construct_icmpv6(
      #   ip_saddr: 'required - source ip of packet',
      #   ip_daddr: 'required - destination ip to send packet',
      #   payload: 'optional - packet payload defaults to empty string',
      #   ip_id: 'optional - defaults to 0xfeed',
      #   iface: 'optional - interface to send packet (defaults to eth0)',
      # )

      public_class_method def self.construct_icmpv6(opts = {})
        # Ethernet Header
        eth_src = opts[:eth_src]
        eth_dst = opts[:eth_dst]

        if opts[:eth_proto]
          eth_proto = opts[:eth_proto]
        else
          eth_proto = 0x86dd # IPv6
        end

        # IPv6 Header
        if opts[:ipv6_v]
          ipv6_v = opts[:ipv6_v]
        else
          ipv6_v = 6
        end

        if opts[:ipv6_class]
          ipv6_class = opts[:ipv6_class]
        else
          ipv6_class = 0
        end

        if opts[:ipv6_label]
          ipv6_label = opts[:ipv6_label]
        else
          ipv6_label = 0
        end

        if opts[:ipv6_len]
          ipv6_len = opts[:ipv6_len]
        else
          ipv6_len = 0
        end

        if opts[:ipv6_next]
          ipv6_next = opts[:ipv6_next]
        else
          ipv6_next = 58
        end

        if opts[:ipv6_hop]
          ipv6_hop = opts[:ipv6_hop]
        else
          ipv6_hop = 255
        end

        ipv6_saddr = opts[:ipv6_saddr]
        ipv6_daddr = opts[:ipv6_daddr]

        # ICMPv6 Header
        if opts[:icmpv6_type]
          icmpv6_type = opts[:icmpv6_type]
        else
          icmp_type = 8
        end

        if opts[:icmpv6_code]
          icmpv6_code = opts[:icmpv6_code]
        else
          icmpv6_code = 0
        end

        if opts[:icmpv6_sum]
          icmp_sum = opts[:icmpv6_sum]
        else
          icmpv6_sum = 0x0000
        end

        # Payload
        payload = opts[:payload]

        pkt = PacketFu::IPv6Packet.new(config: PacketFu::Utils.whoami?)
        # Ethernet Header
        pkt.eth_saddr = eth_src unless eth_src.nil?
        pkt.eth_daddr = eth_dst unless eth_dst.nil?
        pkt.eth_proto = eth_proto
        # IPv6 Header
        pkt.ipv6_v = ipv6_v
        pkt.ipv6_hl = ipv6_hl
        pkt.ipv6_tos = ipv6_tos
        pkt.ipv6_len = ipv6_len
        pkt.ipv6_id = ipv6_id
        pkt.ipv6_frag = ipv6_frag
        pkt.ipv6_saddr = ipv6_saddr
        pkt.ipv6_daddr = ipv6_daddr
        # ICMPv6 Header
        pkt.icmpv6_type = icmpv6_type
        pkt.icmpv6_code = icmpv6_code
        pkt.icmpv6_sum = icmpv6_sum
        # Payload
        pkt.payload = payload if payload

        pkt
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # pkt = PWN::Plugins::Packet.construct_ip(
      #   ip_saddr: 'required - source ip of packet',
      #   ip_daddr: 'required - destination ip to send packet',
      #   payload: 'optional - packet payload defaults to empty string',
      #   ip_id: 'optional - defaults to 0xfeed',
      #   iface: 'optional - interface to send packet (defaults to eth0)',
      # )

      public_class_method def self.construct_ip(opts = {})
        # Ethernet Header
        eth_src = opts[:eth_src]
        eth_dst = opts[:eth_dst]

        if opts[:eth_proto]
          eth_proto = opts[:eth_proto]
        else
          eth_proto = 0x0800 # IPv4
        end

        # IP Header
        if opts[:ip_v]
          ip_v = opts[:ip_v]
        else
          ip_v = 4
        end

        if opts[:ip_hl]
          ip_hl = opts[:ip_hl]
        else
          ip_hl = 5
        end

        if opts[:ip_tos]
          ip_tos = opts[:ip_tos]
        else
          ip_tos = 0
        end

        if opts[:ip_len]
          ip_len = opts[:ip_len]
        else
          ip_len = 20
        end

        if opts[:ip_id]
          ip_id = opts[:ip_id]
        else
          ip_id = 0xfeed
        end

        if opts[:ip_frag]
          ip_frag = opts[:ip_frag]
        else
          ip_frag = 0
        end

        if opts[:ip_ttl]
          ip_ttl = opts[:ip_ttl]
        else
          ip_ttl = 32
        end

        if opts[:ip_proto]
          ip_proto = opts[:ip_proto]
        else
          ip_proto = -1
        end

        if opts[:ip_sum]
          ip_sum = opts[:ip_sum]
        else
          ip_sum = 0xffff
        end

        ip_saddr = opts[:ip_saddr]
        ip_daddr = opts[:ip_daddr]

        # Payload
        payload = opts[:payload]

        pkt = PacketFu::IPPacket.new(config: PacketFu::Utils.whoami?)
        # Ethernet Header
        pkt.eth_saddr = eth_src unless eth_src.nil?
        pkt.eth_daddr = eth_dst unless eth_dst.nil?
        pkt.eth_proto = eth_proto
        # IP Header
        pkt.ip_v = ip_v
        pkt.ip_hl = ip_hl
        pkt.ip_tos = ip_tos
        pkt.ip_len = ip_len
        pkt.ip_id = ip_id
        pkt.ip_frag = ip_frag
        pkt.ip_ttl = ip_ttl
        pkt.ip_proto = ip_proto
        pkt.ip_sum = ip_sum
        pkt.ip_saddr = ip_saddr
        pkt.ip_daddr = ip_daddr
        # Payload
        pkt.payload = payload if payload

        pkt
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # pkt = PWN::Plugins::Packet.construct_ipv6(
      #   ip_saddr: 'required - source ip of packet',
      #   ip_daddr: 'required - destination ip to send packet',
      #   payload: 'optional - packet payload defaults to empty string',
      #   ip_id: 'optional - defaults to 0xfeed',
      #   iface: 'optional - interface to send packet (defaults to eth0)',
      # )

      public_class_method def self.construct_ipv6(opts = {})
        # Ethernet Header
        eth_src = opts[:eth_src]
        eth_dst = opts[:eth_dst]

        if opts[:eth_proto]
          eth_proto = opts[:eth_proto]
        else
          eth_proto = 0x86dd # IPv6
        end

        # IPv6 Header
        if opts[:ipv6_v]
          ipv6_v = opts[:ipv6_v]
        else
          ipv6_v = 6
        end

        if opts[:ipv6_class]
          ipv6_class = opts[:ipv6_class]
        else
          ipv6_class = 0
        end

        if opts[:ipv6_label]
          ipv6_label = opts[:ipv6_label]
        else
          ipv6_label = 0
        end

        if opts[:ipv6_len]
          ipv6_len = opts[:ipv6_len]
        else
          ipv6_len = 0
        end

        if opts[:ipv6_next]
          ipv6_next = opts[:ipv6_next]
        else
          ipv6_next = 0
        end

        if opts[:ipv6_hop]
          ipv6_hop = opts[:ipv6_hop]
        else
          ipv6_hop = 255
        end

        ipv6_saddr = opts[:ipv6_saddr]
        ipv6_daddr = opts[:ipv6_daddr]

        # Payload
        payload = opts[:payload]

        pkt = PacketFu::IPv6Packet.new(config: PacketFu::Utils.whoami?)
        # Ethernet Header
        pkt.eth_saddr = eth_src unless eth_src.nil?
        pkt.eth_daddr = eth_dst unless eth_dst.nil?
        pkt.eth_proto = eth_proto
        # IPv6 Header
        pkt.ipv6_v = ipv6_v
        pkt.ipv6_hl = ipv6_hl
        pkt.ipv6_tos = ipv6_tos
        pkt.ipv6_len = ipv6_len
        pkt.ipv6_id = ipv6_id
        pkt.ipv6_frag = ipv6_frag
        pkt.ipv6_saddr = ipv6_saddr
        pkt.ipv6_daddr = ipv6_daddr
        # Payload
        pkt.payload = payload if payload

        pkt
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # pkt = PWN::Plugins::Packet.construct_tcp(
      #   ip_saddr: 'required - source ip of packet',
      #   ip_daddr: 'required - destination ip to send packet',
      #   payload: 'optional - packet payload defaults to empty string',
      #   ip_id: 'optional - defaults to 0xfeed',
      #   iface: 'optional - interface to send packet (defaults to eth0)',
      # )

      public_class_method def self.construct_tcp(opts = {})
        # Ethernet Header
        eth_src = opts[:eth_src]
        eth_dst = opts[:eth_dst]

        if opts[:eth_proto]
          eth_proto = opts[:eth_proto]
        else
          eth_proto = 0x0800 # IPv4
        end

        # IP Header
        if opts[:ip_v]
          ip_v = opts[:ip_v]
        else
          ip_v = 4
        end

        if opts[:ip_hl]
          ip_hl = opts[:ip_hl]
        else
          ip_hl = 5
        end

        if opts[:ip_tos]
          ip_tos = opts[:ip_tos]
        else
          ip_tos = 0
        end

        if opts[:ip_len]
          ip_len = opts[:ip_len]
        else
          ip_len = 20
        end

        if opts[:ip_id]
          ip_id = opts[:ip_id]
        else
          ip_id = 0xfeed
        end

        if opts[:ip_frag]
          ip_frag = opts[:ip_frag]
        else
          ip_frag = 0
        end

        if opts[:ip_ttl]
          ip_ttl = opts[:ip_ttl]
        else
          ip_ttl = 32
        end

        if opts[:ip_proto]
          ip_proto = opts[:ip_proto]
        else
          ip_proto = 6 # TCP
        end

        if opts[:ip_sum]
          ip_sum = opts[:ip_sum]
        else
          ip_sum = 0xffff
        end

        ip_saddr = opts[:ip_saddr]
        ip_daddr = opts[:ip_daddr]

        # TCP Header
        tcp_src_port = opts[:tcp_src_port]
        tcp_dst_port = opts[:tcp_dst_port]

        if opts[:tcp_seq]
          tcp_seq = opts[:tcp_seq]
        else
          tcp_seq = 0x5fcea416
        end

        if opts[:tcp_ack]
          tcp_ack = opts[:tcp_ack]
        else
          tcp_ack = 0x00000000
        end

        if opts[:tcp_hlen]
          tcp_hlen = opts[:tcp_hlen]
        else
          tcp_hlen = 5
        end

        if opts[:tcp_reserved]
          tcp_reserved = opts[:tcp_reserved]
        else
          tcp_reserved = 0
        end

        if opts[:tcp_ecn]
          tcp_ecn = opts[:tcp_ecn]
        else
          tcp_ecn = 0
        end

        tcp_flags = opts[:tcp_flags]

        if opts[:tcp_win]
          tcp_win = opts[:tcp_win]
        else
          tcp_win = 16_384
        end

        if opts[:tcp_sum]
          tcp_sum = opts[:tcp_sum]
        else
          tcp_sum = 0x1ab2
        end

        if opts[:tcp_urg]
          tcp_urg = opts[:tcp_urg]
        else
          tcp_urg = 0
        end

        tcp_opts = opts[:tcp_opts]

        # Payload
        payload = opts[:payload]

        pkt = PacketFu::TCPPacket.new(config: PacketFu::Utils.whoami?)
        # Ethernet Header
        pkt.eth_saddr = eth_src unless eth_src.nil?
        pkt.eth_daddr = eth_dst unless eth_dst.nil?
        pkt.eth_proto = eth_proto
        # IP Header
        pkt.ip_v = ip_v
        pkt.ip_hl = ip_hl
        pkt.ip_tos = ip_tos
        pkt.ip_len = ip_len
        pkt.ip_id = ip_id
        pkt.ip_frag = ip_frag
        pkt.ip_ttl = ip_ttl
        pkt.ip_proto = ip_proto
        pkt.ip_sum = ip_sum
        pkt.ip_saddr = ip_saddr
        pkt.ip_daddr = ip_daddr
        # TCP Header
        pkt.tcp_src = tcp_src_port if tcp_src_port
        pkt.tcp_dst = tcp_dst_port if tcp_dst_port
        pkt.tcp_seq = tcp_seq
        pkt.tcp_ack = tcp_ack
        pkt.tcp_hlen = tcp_hlen
        pkt.tcp_reserved = tcp_reserved
        pkt.tcp_ecn = tcp_ecn
        pkt.tcp_flags = PacketFu::TcpFlags.new
        pkt.tcp_win = tcp_win
        pkt.tcp_sum = tcp_sum
        pkt.tcp_urg = tcp_urg
        pkt.tcp_opts = PacketFu::TcpOptions.new
        # Payload
        pkt.payload = payload if payload

        pkt
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # pkt = PWN::Plugins::Packet.construct_udp(
      #   ip_saddr: 'required - source ip of packet',
      #   ip_daddr: 'required - destination ip to send packet',
      #   payload: 'optional - packet payload defaults to empty string',
      #   ip_id: 'optional - defaults to 0xfeed',
      #   iface: 'optional - interface to send packet (defaults to eth0)',
      # )

      public_class_method def self.construct_udp(opts = {})
        # Ethernet Header
        eth_src = opts[:eth_src]
        eth_dst = opts[:eth_dst]

        if opts[:eth_proto]
          eth_proto = opts[:eth_proto]
        else
          eth_proto = 0x0800 # IPv4
        end

        # IP Header
        if opts[:ip_v]
          ip_v = opts[:ip_v]
        else
          ip_v = 4
        end

        if opts[:ip_hl]
          ip_hl = opts[:ip_hl]
        else
          ip_hl = 5
        end

        if opts[:ip_tos]
          ip_tos = opts[:ip_tos]
        else
          ip_tos = 0
        end

        if opts[:ip_len]
          ip_len = opts[:ip_len]
        else
          ip_len = 20
        end

        if opts[:ip_id]
          ip_id = opts[:ip_id]
        else
          ip_id = 0xfeed
        end

        if opts[:ip_frag]
          ip_frag = opts[:ip_frag]
        else
          ip_frag = 0
        end

        if opts[:ip_ttl]
          ip_ttl = opts[:ip_ttl]
        else
          ip_ttl = 32
        end

        if opts[:ip_proto]
          ip_proto = opts[:ip_proto]
        else
          ip_proto = 17 # UDP
        end

        if opts[:ip_sum]
          ip_sum = opts[:ip_sum]
        else
          ip_sum = 0xffff
        end

        ip_saddr = opts[:ip_saddr]
        ip_daddr = opts[:ip_daddr]

        # UDP Header
        udp_src_port = opts[:udp_src_port]
        udp_dst_port = opts[:udp_dst_port]

        if opts[:udp_len]
          udp_len = opts[:udp_len]
        else
          udp_len = 8
        end

        if opts[:udp_sum]
          udp_sum = opts[:udp_sum]
        else
          udp_sum = 0xffde
        end

        # Payload
        payload = opts[:payload]

        pkt = PacketFu::UDPPacket.new(config: PacketFu::Utils.whoami?)
        # Ethernet Header
        pkt.eth_saddr = eth_src unless eth_src.nil?
        pkt.eth_daddr = eth_dst unless eth_dst.nil?
        pkt.eth_proto = eth_proto
        # IP Header
        pkt.ip_v = ip_v
        pkt.ip_hl = ip_hl
        pkt.ip_tos = ip_tos
        pkt.ip_len = ip_len
        pkt.ip_id = ip_id
        pkt.ip_frag = ip_frag
        pkt.ip_ttl = ip_ttl
        pkt.ip_proto = ip_proto
        pkt.ip_sum = ip_sum
        pkt.ip_saddr = ip_saddr
        pkt.ip_daddr = ip_daddr
        # UDP Header
        pkt.udp_src = udp_src_port if udp_src_port
        pkt.udp_dst = udp_dst_port if udp_dst_port
        pkt.udp_len = udp_len
        pkt.udp_sum = udp_sum
        # Payload
        pkt.payload = payload if payload

        pkt
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Packet.send(
      #   pkt: 'required - pkt returned from other #construct_<type> methods',
      #   iface: 'optional - interface to send packet (defaults to eth0)',
      # )

      public_class_method def self.send(opts = {})
        pkt = opts[:pkt]

        if opts[:iface]
          iface = opts[:iface].to_s.scrub.strip.chomp
        else
          iface = 'eth0'
        end

        if pkt.instance_of?(PacketFu::TCPPacket)
          this_ip = Socket.ip_address_list.detect(&:ipv4_private?).ip_address

          # If we're not passing a RST packet, prevent kernel from sending its own
          if this_ip == pkt.ip_saddr && pkt.tcp_flags.rst.zero?
            # We have to prevent the kernel space from sending a RST
            # because it won't have a socket open on the respective
            # port number before we have a chance to do anything.
            # In other words, the kernel will receive a SYN-ACK first,
            # know it didn't send a SYN & send a RST as a result.

            my_os = PWN::Plugins::DetectOS.type
            case my_os
            when :linux
              ipfilter = 'sudo iptables'
              chain_action = '-C'
              ipfilter_rule = "OUTPUT --protocol tcp --source #{pkt.ip_saddr} --destination #{pkt.ip_daddr} --destination-port #{pkt.tcp_dst} --tcp-flags RST RST -j DROP"

              ipfilter_cmd = "#{ipfilter} #{chain_action} #{ipfilter_rule}"

              unless system(ipfilter_cmd, out: File::NULL, err: File::NULL)
                chain_action = '-A'
                ipfilter_cmd = "#{ipfilter} #{chain_action} #{ipfilter_rule}"

                puts 'Preventing kernel from misbehaving when manipulating packets.'
                puts 'Creating the following iptables rule:'
                puts ipfilter_cmd
                system(ipfilter_cmd)

                puts "Be sure to delete iptables rule, once completed.  Here's how:"
                chain_action = '-D'
                ipfilter_cmd = "#{ipfilter} #{chain_action} #{ipfilter_rule}"
                puts ipfilter_cmd
              end

              pkt.recalc
              pkt.to_w(iface)

              system(ipfilter, "-D #{ipfilter_rule}")
            # when :osx
            #   ipfilter = 'pfctl'
            #   ipfilter_rule = "block out proto tcp from #{pkt.ip_saddr} to #{pkt.ip_daddr} port #{pkt.tcp_dst} flags R"
            #   system(ipfilter, "pfctl_add_flag #{ipfilter_rule}")
            #   pkt.recalc
            #   pkt.to_w(iface)
            #   system(ipfilter, "pfctl_del_flag #{ipfilter_rule}")
            else
              raise "ERROR: #{self} Does not Support #{my_os}"
            end
          end
        else
          pkt.recalc
          pkt.to_w(iface)
        end
      rescue StandardError => e
        raise e
      end

      # Author(s):: 0day Inc. <request.pentest@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <request.pentest@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          pcap = #{self}.open_pcap_file(
            path: 'required - path to packet capture file'
          )
          pcap[0].public_methods
          pcap.each do |p|
            print \"IP ID: \#{p.ip_id_readable} \"
            print \"IP Sum: \#{p.ip_sum_readable} \"
            print \"SRC IP: \#{p.ip_src_readable} \"
            print \"SRC MAC: (\#{p.eth_src_readable}) \"
            print \"TCP SRC PORT: \#{p.tcp_sport} => \"
            print \"DST IP: \#{p.ip_dst_readable} \"
            print \"DST MAC: (\#{p.eth_dst_readable}) \"
            print \"TCP DST PORT: \#{p.tcp_dport} \"
            print \"ETH PROTO: \#{p.eth_proto_readable} \"
            print \"TCP FLAGS: \#{p.tcp_flags_readable} \"
            print \"TCP ACK: \#{p.tcp_ack_readable} \"
            print \"TCP SEQ: \#{p.tcp_seq_readable} \"
            print \"TCP SUM: \#{p.tcp_sum_readable} \"
            print \"TCP OPTS: \#{p.tcp_opts_readable} \"
            puts \"BODY: \#{p.hexify(p.payload)}\"
            puts \"\\n\\n\\n\"
          end

          pkt = #{self}.construct_arp(
            ip_saddr: 'required - source ip of packet',
            ip_daddr: 'required - destination ip to send packet',
            payload: 'optional - packet payload defaults to empty string',
            ip_id: 'optional - defaults to 0xfeed',
            iface: 'optional - interface to send packet (defaults to eth0)',
          )

          pkt = #{self}.construct_eth(
            ip_saddr: 'required - source ip of packet',
            ip_daddr: 'required - destination ip to send packet',
            payload: 'optional - packet payload defaults to empty string',
            ip_id: 'optional - defaults to 0xfeed',
            iface: 'optional - interface to send packet (defaults to eth0)',
          )

          pkt = #{self}.construct_hsrp(
            ip_saddr: 'required - source ip of packet',
            ip_daddr: 'required - destination ip to send packet',
            payload: 'optional - packet payload defaults to empty string',
            ip_id: 'optional - defaults to 0xfeed',
            iface: 'optional - interface to send packet (defaults to eth0)',
          )

          pkt = #{self}.construct_icmp(
            ip_saddr: 'required - source ip of packet',
            ip_daddr: 'required - destination ip to send packet',
            payload: 'optional - packet payload defaults to \"*ping*\"',
            ip_id: 'optional - defaults to 0xfeed',
            iface: 'optional - interface to send packet (defaults to eth0)',
          )

          pkt = #{self}.construct_icmpv6(
            ip_saddr: 'required - source ip of packet',
            ip_daddr: 'required - destination ip to send packet',
            payload: 'optional - packet payload defaults to empty string',
            ip_id: 'optional - defaults to 0xfeed',
            iface: 'optional - interface to send packet (defaults to eth0)',
          )

          pkt = #{self}.construct_ip(
            ip_saddr: 'required - source ip of packet',
            ip_daddr: 'required - destination ip to send packet',
            payload: 'optional - packet payload defaults to empty string',
            ip_id: 'optional - defaults to 0xfeed',
            iface: 'optional - interface to send packet (defaults to eth0)',
          )

          pkt = #{self}.construct_ipv6(
            ip_saddr: 'required - source ip of packet',
            ip_daddr: 'required - destination ip to send packet',
            payload: 'optional - packet payload defaults to empty string',
            ip_id: 'optional - defaults to 0xfeed',
            iface: 'optional - interface to send packet (defaults to eth0)',
          )

          pkt = #{self}.construct_tcp(
            ip_saddr: 'required - source ip of packet',
            ip_daddr: 'required - destination ip to send packet',
            payload: 'optional - packet payload defaults to empty string',
            ip_id: 'optional - defaults to 0xfeed',
            iface: 'optional - interface to send packet (defaults to eth0)',
          )

          pkt = #{self}.construct_udp(
            ip_saddr: 'required - source ip of packet',
            ip_daddr: 'required - destination ip to send packet',
            payload: 'optional - packet payload defaults to empty string',
            ip_id: 'optional - defaults to 0xfeed',
            iface: 'optional - interface to send packet (defaults to eth0)',
          )

          #{self}.send(
            pkt: 'required - pkt returned from other #construct_<type> methods',
            iface: 'optional - interface to send packet (defaults to eth0)',
          )

          #{self}.authors
        "
      end
    end
  end
end
