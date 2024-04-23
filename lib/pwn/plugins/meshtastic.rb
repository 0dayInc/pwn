# frozen_string_literal: true

require 'base64'
require 'geocoder'
require 'json'
require 'mqtt'
require 'openssl'
require 'securerandom'

module PWN
  module Plugins
    # Plugin used to interact with Meshtastic nodes
    module Meshtastic
      # Supported Method Parameters::
      # mqtt_obj = PWN::Plugins::Meshtastic.connect(
      #   host: 'optional - mqtt host (default: mqtt.meshtastic.org)',
      #   port: 'optional - mqtt port (defaults: 1883)',
      #   username: 'optional - mqtt username (default: meshdev)',
      #   password: 'optional - (default: large4cats)'
      # )

      public_class_method def self.connect(opts = {})
        # Publicly available MQTT server / credentials by default
        host = opts[:host] ||= 'mqtt.meshtastic.org'
        port = opts[:port] ||= 1883
        username = opts[:username] ||= 'meshdev'
        password = opts[:password] ||= 'large4cats'

        mqtt_obj = MQTT::Client.connect(
          host: host,
          port: port,
          username: username,
          password: password
        )

        mqtt_obj.client_id = SecureRandom.random_bytes(8).unpack1('H*')

        mqtt_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Meshtastic.subscribe(
      #   mqtt_obj: 'required - mqtt_obj returned from #connect method'
      #   region: 'optional - region (default: US)',
      #   channel: 'optional - channel name (default: LongFast)',
      #   psk: 'optional - channel pre-shared key (default: AQ==)',
      #   qos: 'optional - quality of service (default: 0)',
      #   json: 'optional - JSON output (default: false)'
      # )

      public_class_method def self.subscribe(opts = {})
        mqtt_obj = opts[:mqtt_obj]
        region = opts[:region] ||= 'US'
        channel = opts[:channel] ||= 'LongFast'
        psk = opts[:psk] ||= 'AQ=='
        qos = opts[:qos] ||= 0
        json = opts[:json] ||= false

        # TODO: Find JSON URI for this
        root_topic = "msh/#{region}/2/json" if json
        # root_topic = "msh/#{region}/2/e" unless json
        root_topic = "msh/#{region}/2/c" unless json
        mqtt_obj.subscribe("#{root_topic}/#{channel}/#", qos)

        # Decrypt the message
        # Our AES key is 128 or 256 bits, shared as part of the 'Channel' specification.

        # Actual pre-shared key for LongFast channel
        psk = '1PG7OiApB1nwvP+rz05pAQ==' if channel == 'LongFast'
        padded_psk = psk.ljust(psk.length + ((4 - (psk.length % 4)) % 4), '=')
        replaced_psk = padded_psk.gsub('-', '+').gsub('_', '/')
        psk = replaced_psk
        dec_psk = Base64.strict_decode64(psk)

        # cipher = OpenSSL::Cipher.new('AES-256-CTR')
        cipher = OpenSSL::Cipher.new('AES-128-CTR')

        if json
          mqtt_obj.get_packet do |json_packet|
            puts '-' * 80
            packet = JSON.parse(json_packet.payload, symbolize_names: true)
            puts JSON.pretty_generate(packet)
            puts '-' * 80
            puts "\n\n\n"
          end
        else
          mqtt_obj.get_packet do |packet|
            puts '-' * 80

            payload = packet.payload.to_s

            # Convert raw packet to hex-escaped bytes
            # puts "PSK: #{psk.inspect} | Length: #{psk.length}"
            # puts "Dec PSK: #{dec_psk.inspect} | Length: #{dec_psk.length}"
            packet_from_backwards = payload[3..6]
            if packet_from_backwards
              packet_from_str = packet_from_backwards.reverse
              packet_from_hex = packet_from_str.bytes.map { |byte| byte.to_s(16).rjust(2, '0') }.join
              packet_from = packet_from_hex.to_i(16)
              puts "\nFrom: #{packet_from_str.inspect} >> #{packet_from_hex} >> #{packet_from}"
            end

            packet_to_backwards = payload[8..11]
            if packet_to_backwards
              packet_to_str = packet_to_backwards.reverse
              packet_to_hex = packet_to_str.bytes.map { |byte| byte.to_s(16).rjust(2, '0') }.join
              packet_to = packet_to_hex.to_i(16)
              puts "To: #{packet_to_str.inspect} >> #{packet_to_hex} >> #{packet_to}"
            end

            mystery_byte = payload[12]
            if mystery_byte
              mystery_hex = mystery_byte.bytes.map { |byte| byte.to_s(16).rjust(2, '0') }.join
              mystery = mystery_hex.to_i(16)
              puts "Mystery 1: #{mystery_byte.inspect} >> #{mystery_hex} >> #{mystery}"
            end

            msg_len = 0
            msg_len_byte = payload[13]
            if msg_len_byte
              msg_len_hex = msg_len_byte.bytes.map { |byte| byte.to_s(16).rjust(2, '0') }.join
              msg_len = msg_len_hex.to_i(16)
            end
            puts "Message Length: #{msg_len_byte.inspect} >> #{msg_len}"

            channel_byte = payload[14]
            if channel_byte
              channel_hex = channel_byte.bytes.map { |byte| byte.to_s(16).rjust(2, '0') }.join
              channel = channel_hex.to_i(16)
              puts "Channel: #{channel_byte.inspect} >> #{channel_hex} >> #{channel}"
            end

            mystery_byte = payload[15]
            if mystery_byte
              mystery_hex = mystery_byte.bytes.map { |byte| byte.to_s(16).rjust(2, '0') }.join
              mystery = mystery_hex.to_i(16)
              puts "Mystery 2: #{mystery_byte.inspect} >> #{mystery_hex} >> #{mystery}"
            end

            pid_id_backwards = payload.b[-34..-31]
            if pid_id_backwards
              pid_str = pid_id_backwards.reverse
              pid_hex = pid_str.bytes.map { |byte| byte.to_s(16).rjust(2, '0') }.join
              packet_id = pid_hex.to_i(16)
              puts "ID: #{pid_str.inspect} >> #{pid_hex} >> #{packet_id}"
            end

            topic = packet.topic
            puts "\nTopic: #{topic}"

            if msg_len.positive?
              begin
                puts "Payload: #{payload.inspect}"
                puts "Payload Length: #{payload.length}"

                nonce_packet_id = [packet_id].pack('V').ljust(8, "\x00")
                nonce_from_node = [packet_from].pack('V').ljust(8, "\x00")
                # puts "Nonce from Node: #{nonce_from_node.inspect} | Length: #{nonce_from_node.length}"
                nonce = "#{nonce_packet_id}#{nonce_from_node}".b
                puts "Nonce: #{nonce.inspect} | Length: #{nonce.length}"

                # Decrypt the message
                # Key must be 32 bytes
                # IV mustr be 16 bytes
                cipher.decrypt
                cipher.key = dec_psk
                cipher.iv = nonce
                first_byte = 16
                last_byte = first_byte + msg_len - 1
                encrypted_payload = payload[first_byte..last_byte]
                puts "\nEncrypted Payload:\n#{encrypted_payload.inspect}"
                puts "Length: #{encrypted_payload.length}" if encrypted_payload

                decrypted = cipher.update(encrypted_payload) + cipher.final
                puts "\nDecrypted Payload:\n#{decrypted.inspect}"
                puts "Length: #{decrypted.length}" if decrypted
              rescue StandardError => e
                puts "Error decrypting message: #{e}"
              end
            end
            raw_packet = packet.to_s.b
            puts "\nRaw Packet: #{raw_packet.inspect}"
            puts "Length: #{packet.to_s.length}"
            puts '-' * 80
            puts "\n\n\n"
          end
        end
      rescue Interrupt
        puts "\nCTRL+C detected. Exiting..."
      rescue StandardError => e
        raise e
      ensure
        mqtt_obj.disconnect if mqtt_obj
      end

      # Supported Method Parameters::
      # mqtt_obj = PWN::Plugins::Meshtastic.gps_search(
      #   lat: 'required - latitude float (e.g. 37.7749)',
      #   lon: 'required - longitude float (e.g. -122.4194)',
      # )
      public_class_method def self.gps_search(opts = {})
        lat = opts[:lat]
        lon = opts[:lon]

        raise 'ERROR: Latitude and Longitude are required' unless lat && lon

        gps_arr = [lat.to_f, lon.to_f]

        Geocoder.search(gps_arr)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # mqtt_obj = PWN::Plugins::Meshtastic.disconnect(
      #   mqtt_obj: 'required - mqtt_obj returned from #connect method'
      # )
      public_class_method def self.disconnect(opts = {})
        mqtt_obj = opts[:mqtt_obj]

        mqtt_obj.disconnect if mqtt_obj
        nil
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
          mqtt_obj = #{self}.connect(
            host: 'optional - mqtt host (default: mqtt.meshtastic.org)',
            port: 'optional - mqtt port (defaults: 1883)',
            username: 'optional - mqtt username (default: meshdev)',
            password: 'optional - (default: large4cats)'
          )

          #{self}.subscribe(
            mqtt_obj: 'required - mqtt_obj object returned from #connect method',
            region: 'optional - region (default: US)',
            channel: 'optional - channel name (default: LongFast)',
            psk: 'optional - channel pre-shared key (default: AQ==)',
            qos: 'optional - quality of service (default: 0)'
          )

          mqtt_obj = #{self}.disconnect(
            mqtt_obj: 'required - mqtt_obj object returned from #connect method'
          )

          #{self}.authors
        "
      end
    end
  end
end
