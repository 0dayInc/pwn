# frozen_string_literal: true

require 'curses'
require 'yaml'
require 'json'
require 'base64'
require 'pry'
require 'reline'
require 'io/wait'

module PWN
  module Plugins
    module REPL
      # pwn-mesh REPL mode.
      module Mesh
        # Register Pry commands for this REPL mode.
        public_class_method def self.add_commands
          Pry::Commands.create_command 'pwn-mesh' do
            description 'Communicate with Meshtastic network within pwn REPL.'

            def process
              pi = pry_instance
              # meshtastic is a *setup-managed* gem (see pwn.gemspec / PWN::Setup):
              # its rubygems.org releases carry `required_ruby_version >= 4.0`, so
              # it cannot be a hard runtime dependency while pwn supports ruby 3.3+.
              begin
                require 'meshtastic'
              rescue LoadError => e
                output.puts "pwn-mesh unavailable: #{e.message}"
                output.puts "  meshtastic requires ruby >= 4.0 (running #{RUBY_VERSION})." if Gem::Version.new(RUBY_VERSION) < Gem::Version.new('4.0.0')
                output.puts '  Run: `pwn setup --profile full` (or `gem install meshtastic`) on ruby >= 4.0.'
                return
              end

              pi.config.pwn_mesh = true
              pi.config.pwn_ai = false
              pi.config.pwn_asm = false
              meshtastic_env = PWN::Env[:plugins][:meshtastic] || {}

              PWN.send(:remove_const, :MeshTxEchoThread) if PWN.const_defined?(:MeshTxEchoThread)
              PWN.send(:remove_const, :MqttObj) if PWN.const_defined?(:MqttObj)
              PWN.send(:remove_const, :MeshObj) if PWN.const_defined?(:MeshObj)
              PWN.send(:remove_const, :MeshRxHeaderWin) if PWN.const_defined?(:MeshRxHeaderWin)
              PWN.send(:remove_const, :MeshRxBodyWin) if PWN.const_defined?(:MeshRxBodyWin)
              PWN.send(:remove_const, :MeshTxWin) if PWN.const_defined?(:MeshTxWin)
              PWN.send(:remove_const, :MeshMutex) if PWN.const_defined?(:MeshMutex)
              PWN.send(:remove_const, :MqttSubThread) if PWN.const_defined?(:MqttSubThread)
              PWN.send(:remove_const, :MeshSubThread) if PWN.const_defined?(:MeshSubThread)
              PWN.send(:remove_const, :MeshTransport) if PWN.const_defined?(:MeshTransport)
              PWN.send(:remove_const, :MeshTxPrompt) if PWN.const_defined?(:MeshTxPrompt)
              PWN.send(:remove_const, :MeshTxEpoch) if PWN.const_defined?(:MeshTxEpoch)
              PWN.send(:remove_const, :MeshTxBlank) if PWN.const_defined?(:MeshTxBlank)
              PWN.send(:remove_const, :MeshLastSubmit) if PWN.const_defined?(:MeshLastSubmit)
              PWN.send(:remove_const, :MeshRxState) if PWN.const_defined?(:MeshRxState)

              begin
                mesh_obj = PWN::Plugins::REPL.send(:mesh_connect, env: meshtastic_env)
              rescue StandardError => e
                output.puts "pwn-mesh unavailable: #{e.class}: #{e.message}"
                pi.config.pwn_mesh = false
                return
              end
              PWN.const_set(:MeshObj, mesh_obj)
              PWN.const_set(:MqttObj, mesh_obj)

              active_channel = meshtastic_env[:channel][:active].to_s.to_sym
              channel_env = meshtastic_env[:channel][active_channel]
              psk = channel_env[:psk]
              region = channel_env[:region]
              topic = channel_env[:topic]
              channel_num = channel_env[:channel_num]
              link = PWN::Plugins::REPL.send(:mesh_link_label, env: meshtastic_env)

              # Init ncurses UI (idempotent) with separate RX (top) and TX (bottom) panes
              Curses.init_screen
              Curses.curs_set(0)
              Curses.noecho
              Curses.cbreak
              Curses.crmode
              Curses.ESCDELAY = 0
              Curses.start_color
              Curses.use_default_colors
              Curses.init_pair(20, Curses::COLOR_CYAN, -1)
              Curses.init_pair(21, Curses::COLOR_YELLOW, -1)
              Curses.init_pair(22, Curses::COLOR_BLACK, Curses::COLOR_CYAN)
              Curses.init_pair(23, Curses::COLOR_GREEN, -1)
              Curses.init_pair(24, Curses::COLOR_WHITE, -1)

              PWN.const_set(:MeshColors, [20, 23, 21])
              PWN.const_set(:MeshLastColor, 20)

              layout = PWN::Plugins::REPL.send(:mesh_layout, lines: Curses.lines, cols: Curses.cols)
              mesh_tx_rows = layout[:tx]
              mesh_header_rows = layout[:header]
              body_height = layout[:body]
              rx_header_win = Curses::Window.new(mesh_header_rows, Curses.cols, 0, 0)
              rx_header_win.scrollok(false)
              rx_header_win.nodelay = true
              PWN::Plugins::REPL.send(:mesh_box!, win: rx_header_win)
              rx_header_win.attron(Curses.color_pair(20) | Curses::A_BOLD)
              rx_header = " pwn.mesh  #{link}  #{region}/#{topic}  ch #{channel_num} "
              inner_cols = [Curses.cols - 2, 1].max
              rx_header_win.setpos(1, 1)
              rx_header_win.addstr(rx_header[0, inner_cols].to_s.ljust(inner_cols))
              rx_header_win.attroff(Curses.color_pair(20) | Curses::A_BOLD)
              rx_header_win.refresh
              PWN.const_set(:MeshRxHeaderWin, rx_header_win)

              body_start_row = mesh_header_rows
              frame = Curses::Window.new(body_height, Curses.cols, body_start_row, 0)
              PWN::Plugins::REPL.send(:mesh_box!, win: frame)
              frame.setpos(0, 2)
              frame.addstr(' CONVERSATION ')
              frame.refresh
              PWN.const_set(:MeshRxFrameWin, frame)
              rx_body_win = Curses::Window.new(
                [body_height - 2, 1].max,
                [Curses.cols - 4, 1].max,
                body_start_row + (body_height > 2 ? 1 : 0),
                Curses.cols > 4 ? 2 : 0
              )
              rx_body_win.scrollok(true)
              rx_body_win.nodelay = true
              rx_body_win.refresh
              PWN.const_set(:MeshRxBodyWin, rx_body_win)

              tx_win = Curses::Window.new(mesh_tx_rows, Curses.cols, layout[:tx_top], 0)
              tx_win.scrollok(false)
              tx_win.nodelay = true
              PWN::Plugins::REPL.send(:mesh_box!, win: tx_win)
              tx_win.refresh

              PWN.const_set(:MeshTxWin, tx_win)
              PWN.const_set(:MeshMutex, Mutex.new)

              # Curses owns input and rendering until this command returns to Pry.
              PWN.const_set(:MeshEvents, Queue.new)
              PWN::Plugins::REPL.send(:mesh_capture_output, run: proc {
                PWN::Plugins::REPL.send(:mesh_start_rx!, env: meshtastic_env, obj: mesh_obj)
                PWN::Plugins::REPL.send(:mesh_refresh_ui!, env: meshtastic_env)
                PWN::Plugins::REPL.send(:mesh_ui_puts, text: 'Ready. /menu opens settings. Incoming channel messages appear here.')
                PWN::Plugins::REPL.send(:mesh_console_loop, pry: pi)
              })
            rescue StandardError => e
              raise e
            ensure
              PWN::Plugins::REPL.leave_special_mode!(pry: pi) if pi&.config&.pwn_mesh
            end
          end
        end
        PWN_MESH_TRANSPORTS = %i[serial bluetooth tcp mqtt].freeze
        # meshtastic 0.0.184 loses protobuf defaults in Data#to_h. Empty
        # decoded data is not an unsupported application payload.
        EMPTY_DATA_DECODER = Module.new do
          define_method(:decode_payload) do |opts = {}|
            return nil if opts[:payload].nil? && opts[:msg_type].nil?

            super(opts)
          end
        end

        # Meshtastic transport for pwn-mesh: auto (probe order) or a pinned kind.
        class << PWN::Plugins::REPL # rubocop:disable Metrics/ClassLength
          def mesh_transport(opts = {})
            env = opts[:env] || {}
            name = (env[:transport] || env['transport'] || :auto).to_s.downcase.to_sym
            return :auto if name.empty? || name == :auto
            return name if PWN_MESH_TRANSPORTS.include?(name)

            :auto
          end

          # Live radio kind after connect (MeshTransport) or the pinned / first-probe kind.
          def mesh_bound_transport(opts = {})
            env = opts[:env] || {}
            if PWN.const_defined?(:MeshTransport)
              live = PWN.const_get(:MeshTransport).to_s.downcase.to_sym
              return live if PWN_MESH_TRANSPORTS.include?(live)
            end

            t = mesh_transport(env: env)
            t == :auto ? PWN_MESH_TRANSPORTS.first : t
          end

          # Row counts for header, CONVERSATION, and COMPOSE so the TUI fits the terminal.
          def mesh_layout(opts = {})
            lines = opts[:lines]
            cols = opts[:cols]
            lines = lines.nil? ? Curses.lines : Integer(lines)
            cols = cols.nil? ? Curses.cols : Integer(cols)
            lines = 1 if lines < 1
            cols = 1 if cols < 1
            header = 5
            tx = 5
            min_header = 3
            min_tx = 3
            min_body = 3
            body = lines - header - tx
            while body < min_body && header > min_header
              header -= 1
              body = lines - header - tx
            end
            while body < min_body && tx > min_tx
              tx -= 1
              body = lines - header - tx
            end
            body = [body, 1].max
            overflow = header + body + tx - lines
            body -= overflow if overflow.positive? && body > 1
            body = 1 if body < 1
            {
              header: header,
              body: body,
              tx: tx,
              cols: cols,
              tx_top: header + body
            }
          end

          # Explicit Unicode avoids ACS falling back to ASCII on some terminals.
          def mesh_box!(opts = {})
            win = opts[:win]
            width = win.maxx
            height = win.maxy
            win.setpos(0, 0)
            win.addstr("╭#{'─' * (width - 2)}╮")
            (1...(height - 1)).each do |row|
              win.setpos(row, 0)
              win.addstr('│')
              win.setpos(row, width - 1)
              win.addstr('│')
            end
            win.setpos(height - 1, 0)
            win.addstr("╰#{'─' * (width - 2)}╯")
            win
          end

          # Region is an opaque broker path and may contain multiple components.
          def mesh_mqtt_region(opts = {})
            raw = opts[:region].to_s
            if raw.empty?
              mqtt = (opts[:env] || {})[:mqtt] || {}
              raw = mqtt[:region].to_s
            end
            raw.empty? ? 'US' : raw
          end

          # Human-readable link for the pwn-mesh RX header.
          def mesh_mqtt_topic(opts = {})
            env = opts[:env] || mesh_env_hash
            active = env.dig(:channel, :active).to_s
            topic = opts[:topic].to_s
            topic = "2/e/#{active}/#" if topic.empty? && !active.empty?
            topic = topic.sub(%r{/e/#\z}, "/e/#{active}/#") unless active.empty?
            topic
          end

          def mesh_active_psks(opts = {})
            env = opts[:env] || mesh_env_hash
            active = env.dig(:channel, :active).to_s
            slot = env.dig(:channel, active.to_sym) || {}
            topic = mesh_mqtt_topic(env: env, topic: slot[:topic])
            name = topic.split('/')[-2]
            name = active if name.to_s.empty? || name == 'e'
            { name.to_sym => slot[:psk] }
          end

          def mesh_device_channel_meta(opts = {})
            obj = opts[:obj]
            return {} unless obj.is_a?(Hash)

            rows = if obj[:rx_mutex]
                     obj[:rx_mutex].synchronize { Array(obj[:proto_data]).dup }
                   else
                     Array(obj[:proto_data])
                   end
            by_index = {}
            rows.each do |row|
              ch = row.is_a?(Hash) ? (row[:channel] || row['channel']) : nil
              ch = row if ch.nil? && row.is_a?(Hash) && (row[:settings] || row['settings'])
              ch = ch.to_h if !ch.is_a?(Hash) && ch.respond_to?(:to_h)
              next unless ch.is_a?(Hash)

              role = (ch[:role] || ch['role']).to_s.downcase
              idx = (ch[:index] || ch['index'] || 0).to_i
              next unless (0..7).cover?(idx)

              # Protobuf omits the default DISABLED role from to_h.
              if role.empty? || %w[disabled 0].include?(role)
                by_index.delete(idx)
                next
              end

              settings = ch[:settings] || ch['settings'] || {}
              settings = settings.to_h if !settings.is_a?(Hash) && settings.respond_to?(:to_h)
              settings = {} unless settings.is_a?(Hash)
              by_index[idx] = {
                name: (settings[:name] || settings['name']).to_s.strip,
                psk: (settings[:psk] || settings['psk']).to_s
              }
            end
            by_index
          end

          def mesh_device_channels(opts = {})
            return {} unless opts.is_a?(Hash)

            mesh_device_channel_meta(obj: opts[:obj]).transform_values { |row| row[:name].to_s }
          end

          def mesh_radio_channel(opts = {})
            return unless opts.is_a?(Hash)

            env = opts[:env] || mesh_env_hash
            name = opts[:name].to_s
            name = env.dig(:channel, :active).to_s if name.empty?
            return if name.empty?

            mesh_radio_index_for_name(env: env, obj: opts[:obj], name: name)
          end

          def mesh_radio_index_for_name(opts = {})
            return unless opts.is_a?(Hash)

            name = opts[:name].to_s
            return if name.empty?

            env = opts[:env] || mesh_env_hash
            slot = env.dig(:channel, name.to_sym) || env.dig(:channel, name) || {}
            index = slot[:radio_index] if slot.is_a?(Hash)
            obj = opts[:obj]
            obj = PWN.const_get(:MeshObj) if obj.nil? && PWN.const_defined?(:MeshObj)
            if index.nil?
              wanted = name.downcase
              named = mesh_device_channels(obj: obj).select do |_idx, ch_name|
                n = ch_name.to_s.downcase
                n == wanted || (wanted == 'longfast' && n.empty?)
              end
              index = named.keys.max
            end
            if index.nil?
              found = mesh_unassigned_slot_map(env: env, obj: obj).find do |_i, ch_name|
                ch_name.to_s.downcase == wanted
              end
              index = found&.first
            end
            n = slot[:channel_num] if slot.is_a?(Hash)
            index = n if index.nil? && n.is_a?(Integer) && (0..7).cover?(n)
            return if index.nil?

            index = Integer(index)
            return unless (0..7).cover?(index)

            index
          end

          def mesh_channel_name_for_index(opts = {})
            return '' unless opts.is_a?(Hash)

            idx = opts[:index]
            return '' if idx.nil?

            idx = Integer(idx)
            return '' unless (0..7).cover?(idx)

            env = opts[:env] || mesh_env_hash
            obj = opts[:obj]
            obj = PWN.const_get(:MeshObj) if obj.nil? && PWN.const_defined?(:MeshObj)
            meta = mesh_device_channel_meta(obj: obj)
            name = meta.dig(idx, :name).to_s.strip
            return name unless name.empty?

            ch = env[:channel] || {}
            ch.each do |key, val|
              next if key.to_s == 'active'
              next unless val.is_a?(Hash)
              next if val[:radio_index].nil?
              return key.to_s if val[:radio_index].to_i == idx
            end
            psk_name = mesh_env_channel_name_for_psk(env: env, psk: meta.dig(idx, :psk))
            return psk_name unless psk_name.empty?

            mesh_unassigned_slot_map(env: env, obj: obj)[idx].to_s
          end

          def mesh_unassigned_slot_map(opts = {})
            return {} unless opts.is_a?(Hash)

            env = opts[:env] || mesh_env_hash
            obj = opts[:obj]
            obj = PWN.const_get(:MeshObj) if obj.nil? && PWN.const_defined?(:MeshObj)
            meta = mesh_device_channel_meta(obj: obj)
            claimed_idx = []
            claimed_names = []
            meta.each do |i, info|
              n = info[:name].to_s.strip
              next if n.empty?

              claimed_idx << i
              claimed_names << n.downcase
            end
            ch = env[:channel] || {}
            ch.each do |key, val|
              next if key.to_s == 'active'
              next unless val.is_a?(Hash)
              next if val[:radio_index].nil?

              claimed_idx << val[:radio_index].to_i
              claimed_names << key.to_s.downcase
            end
            meta.each do |i, info|
              n = mesh_env_channel_name_for_psk(env: env, psk: info[:psk])
              next if n.empty?

              claimed_idx << i
              claimed_names << n.downcase
            end
            unnamed = ([0] + meta.keys).uniq.sort - claimed_idx.uniq
            names = mesh_channel_names(env: env)
            encrypted, rest = names.partition do |n|
              mesh_channel_securely_encrypted?(env: env, channel: n)
            end
            unclaimed = (encrypted + rest).reject { |n| claimed_names.include?(n.downcase) }
            unnamed.zip(unclaimed).to_h.compact
          end

          def mesh_psk_b64(opts = {})
            raw = opts[:psk].to_s
            return '' if raw.empty?
            return raw if raw.match?(%r{\A[A-Za-z0-9+/]+=*\z}) && (raw.length % 4).zero?

            Base64.strict_encode64(raw)
          end

          def mesh_psk_same?(opts = {})
            return false unless opts.is_a?(Hash)

            left = mesh_psk_b64(psk: opts[:left])
            right = mesh_psk_b64(psk: opts[:right])
            !left.empty? && left == right
          end

          def mesh_env_channel_name_for_psk(opts = {})
            return '' unless opts.is_a?(Hash)

            psk = opts[:psk].to_s
            return '' if psk.empty?

            env = opts[:env] || mesh_env_hash
            ch = env[:channel] || {}
            found = ch.find do |key, val|
              key.to_s != 'active' && val.is_a?(Hash) && mesh_psk_same?(left: psk, right: val[:psk])
            end
            found ? found.first.to_s : ''
          end

          def mesh_whitelist_name_for_index(opts = {})
            return '' unless opts.is_a?(Hash)

            idx = opts[:index]
            return '' if idx.nil?

            idx = Integer(idx)
            return '' unless (0..7).cover?(idx)

            env = opts[:env] || mesh_env_hash
            found = Array(env[:ai_whitelist]).find do |entry|
              n = entry.to_s
              next if n.empty?

              mesh_radio_index_for_name(env: env, obj: opts[:obj], name: n) == idx
            end
            found.to_s
          end

          def mesh_channel_name_from_topic(opts = {})
            return '' unless opts.is_a?(Hash)

            topic = opts[:topic].to_s
            return '' if topic.empty?

            seg = topic.split('/').each_cons(2).find { |a, b| a == 'e' && b && b != '#' }
            seg ? seg.last.to_s : ''
          end

          def mesh_link_label(opts = {})
            env = opts[:env] || {}
            case mesh_bound_transport(env: env)
            when :serial
              (env[:serial] || {})[:port].to_s
            when :bluetooth
              (env[:bluetooth] || {})[:address].to_s
            when :tcp
              tcp = env[:tcp] || {}
              "#{tcp[:host]}:#{tcp[:port]}"
            else
              mqtt = env[:mqtt] || {}
              "#{mqtt[:host]}:#{mqtt[:port]}"
            end
          end

          # Open one Meshtastic backend (serial, bluetooth, tcp, or mqtt).
          def mesh_connect_one(opts = {})
            env = opts[:env] || {}
            case opts[:transport]
            when :serial
              serial = env[:serial] || {}
              obj = Meshtastic::Serial.connect(
                block_dev: serial[:port],
                baud: serial[:baud],
                data_bits: serial[:bits],
                stop_bits: serial[:stop],
                parity: serial[:parity]
              )
              Meshtastic::Serial.wait_for_config(serial_obj: obj, timeout: 10)
              obj
            when :bluetooth
              obj = Meshtastic::Bluetooth.connect(address: (env[:bluetooth] || {})[:address])
              Meshtastic::Bluetooth.wait_for_config(bluetooth_obj: obj, timeout: 30)
              obj
            when :tcp
              tcp = env[:tcp] || {}
              obj = Meshtastic::TCP.connect(host: tcp[:host], port: tcp[:port])
              Meshtastic::TCP.wait_for_config(tcp_obj: obj, timeout: 10)
              obj
            else
              mqtt = env[:mqtt] || {}
              kwargs = {
                host: mqtt[:host],
                port: mqtt[:port],
                tls: mesh_mqtt_tls?(tls: mqtt[:tls]),
                username: mqtt[:user],
                password: mqtt[:pass]
              }
              kwargs[:client_id] = mqtt[:client_id] unless mqtt[:client_id].to_s.empty?
              kwargs[:keep_alive] = mqtt[:keep_alive] unless mqtt[:keep_alive].nil?
              kwargs[:ack_timeout] = mqtt[:ack_timeout] unless mqtt[:ack_timeout].nil?
              Meshtastic::MQTT.connect(kwargs)
            end
          end

          # Treat only explicit true-ish values as MQTT TLS (YAML "false" is a truthy string).
          def mesh_mqtt_tls?(opts = {})
            tls = opts[:tls]
            return false if tls.nil? || tls == false

            %w[true yes 1].include?(tls.to_s.strip.downcase)
          end

          # Open a Meshtastic session. auto probes serial → bluetooth → tcp → mqtt.
          def mesh_connect(opts = {})
            env = opts[:env] || {}
            selected = mesh_transport(env: env)
            kinds = selected == :auto ? PWN_MESH_TRANSPORTS : [selected]
            errors = []
            kinds.each do |kind|
              obj = mesh_connect_one(env: env, transport: kind)
              PWN.send(:remove_const, :MeshTransport) if PWN.const_defined?(:MeshTransport)
              PWN.const_set(:MeshTransport, kind)
              return obj
            rescue StandardError => e
              errors << "#{kind}: #{e.class}: #{e.message}"
              raise unless selected == :auto
            end
            raise IOError, "pwn-mesh: no transport connected (#{errors.join('; ')})" if errors.any?

            raise IOError, 'pwn-mesh: no Meshtastic transport connected'
          end

          # Subscribe for inbound TEXT_MESSAGE_APP frames.
          def mesh_subscribe(opts = {})
            Meshtastic::MeshInterface.prepend(Mesh::EMPTY_DATA_DECODER) unless Meshtastic::MeshInterface.ancestors.include?(Mesh::EMPTY_DATA_DECODER)
            env = opts[:env] || {}
            obj = opts[:obj]
            psks = opts[:psks]
            blk = opts[:on_message]
            case mesh_bound_transport(env: env)
            when :serial
              Meshtastic::Serial.subscribe(serial_obj: obj, psks: psks, &blk)
            when :bluetooth
              Meshtastic::Bluetooth.subscribe(bluetooth_obj: obj, psks: psks, &blk)
            when :tcp
              Meshtastic::TCP.subscribe(tcp_obj: obj, psks: psks, &blk)
            else
              Meshtastic::MQTT.subscribe(
                mqtt_obj: obj,
                region: mesh_mqtt_region(region: opts[:region], env: env),
                topic: mesh_mqtt_topic(env: env, topic: opts[:topic]),
                psks: psks,
                &blk
              )
            end
          end

          # Send a text frame on the active mesh transport.
          def mesh_text_payload_max(opts = {})
            return 0 unless opts.is_a?(Hash)

            cap = opts[:max] || Meshtastic::Constants::DATA_PAYLOAD_LEN
            # DATA_PAYLOAD_LEN is the protobuf Data.payload max. A MeshPacket
            # around a full-size payload is ~260 bytes and will not fit a 256-byte
            # LoRa frame, so the radio accepts ToRadio then silently drops TX.
            lora = 256
            overhead = 32
            [cap, lora - overhead].min
          end

          def mesh_payload_fits?(opts = {})
            return false unless opts.is_a?(Hash)

            text = opts[:text].to_s
            max = opts[:max] || mesh_text_payload_max
            text.length <= max && text.bytesize <= max
          end

          def mesh_tx_row_ready?(opts = {})
            mesh_tx_outcome(opts) == :ok
          end

          def mesh_tx_outcome(opts = {})
            return :idle unless opts.is_a?(Hash)

            row = opts[:row]
            return :idle unless row.is_a?(Hash)

            packet = row[:packet] || row['packet']
            return :idle unless packet.is_a?(Hash)

            decoded = packet[:decoded] || packet['decoded']
            return :idle unless decoded.is_a?(Hash)

            port = decoded[:portnum] || decoded['portnum']
            return :idle unless %w[5 ROUTING_APP].include?(port.to_s) || port == :ROUTING_APP

            want = opts[:request_id]
            got = decoded[:request_id] || decoded['request_id']
            return :idle if want && got && want.to_i != got.to_i

            routing = decoded[:payload] || decoded['payload']
            routing = Meshtastic::Routing.decode(routing).to_h if routing.is_a?(String)
            reason = routing[:error_reason] if routing.is_a?(Hash)
            reason = Meshtastic::Routing::Error.lookup(reason) || reason if reason.is_a?(Integer)
            name = reason.to_s
            return :ok if reason.nil? || %w[0 NONE].include?(name)
            return :rate_limited if name == 'RATE_LIMIT_EXCEEDED'

            :error
          end

          def mesh_wait_tx_slot(opts = {})
            return :ok unless opts.is_a?(Hash)

            obj = opts[:obj]
            return :ok unless obj.is_a?(Hash)

            timeout = opts[:timeout]
            timeout = 8 if timeout.nil?
            timeout = Float(timeout)
            return :ok if timeout <= 0

            since = opts[:since].to_i
            deadline = Time.now + timeout
            loop do
              rows = if obj[:rx_mutex]
                       obj[:rx_mutex].synchronize { Array(obj[:proto_data]).dup }
                     else
                       Array(obj[:proto_data])
                     end
              rows.drop(since).each do |row|
                outcome = mesh_tx_outcome(row: row, request_id: opts[:request_id])
                return outcome unless outcome == :idle
              end
              return :timeout if Time.now >= deadline

              sleep 0.05
            end
          end

          def mesh_text_chunks(opts = {})
            return [] unless opts.is_a?(Hash)

            text = opts[:text].to_s
            max = mesh_text_payload_max
            return [text] if mesh_payload_fits?(text: text, max: max)

            n = 2
            loop do
              prefix = "(#{n}/#{n}) "
              body_max = max - prefix.length
              raise ArgumentError, "DATA_PAYLOAD_LEN #{max} cannot hold a chunk prefix" if body_max < 1

              bodies = []
              offset = 0
              while offset < text.length
                take = body_max
                piece = text[offset, take].to_s
                while !mesh_payload_fits?(text: "#{prefix}#{piece}", max: max) && take > 1
                  take -= 1
                  piece = text[offset, take].to_s
                end
                bodies << piece
                offset += piece.length
                next unless offset < text.length && piece.match?(/[^[:space:]]\z/)

                cut = piece.rindex(/[[:space:]]/)
                next unless cut&.positive?

                bodies[-1] = piece[0, cut + 1]
                offset = offset - piece.length + bodies[-1].length
              end
              if bodies.size <= n
                total = bodies.size
                return bodies.each_with_index.map { |body, i| "(#{i + 1}/#{total}) #{body}" }
              end
              n = bodies.size
            end
          end

          def mesh_node_user(opts = {})
            obj = opts[:obj]
            return unless obj.is_a?(Hash)

            rows = obj[:rx_mutex] ? obj[:rx_mutex].synchronize { Array(obj[:proto_data]).dup } : Array(obj[:proto_data]).dup
            user = nil
            rows.each do |row|
              next unless row.is_a?(Hash)

              info = row[:node_info] || row[:nodeInfo]
              user = info[:user] if info.is_a?(Hash) && info[:num] == opts[:num]
              packet = row[:packet]
              next unless packet.is_a?(Hash) && packet[:from] == opts[:num]

              data = packet[:decoded]
              next unless data.is_a?(Hash) && %w[4 NODEINFO_APP].include?(data[:portnum].to_s)

              payload = data[:payload]
              user = payload.is_a?(String) ? Meshtastic::User.decode(payload).to_h : payload
            end
            user if user.is_a?(Hash)
          end

          def mesh_dm_key(opts = {})
            kind = opts[:kind]
            raise IOError, 'MQTT PKI DMs are unsupported; message remains unsent. Use a device transport.' if kind == :mqtt

            obj = opts[:obj]
            raise IOError, 'No connected radio; message remains unsent.' unless obj.is_a?(Hash)

            num = opts[:to].delete_prefix('!').to_i(16)
            user = mesh_node_user(obj: obj, num: num)
            return user[:public_key] if user && user[:public_key].to_s.bytesize == 32

            own = mesh_node_user(obj: obj, num: obj[:my_node_num])
            raise IOError, 'Local radio public key unavailable; reconnect to refresh NodeInfo. Message remains unsent.' unless own && own[:public_key].to_s.bytesize == 32

            timeout = Float(opts.fetch(:timeout, 15))
            raise ArgumentError, 'key timeout must be between 0 and 60 seconds' unless timeout.finite? && (0..60).cover?(timeout)

            mesh_ui_puts(text: "Discovering public key for #{opts[:to]} (up to #{timeout}s); DM text is held locally.")
            data = Meshtastic::Data.new(portnum: :NODEINFO_APP, payload: Meshtastic::User.new(own).to_proto, want_response: true)
            transport = { serial: Meshtastic::Serial, bluetooth: Meshtastic::Bluetooth, tcp: Meshtastic::TCP }.fetch(kind)
            transport.send_data({ "#{kind}_obj": obj, to: opts[:to], channel: opts[:radio] || 0,
                                  data: data, port_num: Meshtastic::PortNum::NODEINFO_APP, want_ack: true })
            deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
            loop do
              user = mesh_node_user(obj: obj, num: num)
              return user[:public_key] if user && user[:public_key].to_s.bytesize == 32

              break if obj[:closing] || Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

              sleep 0.05
            end
            raise IOError, 'Destination public key discovery timed out; message remains unsent. Retry with /msg.'
          end

          private :mesh_node_user, :mesh_dm_key

          def mesh_send_text(opts = {})
            env = opts[:env] || {}
            obj = opts[:obj]
            from = opts[:from]
            channel = opts[:channel]
            psks = opts[:psks]
            dest = opts[:to].to_s
            dest = '!ffffffff' if dest.empty?
            kind = mesh_bound_transport(env: env)
            channel_name = opts[:channel_name].to_s
            radio = opts[:radio]
            radio = mesh_radio_index_for_name(env: env, obj: obj, name: channel_name) if radio.nil? && !channel_name.empty?
            radio = mesh_radio_channel(env: env, obj: obj) if radio.nil? && %i[serial bluetooth tcp].include?(kind)
            dm_key = nil
            unless mesh_broadcast?(to: dest)
              raise ArgumentError, 'DM destination must be ! followed by eight hex digits' unless dest.match?(/\A![0-9a-fA-F]{8}\z/)

              PWN.send(:remove_const, :MeshPendingDm) if PWN.const_defined?(:MeshPendingDm)
              PWN.const_set(:MeshPendingDm, { to: dest, text: opts[:text].to_s, channel_name: channel_name })
              dm_key = mesh_dm_key(obj: obj, kind: kind, to: dest, radio: radio, timeout: opts.fetch(:key_timeout, 15))
            end
            chunks = mesh_text_chunks(text: opts[:text])
            chunks.each_with_index do |piece, _idx|
              echoed = false
              attempts = 0
              loop do
                attempts += 1
                packet_id = Random.rand(2...0xffffffff)
                since = obj.is_a?(Hash) ? Array(obj[:proto_data]).size : 0
                if dm_key
                  bytes = Meshtastic::MeshInterface.new.send_text(from: obj[:my_node_num] || 0, to: dest, channel: radio || 0, text: piece, want_ack: true, psks: nil, last_packet_id: packet_id - 1)
                  packet = Meshtastic::ToRadio.decode(bytes)
                  packet.packet.pki_encrypted = true
                  packet.packet.public_key = dm_key
                  transport = { serial: Meshtastic::Serial, bluetooth: Meshtastic::Bluetooth, tcp: Meshtastic::TCP }.fetch(kind)
                  transport.send_to_radio({ "#{kind}_obj": obj, to_radio: packet.to_proto })
                else
                  case kind
                  when :serial
                    tx = { serial_obj: obj, to: dest, text: piece, want_ack: true, last_packet_id: packet_id - 1 }
                    tx[:channel] = radio unless radio.nil?
                    Meshtastic::Serial.send_text(tx)
                  when :bluetooth
                    tx = { bluetooth_obj: obj, to: dest, text: piece, want_ack: true, last_packet_id: packet_id - 1 }
                    tx[:channel] = radio unless radio.nil?
                    Meshtastic::Bluetooth.send_text(tx)
                  when :tcp
                    tx = { tcp_obj: obj, to: dest, text: piece, want_ack: true, last_packet_id: packet_id - 1 }
                    tx[:channel] = radio unless radio.nil?
                    Meshtastic::TCP.send_text(tx)
                  else
                    send_psks = psks
                    send_psks = mesh_channel_psks(env: env) if send_psks.nil? || send_psks.empty?
                    Meshtastic::MQTT.send_text(
                      mqtt_obj: obj,
                      last_packet_id: packet_id - 1,
                      from: from,
                      to: dest,
                      region: mesh_mqtt_region(region: opts[:region], env: env),
                      topic: mesh_mqtt_topic(env: env, topic: opts[:topic]),
                      channel: channel,
                      text: piece,
                      psks: send_psks
                    )
                  end
                end
                unless echoed
                  from_id = from.to_s
                  from_id = mesh_self_node_id(env: env, obj: obj) if from_id.empty?
                  from_id = mesh_format_node_id(id: from_id)
                  PWN.send(:remove_const, :MeshLastTx) if PWN.const_defined?(:MeshLastTx)
                  PWN.const_set(:MeshLastTx, { from: from_id, to: dest, text: piece.to_s, at: Time.now })
                  mesh_handle_rx(
                    local: true,
                    channel_name: channel_name,
                    msg: {
                      packet: {
                        id: packet_id,
                        channel: radio,
                        pki_encrypted: !dm_key.nil?,
                        node_id_from: from_id,
                        node_id_to: dest,
                        decoded: { portnum: :TEXT_MESSAGE_APP, payload: piece.to_s }
                      }
                    }
                  )
                  echoed = true
                end
                break unless %i[serial bluetooth tcp].include?(kind)

                slot = mesh_wait_tx_slot(obj: obj, since: since, request_id: packet_id)
                break if slot == :ok || slot == :timeout || slot == :error || attempts >= 8
              end
            end
            return unless dm_key && PWN.const_defined?(:MeshPendingDm)

            PWN.send(:remove_const, :MeshPendingDm)
            PWN.const_set(:MeshPendingDm, nil)
          end

          # Close the Meshtastic session opened by #mesh_connect.
          def mesh_disconnect(opts = {})
            env = opts[:env] || {}
            obj = opts[:obj]
            return if obj.nil?

            case mesh_bound_transport(env: env)
            when :serial
              Meshtastic::Serial.disconnect(serial_obj: obj)
            when :bluetooth
              Meshtastic::Bluetooth.disconnect(bluetooth_obj: obj)
            when :tcp
              Meshtastic::TCP.disconnect(tcp_obj: obj)
            else
              Meshtastic::MQTT.disconnect(mqtt_obj: obj)
            end
          end

          # Send compose text on the active channel, or a @!nodeid DM.
          def mesh_compose_send(opts = {})
            env = opts[:env] || mesh_env_hash
            obj = opts[:obj]
            tx_text = opts[:text].to_s.dup
            to = '!ffffffff'
            if tx_text.include?('@!')
              to_raw = tx_text.split('@').last.chomp[0..8]
              to = to_raw if to_raw[1..].match?(/^[a-fA-F0-9]{8}$/)
              tx_text.gsub!("@#{to_raw}", '').strip!
            end
            channel_name = (env[:channel] || {})[:active].to_s
            raise ArgumentError, 'use /msg <channel|!nodeid> <text> or /channel <name>' if to == '!ffffffff' && channel_name.empty?

            slot = (env[:channel] || {})[channel_name.to_sym] || {}
            mesh_send_text(
              env: env,
              obj: obj,
              from: mesh_self_node_id(env: env, obj: obj),
              to: to,
              region: slot[:region],
              topic: slot[:topic],
              channel: slot[:channel_num] || channel_name,
              channel_name: channel_name,
              radio: mesh_radio_index_for_name(env: env, obj: obj, name: channel_name),
              text: tx_text,
              psks: mesh_channel_psks(env: env)
            )
          end

          # Named Meshtastic channel keys from plugins.meshtastic.channel (not :active).
          def mesh_channel_names(opts = {})
            env = opts[:env] || mesh_env_hash
            ch = env[:channel] || {}
            ch.keys.map(&:to_s).reject { |k| k == 'active' }
          end

          def mesh_env_hash(opts = {})
            return {} unless opts.is_a?(Hash)

            env = opts[:env]
            return env if env.is_a?(Hash)
            return {} unless defined?(PWN::Env) && PWN::Env.is_a?(Hash)

            PWN::Env.dig(:plugins, :meshtastic) || {}
          end

          def mesh_submit(opts = {})
            request = opts[:request].to_s.dup
            return if request.empty?

            request = '/back' if request == 'back'
            if request.start_with?('/') && !PWN_MESH_SLASH_COMMANDS.include?(request.split.first) && request != '/'
              mesh_ui_puts(text: 'Unknown command. Use /help or /menu.')
              return
            end
            Pry.config.hooks.get_hook(:after_read, :pwn_mesh_hook).call(request, opts[:pry])
          rescue StandardError => e
            mesh_ui_puts(text: "Command failed: #{e.class}: #{e.message}")
          end

          # Workers enqueue RX; curses alone owns terminal input and drawing.
          def mesh_console_loop(opts = {})
            pi = opts[:pry]
            reader = opts[:getch]
            unless reader
              PWN::MeshTxWin.keypad(true)
              PWN::MeshTxWin.timeout = 100
              reader = proc { PWN::MeshTxWin.getch }
            end
            text = +''
            cursor = 0
            history = []
            history_index = 0
            draft = +''
            draft_cursor = 0
            while pi.config.pwn_mesh
              mesh_drain_events
              mesh_draw_input(text: text, cursor: cursor)
              key = reader.call
              case key
              when "\u0004", 4
                break if text.empty?
              when "\n", "\r", 10, 13, Curses::KEY_ENTER
                submitted = text.dup
                unless submitted.strip.empty? || history.last == submitted
                  history << submitted.dup
                  history.shift if history.length > 100
                end
                history_index = history.length
                draft = +''
                draft_cursor = 0
                text.clear
                cursor = 0
                mesh_draw_input(text: text, cursor: cursor)
                mesh_submit(request: submitted, pry: pi)
              when Curses::KEY_UP
                next if history.empty? || history_index.zero?

                if history_index == history.length
                  draft = text.dup
                  draft_cursor = cursor
                end
                history_index -= 1
                text = history[history_index].dup
                cursor = text.length
              when Curses::KEY_DOWN
                next if history_index >= history.length

                history_index += 1
                text = history_index == history.length ? draft.dup : history[history_index].dup
                cursor = history_index == history.length ? draft_cursor : text.length
              when "\u007f", "\b", 127, 8, Curses::KEY_BACKSPACE
                if cursor.positive?
                  cursor -= 1
                  text.slice!(cursor)
                end
              when Curses::KEY_DC
                text.slice!(cursor)
              when Curses::KEY_LEFT
                cursor = [cursor - 1, 0].max
              when Curses::KEY_RIGHT
                cursor = [cursor + 1, text.length].min
              when Curses::KEY_HOME, "\u0001"
                cursor = 0
              when Curses::KEY_END, "\u0005"
                cursor = text.length
              when "\u0015"
                text.clear
                cursor = 0
              when "\t", 9
                hits = pwn_mesh_menu_rows(line: text)
                choice = mesh_menu_pick(title: 'Commands', items: hits) unless hits.empty?
                if choice
                  text = text.include?(' ') ? "#{text.split.first} #{choice}" : choice.dup
                  cursor = text.length
                end
              else
                if key.is_a?(String) && key.ord >= 32
                  text.insert(cursor, key)
                  cursor += key.length
                end
              end
            end
          rescue Interrupt
            nil
          end

          def mesh_drain_events
            return unless PWN.const_defined?(:MeshEvents)

            loop do
              event = PWN::MeshEvents.pop(true)
              next if event[:obj] && (!PWN.const_defined?(:MeshObj) || !event[:obj].equal?(PWN::MeshObj))

              if event[:notice]
                notice = mesh_notice_text(text: event[:notice])
                mesh_notice(text: notice) if notice
              elsif event[:msg]
                mesh_handle_rx(msg: event[:msg])
              else
                mesh_ui_puts(text: event[:text])
              end
            end
          rescue ThreadError
            nil
          end

          def mesh_draw_input(opts = {})
            win = PWN::MeshTxWin
            text = opts[:text].to_s
            cursor = opts[:cursor].to_i
            width = [win.maxx - 6, 1].max
            offset = [cursor - width + 1, 0].max
            win.erase
            mesh_box!(win: win)
            win.attron(Curses.color_pair(20) | Curses::A_BOLD) do
              win.setpos(0, 2)
              win.addstr(' COMPOSE ')
              win.setpos(1, 2)
              win.addstr('› ')
            end
            win.setpos(1, 4)
            win.addstr(text[offset, width].to_s)
            win.setpos(1, 4 + cursor - offset)
            win.attron(Curses::A_REVERSE) { win.addstr(text[cursor] || ' ') }
            hits = pwn_mesh_menu_rows(line: text)
            unless hits.empty?
              win.setpos(2, 2)
              win.attron(Curses.color_pair(20)) do
                win.addstr(hits.join('  ')[0, win.maxx - 4].to_s)
              end
            end
            win.setpos(3, 2)
            win.addstr('Enter send   Up/Down history   Tab complete   /menu settings   Ctrl+D back'[0, win.maxx - 4])
            win.refresh
          end

          # Print slash-menu text into the RX pane when curses is up, else STDOUT.
          def mesh_wrap_text(opts = {})
            width = [opts[:width].to_i, 1].max
            opts[:text].to_s.split("\n", -1).flat_map do |line|
              rows = [+'']
              cells = 0
              line.each_char do |char|
                size = Unicode::DisplayWidth.of(char)
                if cells + size > width && !rows.last.empty?
                  rows << +''
                  cells = 0
                end
                rows.last << char
                cells += size
              end
              rows
            end
          end

          def mesh_ui_puts(opts = {})
            text = opts[:text].to_s
            if PWN.const_defined?(:MeshEvents) && text.match?(/warning|error|failed|disconnect|persist skipped|unknown command/i)
              PWN::MeshEvents << { notice: text }
              return text
            end
            if PWN.const_defined?(:MeshRxBodyWin) && PWN.const_defined?(:MeshMutex)
              win = PWN.const_get(:MeshRxBodyWin)
              mutex = PWN.const_get(:MeshMutex)
              mutex.synchronize do
                width = [win.maxx - 1, 1].max
                win.attron(Curses.color_pair(20) | Curses::A_BOLD)
                win.addstr("  SYSTEM\n")
                win.attroff(Curses.color_pair(20) | Curses::A_BOLD)
                mesh_wrap_text(text: text, width: width - 2).each do |line|
                  win.addstr("  #{line}\n")
                end
                win.addstr("\n")
                win.refresh
              end
            else
              puts text
            end
            text
          end

          def mesh_notice_text(opts = {})
            text = opts[:text].to_s.dup.force_encoding(Encoding::UTF_8).scrub
            text.gsub!(/\e\[[0-9;?]*[A-Za-z]/, '')
            text.gsub!(/[\x00-\x08\x0b\x0c\x0e-\x1f]/, '')
            text.strip!
            text.empty? ? nil : text
          end

          def mesh_capture_output(opts = {})
            original_out = $stdout
            original_err = $stderr
            input, output = IO.pipe
            output.sync = true
            events = PWN::MeshEvents
            collector = Thread.new do
              loop do
                text = input.readpartial(4096)
                begin
                  text << input.readpartial(4096) while text.bytesize < 16_384 && input.wait_readable(0.02)
                rescue EOFError
                  # Flush the last diagnostic even when the TUI is closing.
                end
                notice = mesh_notice_text(text: text)
                events << { notice: notice } if notice
              end
            rescue IOError
              nil
            end
            $stdout = output
            $stderr = output
            opts[:run].call
          ensure
            $stdout = original_out
            $stderr = original_err
            output&.close
            collector&.join(1)
            collector&.kill
            input&.close
          end

          def mesh_notice(opts = {})
            width = [Curses.cols - 2, 80].min
            lines = mesh_wrap_text(text: opts[:text].to_s, width: [width - 4, 1].max)
            height = [lines.size + 5, Curses.lines - 2].min
            win = Curses::Window.new(height, width, (Curses.lines - height) / 2, (Curses.cols - width) / 2)
            win.keypad(true)
            offset = 0
            loop do
              win.erase
              mesh_box!(win: win)
              win.setpos(0, 2)
              win.attron(Curses.color_pair(20) | Curses::A_BOLD)
              win.addstr(' NOTICE ')
              win.attroff(Curses.color_pair(20) | Curses::A_BOLD)
              lines.drop(offset).first([height - 4, 1].max).each_with_index do |line, index|
                win.setpos(index + 1, 2)
                win.addstr(line)
              end
              win.setpos(height - 2, (width - 2) / 2)
              win.attron(Curses.color_pair(20) | Curses::A_BOLD | Curses::A_REVERSE)
              win.addstr('Ok')
              win.attroff(Curses.color_pair(20) | Curses::A_BOLD | Curses::A_REVERSE)
              win.refresh
              key = opts[:getch] ? opts[:getch].call : win.getch
              break if [10, 13, "\n", "\r", Curses::KEY_ENTER].include?(key)

              offset = [offset - 1, 0].max if key == Curses::KEY_UP
              offset += 1 if key == Curses::KEY_DOWN && offset < lines.size - (height - 4)
            end
          ensure
            win&.close
            %i[MeshRxHeaderWin MeshRxFrameWin MeshRxBodyWin MeshTxWin].each do |name|
              next unless PWN.const_defined?(name)

              pane = PWN.const_get(name)
              pane.touch
              pane.refresh
            end
          end

          private :mesh_capture_output, :mesh_notice, :mesh_notice_text

          # Drop the submitted TX buffer so the next prompt is empty (Reline keeps the old line).
          def mesh_reset_input!(opts = {})
            return opts if PWN.const_defined?(:MeshEvents)

            pry = opts[:pry]
            input = pry.respond_to?(:input) ? pry.input : nil
            submitted = opts[:submitted].to_s
            submitted = Reline.line_buffer.to_s if submitted.empty? && defined?(Reline) && Reline.respond_to?(:line_buffer)
            submitted = input.line_buffer.to_s if submitted.empty? && input.respond_to?(:line_buffer)
            PWN.send(:remove_const, :MeshLastSubmit) if PWN.const_defined?(:MeshLastSubmit)
            PWN.const_set(:MeshLastSubmit, submitted)
            PWN.send(:remove_const, :MeshTxBlank) if PWN.const_defined?(:MeshTxBlank)
            PWN.const_set(:MeshTxBlank, true)
            if defined?(Reline)
              begin
                Reline.delete_text if Reline.respond_to?(:delete_text)
                Reline.point = 0 if Reline.respond_to?(:point=)
              rescue StandardError
                nil
              end
            end
            input.instance_variable_set(:@line_buffer, '') if input.respond_to?(:instance_variable_defined?) && input.instance_variable_defined?(:@line_buffer)
            if PWN.const_defined?(:MeshTxEpoch)
              epoch = PWN.const_get(:MeshTxEpoch).to_i
              PWN.send(:remove_const, :MeshTxEpoch)
              PWN.const_set(:MeshTxEpoch, epoch + 1)
            end
            opts
          end

          # Curses (or injected getch) picker for pwn-mesh lists. Esc/q cancels.
          def mesh_menu_pick(opts = {})
            items = Array(opts[:items]).map(&:to_s)
            title = opts[:title].to_s
            return nil if items.empty?

            current = opts[:current].to_s
            idx = items.index(current) || 0
            reader = opts[:getch]
            live = reader.nil? && PWN.const_defined?(:MeshTxWin)
            unless live || reader
              marked = items.map { |item| item == current ? "  * #{item}" : "    #{item}" }
              mesh_ui_puts(text: ([title.empty? ? 'pwn-mesh' : title] + marked).join("\n"))
              return nil
            end

            win = nil
            if live
              PWN.send(:remove_const, :MeshMenuLock) if PWN.const_defined?(:MeshMenuLock)
              PWN.const_set(:MeshMenuLock, true)
              max_h = [Curses.lines - 2, 6].max
              h = (items.length + 6).clamp(6, max_h)
              max_w = [Curses.cols - 2, 24].max
              label_w = [items.map(&:length).max.to_i + 8, title.length + 8, 44].max
              w = [label_w, max_w].min
              top = [(Curses.lines - h) / 2, 0].max
              left = [(Curses.cols - w) / 2, 0].max
              win = Curses::Window.new(h, w, top, left)
              win.keypad(true)
            end

            up = defined?(Curses::KEY_UP) ? Curses::KEY_UP : 259
            down = defined?(Curses::KEY_DOWN) ? Curses::KEY_DOWN : 258
            loop do
              if win
                mutex = PWN.const_defined?(:MeshMutex) ? PWN.const_get(:MeshMutex) : Mutex.new
                mutex.synchronize do
                  win.clear
                  mesh_box!(win: win)
                  inner = [win.maxx - 2, 1].max
                  win.attron(Curses.color_pair(20) | Curses::A_BOLD)
                  win.setpos(1, 2)
                  win.addstr(title.upcase[0, inner - 2])
                  win.attroff(Curses.color_pair(20) | Curses::A_BOLD)
                  visible = [win.maxy - 5, 1].max
                  first = [idx - visible + 1, 0].max
                  items.each_with_index.drop(first).first(visible).each do |item, i|
                    row = i - first + 3

                    win.setpos(row, 1)
                    mark = i == idx ? '▸' : ' '
                    line = "#{mark} #{item}"
                    if i == idx
                      win.attron(Curses.color_pair(22) | Curses::A_BOLD)
                      win.addstr(line[0, inner].to_s.ljust(inner))
                      win.attroff(Curses.color_pair(22) | Curses::A_BOLD)
                    else
                      win.addstr(line[0, inner].to_s.ljust(inner))
                    end
                  end
                  win.setpos(win.maxy - 2, 2)
                  win.addstr('↑↓ select   Enter apply   Esc close'[0, inner - 2])
                  win.refresh
                end
              end

              ch = reader ? reader.call : win.getch
              return nil if ch.nil?

              case ch
              when up, 'k', 'K'
                idx = (idx - 1) % items.length
              when down, 'j', 'J'
                idx = (idx + 1) % items.length
              when 10, 13, "\n", "\r"
                return items[idx]
              when 27, "\e", 'q', 'Q'
                return nil
              else
                enter = defined?(Curses::KEY_ENTER) ? Curses::KEY_ENTER : -1
                return items[idx] if ch == enter
              end
            end
          ensure
            win&.close
            PWN.send(:remove_const, :MeshMenuLock) if PWN.const_defined?(:MeshMenuLock)
            if live
              [PWN::MeshRxHeaderWin, PWN::MeshRxFrameWin, PWN::MeshRxBodyWin, PWN::MeshTxWin].each do |pane|
                pane.touch
                pane.refresh
              end
            end
            if PWN.const_defined?(:MeshTxEpoch)
              epoch = PWN.const_get(:MeshTxEpoch).to_i
              PWN.send(:remove_const, :MeshTxEpoch)
              PWN.const_set(:MeshTxEpoch, epoch + 1)
            end
          end

          def mesh_menu_root(opts = {})
            pi = opts[:pry]
            choice = mesh_menu_pick(
              title: 'pwn-mesh',
              items: %w[channel transport device status toggle-dispatch-to-pwn-ai help back],
              current: 'channel'
            )
            return nil if choice.nil?

            pwn_mesh_dispatch_slash!(request: "/#{choice}", pry: pi)
          end

          # Discover radios for the active transport (serial globs, BLE scan, tcp/mqtt config).
          def mesh_list_devices(opts = {})
            env = opts[:env] || mesh_env_hash
            case mesh_bound_transport(env: env)
            when :serial
              Dir.glob(
                %w[/dev/ttyUSB* /dev/ttyACM* /dev/cu.usbserial* /dev/cu.usbmodem* /dev/serial/by-id/*]
              ).uniq.sort
            when :bluetooth
              begin
                require 'meshtastic' unless defined?(Meshtastic) && Meshtastic.const_defined?(:Bluetooth)
                Array(Meshtastic::Bluetooth.scan(timeout: opts[:timeout] || 3)).map do |row|
                  if row.is_a?(Hash)
                    addr = row[:address] || row['address']
                    name = row[:name] || row['name']
                    paired = row[:paired] || row['paired']
                    [addr, name, paired ? 'paired' : nil].compact.join(' ')
                  else
                    row.to_s
                  end
                end
              rescue StandardError => e
                ["(bluetooth scan failed: #{e.class}: #{e.message})"]
              end
            when :tcp
              tcp = env[:tcp] || {}
              ["#{tcp[:host]}:#{tcp[:port]}"]
            else
              mqtt = env[:mqtt] || {}
              ["#{mqtt[:host]}:#{mqtt[:port]}"]
            end
          end

          # Subscribe thread for TEXT_MESSAGE_APP frames (also used after /channel|/transport|/device).
          def mesh_start_rx!(opts = {})
            env = opts[:env] || mesh_env_hash
            obj = opts[:obj]
            ch = env[:channel] || {}
            active = ch[:active].to_s.to_sym
            slot = ch[active] || {}
            psks = mesh_channel_psks(env: env)
            psks = mesh_active_psks(env: env) if psks.empty?
            PWN.const_set(:MeshRxState, { last_from: nil, last_line: nil }) unless PWN.const_defined?(:MeshRxState)
            events = PWN.const_defined?(:MeshEvents) ? PWN::MeshEvents : Queue.new
            kind = mesh_bound_transport(env: env)
            interval = Float(opts.fetch(:heartbeat_interval, 30))
            raise ArgumentError, 'heartbeat interval must be positive and finite' unless interval.positive? && interval.finite?

            thread = Thread.new do
              heartbeat = if obj.is_a?(Hash) && %i[serial bluetooth tcp].include?(kind)
                            Thread.new do
                              transport = { serial: Meshtastic::Serial, bluetooth: Meshtastic::Bluetooth, tcp: Meshtastic::TCP }.fetch(kind)
                              bytes = Meshtastic::ToRadio.new(heartbeat: Meshtastic::Heartbeat.new(nonce: 0)).to_proto
                              loop do
                                break if obj[:closing]

                                transport.send_to_radio({ "#{kind}_obj": obj, to_radio: bytes })
                                sleep interval
                              end
                            rescue StandardError => e
                              events << { text: "RX keepalive failed: #{e.class}: #{e.message}", obj: obj }
                            end
                          end
              mesh_subscribe(
                env: env,
                obj: obj,
                region: slot[:region],
                topic: slot[:topic],
                psks: psks,
                on_message: proc { |msg| events << { msg: msg, obj: obj } }
              )
              events << { text: 'RX stopped: transport stream closed. Use /transport to reconnect.', obj: obj }
            rescue StandardError => e
              events << { text: "RX failed: #{e.class}: #{e.message}", obj: obj }
            ensure
              heartbeat&.kill
              heartbeat&.join
            end
            PWN.send(:remove_const, :MeshSubThread) if PWN.const_defined?(:MeshSubThread)
            PWN.const_set(:MeshSubThread, thread)
          end

          def mesh_channel_psks(opts = {})
            return {} unless opts.is_a?(Hash)

            env = opts[:env] || mesh_env_hash
            ch = env[:channel] || {}
            psks = {}
            ch.each do |key, val|
              next if key.to_s == 'active'
              next unless val.is_a?(Hash)

              psk = val[:psk].to_s
              psks[key.to_s.to_sym] = psk unless psk.empty?
            end
            psks
          end

          def mesh_text_app?(opts = {})
            return false unless opts.is_a?(Hash)

            port = opts[:portnum]
            s = port.to_s
            %w[TEXT_MESSAGE_APP 1].include?(s)
          end

          def mesh_rx_text(opts = {})
            return '' unless opts.is_a?(Hash)

            payload = opts[:payload]
            return payload.dup.force_encoding(Encoding::UTF_8).scrub if payload.is_a?(String)
            return payload[:text].to_s if payload.is_a?(Hash) && payload[:text]

            ''
          end

          def mesh_format_node_id(opts = {})
            id = opts[:id]
            return format('!%08x', id) if id.is_a?(Integer) && (0..0xffffffff).cover?(id)

            text = id.to_s
            return text unless text.match?(/\A![0-9a-fA-F]{1,8}\z/)

            format('!%08x', text.delete_prefix('!').to_i(16))
          end

          private :mesh_format_node_id

          def mesh_self_node_id(opts = {})
            return '!00000b0b' unless opts.is_a?(Hash)

            obj = opts[:obj]
            obj = PWN.const_get(:MeshObj) if obj.nil? && PWN.const_defined?(:MeshObj)
            return mesh_format_node_id(id: obj[:my_node_num].to_i) if obj.is_a?(Hash) && !obj[:my_node_num].nil?

            '!00000b0b'
          end

          def mesh_decorate_local_id(opts = {})
            return '' unless opts.is_a?(Hash)

            id = mesh_format_node_id(id: opts[:id])
            return id if id.empty?

            self_id = mesh_self_node_id(env: opts[:env], obj: opts[:obj])
            return "#{id} (ME)" if id.downcase == self_id.downcase

            id
          end

          def mesh_public_psk?(opts = {})
            return true unless opts.is_a?(Hash)

            psk = opts[:psk].to_s.strip
            psk.empty? || %w[none default aq==].include?(psk.downcase) || psk == '1PG7OiApB1nwvP+rz05pAQ=='
          end

          def mesh_channel_securely_encrypted?(opts = {})
            return false unless opts.is_a?(Hash)

            env = opts[:env] || mesh_env_hash
            name = opts[:channel].to_s
            return false if name.empty?

            slot = env.dig(:channel, name.to_sym)
            slot = env[:channel][name] if slot.nil? && env[:channel].is_a?(Hash)
            return false unless slot.is_a?(Hash)

            !mesh_public_psk?(psk: slot[:psk])
          end

          def mesh_ai_whitelisted?(opts = {})
            return false unless opts.is_a?(Hash)

            env = opts[:env] || mesh_env_hash
            name = opts[:channel].to_s
            return false if name.empty?

            Array(env[:ai_whitelist]).any? { |entry| entry.to_s.casecmp?(name) }
          end

          def mesh_ai_prompt(opts = {})
            return unless opts.is_a?(Hash)

            text = opts[:text].to_s.strip
            return unless text.match?(/\A@ai(\s|\z)/i)

            text.sub(/\A@ai\s*/i, '').strip
          end

          def mesh_broadcast?(opts = {})
            to = opts[:to].to_s.downcase.delete('!')
            to.empty? || to == 'ffffffff'
          end

          def mesh_reply_target_label(opts = {})
            to = opts[:to].to_s
            return to unless mesh_broadcast?(to: to)

            opts[:channel_name].to_s
          end

          def mesh_conversation_path(opts = {})
            env = opts[:env] || mesh_env_hash
            name = opts[:channel_name].to_s
            topic = opts[:topic].to_s.sub(%r{\Amsh/}, '')
            base = topic[%r{\A(.+/2/[ec]/[^/]+)(?:/[^/]+)?\z}, 1]
            return base if base
            return '' if name.empty?

            slot = env.dig(:channel, name.to_sym) || env.dig(:channel, name) || {}
            topic = slot[:topic].to_s
            topic = "2/e/#{name}/#" if topic.empty?
            topic = topic.sub(%r{/e/#\z}, "/e/#{name}/#").sub(%r{/(?:#|![0-9a-fA-F]{8})\z}, '')
            region = mesh_mqtt_region(env: env)
            topic.start_with?("#{region}/") ? topic : "#{region}/#{topic}"
          end

          private :mesh_conversation_path

          def mesh_handle_rx(opts = {})
            return unless opts.is_a?(Hash)

            msg = opts[:msg]
            return unless msg.is_a?(Hash)

            packet = msg[:packet].is_a?(Hash) ? msg[:packet] : msg
            decoded = packet[:decoded]
            return unless decoded.is_a?(Hash)

            if %w[5 ROUTING_APP].include?(decoded[:portnum].to_s)
              routing = decoded[:payload]
              routing = Meshtastic::Routing.decode(routing).to_h if routing.is_a?(String)
              reason = routing[:error_reason] if routing.is_a?(Hash)
              reason = Meshtastic::Routing::Error.lookup(reason) || reason if reason.is_a?(Integer)
              mesh_ui_puts(text: "TX failed: packet #{decoded[:request_id]}: #{reason}") if reason && !%w[0 NONE RATE_LIMIT_EXCEEDED].include?(reason.to_s)
              return
            end
            return unless mesh_text_app?(portnum: decoded[:portnum])

            env = mesh_env_hash
            idx = packet[:channel] || packet['channel']
            idx = nil unless idx.nil? || idx.is_a?(Integer) || (idx.is_a?(String) && idx.match?(/\A[0-7]\z/))
            idx = 0 if idx.nil? && %i[serial bluetooth tcp].include?(mesh_bound_transport(env: env))
            idx = idx.to_i unless idx.nil?
            channel_name = opts[:channel_name].to_s
            channel_name = mesh_channel_name_for_index(index: idx, env: env) if channel_name.empty?
            if channel_name.empty?
              topic = msg[:topic] || packet[:topic]
              channel_name = mesh_channel_name_from_topic(topic: topic)
            end
            channel_name = mesh_whitelist_name_for_index(env: env, index: idx) if channel_name.empty? && !idx.nil?

            rx_text = mesh_rx_text(payload: decoded[:payload]).to_s
            return if rx_text.strip.empty?

            from_id = packet[:node_id_from].to_s
            from_id = packet[:from] if from_id.empty? && packet[:from]
            from_id = mesh_format_node_id(id: from_id)
            to = packet[:node_id_to].to_s
            to = packet[:to] if to.empty? && packet[:to]
            to = mesh_format_node_id(id: to)
            display_text = mesh_reaction_text(packet: packet, text: rx_text, from: from_id, channel: channel_name, index: idx)
            unless opts[:local]
              last = PWN.const_defined?(:MeshLastTx) ? PWN.const_get(:MeshLastTx) : nil
              if last.is_a?(Hash) &&
                 from_id.downcase == last[:from].to_s.downcase &&
                 rx_text == last[:text].to_s &&
                 last[:at].is_a?(Time) && (Time.now - last[:at]) < 10
                return
              end
            end
            from_id = mesh_self_node_id(env: env) if opts[:local] && from_id.empty?
            dest = to
            dest = mesh_self_node_id(env: env) if dest.empty? && !opts[:local]
            dest_label = mesh_reply_target_label(to: dest, env: env, channel_name: channel_name)
            from = mesh_decorate_local_id(id: from_id, env: env)
            dest_label = mesh_decorate_local_id(id: dest_label, env: env)
            path = mesh_conversation_path(env: env, channel_name: channel_name, topic: msg[:topic] || packet[:topic])
            unless path.empty?
              from = "#{path}/#{from}"
              dest_label = "#{path}/#{mesh_broadcast?(to: dest) ? '#' : dest_label}"
            end
            unless opts[:local] || mesh_broadcast?(to: to) || from_id.empty?
              PWN.send(:remove_const, :MeshLastDm) if PWN.const_defined?(:MeshLastDm)
              PWN.const_set(:MeshLastDm, from_id)
            end
            unless opts[:local] || channel_name.empty?
              PWN.send(:remove_const, :MeshLastChannel) if PWN.const_defined?(:MeshLastChannel)
              PWN.const_set(:MeshLastChannel, channel_name)
            end

            if PWN.const_defined?(:MeshMutex) && PWN.const_defined?(:MeshRxBodyWin)
              mutex = PWN.const_get(:MeshMutex)
              state = PWN.const_defined?(:MeshRxState) ? PWN.const_get(:MeshRxState) : {}
              ts = Time.now.strftime('%Y-%m-%d %H:%M:%S%z')
              color = opts[:local] ? 23 : 21
              secure = packet[:pki_encrypted] == true || mesh_channel_securely_encrypted?(env: env, channel: channel_name)
              security_icon = secure ? '🔒' : '🔍'
              current_line = "#{ts}  #{security_icon}  #{from.strip}  #{dest_label}\n#{display_text}"
              unless state[:last_line] == current_line
                rx_body_win = PWN.const_get(:MeshRxBodyWin)
                mutex.synchronize do
                  width = [rx_body_win.maxx - 2, 1].max
                  rx_body_win.attron(Curses.color_pair(color) | Curses::A_BOLD)
                  rx_body_win.addstr(" #{ts}  #{security_icon}  #{from.strip}  ·  #{dest_label}\n")
                  rx_body_win.attroff(Curses.color_pair(color) | Curses::A_BOLD)
                  rx_body_win.attron(Curses.color_pair(24))
                  mesh_wrap_text(text: display_text, width: width - 1).each do |line|
                    rx_body_win.addstr(" #{line}\n")
                  end
                  rx_body_win.addstr("\n")
                  rx_body_win.attroff(Curses.color_pair(24))
                  rx_body_win.refresh
                end
                state[:last_line] = current_line
                state[:last_from] = from
                PWN.send(:remove_const, :MeshRxState) if PWN.const_defined?(:MeshRxState)
                PWN.const_set(:MeshRxState, state)
              end
            end

            unless opts[:local] || decoded[:emoji].to_i.positive?
              mesh_maybe_dispatch_to_pwn_ai(
                text: rx_text,
                from: from_id,
                to: to,
                channel_name: channel_name,
                radio: idx
              )
            end
          rescue StandardError => e
            mesh_ui_puts(text: "RX display failed: #{e.class}: #{e.message}")
          end

          def mesh_reaction_text(opts = {})
            packet = opts[:packet]
            text = opts[:text]
            decoded = packet[:decoded]
            state = PWN.const_defined?(:MeshRxState) ? PWN.const_get(:MeshRxState) : {}
            PWN.const_set(:MeshRxState, state) unless PWN.const_defined?(:MeshRxState)
            messages = state[:messages] ||= {}
            scope = opts[:index].nil? ? [:channel, opts[:channel]] : [:radio, opts[:index].to_i]
            id = packet[:id].to_i
            if decoded[:emoji].to_i.zero?
              messages[[scope, id]] = { from: opts[:from], text: text } if id.positive?
              messages.shift while messages.size > 1000
              return text unless decoded[:reply_id].to_i.positive?
            end

            original = messages[[scope, decoded[:reply_id].to_i]]
            original ||= mesh_reaction_original(reply_id: decoded[:reply_id], index: opts[:index])
            target = original ? "#{original[:from]} >> #{original[:text]}" : "original message unavailable (packet #{decoded[:reply_id].to_i})"
            if decoded[:emoji].to_i.positive?
              "Reacted to: \"#{target}\" with: #{text}."
            else
              "Replied to: \"#{target}\" with: #{text}"
            end
          end

          def mesh_reaction_original(opts = {})
            obj = PWN.const_defined?(:MeshObj) ? PWN.const_get(:MeshObj) : nil
            return unless obj.is_a?(Hash) && opts[:reply_id].to_i.positive?
            return if opts[:index].nil?

            rows = obj[:rx_mutex] ? obj[:rx_mutex].synchronize { Array(obj[:proto_data]).dup } : Array(obj[:proto_data]).dup
            originals = rows.filter_map do |row|
              packet = row[:packet] if row.is_a?(Hash)
              next unless packet.is_a?(Hash) && packet[:id].to_i == opts[:reply_id].to_i
              next unless packet.fetch(:channel, 0).to_i == opts[:index].to_i

              data = packet[:decoded]
              next unless data.is_a?(Hash) && mesh_text_app?(portnum: data[:portnum]) && data[:emoji].to_i.zero?

              { from: mesh_format_node_id(id: packet[:node_id_from] || packet[:from]), text: mesh_rx_text(payload: data[:payload]).to_s }
            end.uniq
            originals.first if originals.size == 1
          end

          private :mesh_reaction_text, :mesh_reaction_original

          def mesh_maybe_dispatch_to_pwn_ai(opts = {})
            return :skipped unless opts.is_a?(Hash)

            env = opts[:env] || mesh_env_hash
            return :skipped unless env[:dispatch_to_pwn_ai] == true

            channel_name = opts[:channel_name].to_s
            if channel_name.empty? && !opts[:radio].nil?
              channel_name = mesh_channel_name_for_index(index: opts[:radio], env: env)
              channel_name = mesh_whitelist_name_for_index(env: env, index: opts[:radio]) if channel_name.empty?
            end
            return :skipped unless mesh_channel_securely_encrypted?(env: env, channel: channel_name)
            return :skipped unless mesh_ai_whitelisted?(env: env, channel: channel_name)

            text = mesh_ai_prompt(text: opts[:text])
            from = opts[:from].to_s
            return :skipped if text.to_s.empty? || from.empty?
            return :skipped if from.downcase == mesh_self_node_id(env: env).downcase
            return :skipped if PWN.const_defined?(:MeshDispatchLock)

            PWN.const_set(:MeshDispatchLock, true)
            ch = env[:channel] || {}
            slot = ch[channel_name.to_sym] || ch[channel_name] || {}
            obj = PWN.const_defined?(:MeshObj) ? PWN.const_get(:MeshObj) : nil
            dest = mesh_broadcast?(to: opts[:to]) ? '!ffffffff' : from
            radio = opts[:radio]
            radio = mesh_radio_index_for_name(env: env, obj: obj, name: channel_name) if radio.nil?
            raw = defined?(PWN::Env) && PWN::Env.is_a?(Hash) ? PWN::Env.dig(:ai, :active).to_s : ''
            engine = raw.empty? ? nil : raw.downcase.to_sym
            Thread.new do
              Thread.current[:pwn_swarm_engine] = nil
              reply = PWN::AI::Agent::Loop.run(request: text, nested: true, engine: engine)
              mesh_send_text(
                env: env,
                obj: obj,
                from: mesh_self_node_id(env: env, obj: obj),
                to: dest,
                text: reply.to_s,
                channel_name: channel_name,
                radio: radio,
                region: slot[:region],
                topic: slot[:topic],
                channel: slot[:channel_num] || channel_name,
                psks: mesh_channel_psks(env: env)
              )
            rescue StandardError => e
              mesh_ui_puts(text: "TX failed: #{e.class}: #{e.message}")
            ensure
              PWN.send(:remove_const, :MeshDispatchLock) if PWN.const_defined?(:MeshDispatchLock)
            end
            :dispatched
          end

          def mesh_refresh_ui!(opts = {})
            env = opts[:env] || mesh_env_hash
            ch = env[:channel] || {}
            active = ch[:active].to_s.to_sym
            slot = ch[active] || {}
            region = slot[:region]
            topic = slot[:topic]
            channel_num = slot[:channel_num]
            link = mesh_link_label(env: env)
            PWN.send(:remove_const, :MeshTxPrompt) if PWN.const_defined?(:MeshTxPrompt)
            PWN.const_set(:MeshTxPrompt, 'pwn.mesh › ')
            epoch = PWN.const_defined?(:MeshTxEpoch) ? PWN.const_get(:MeshTxEpoch).to_i : 0
            PWN.send(:remove_const, :MeshTxEpoch) if PWN.const_defined?(:MeshTxEpoch)
            PWN.const_set(:MeshTxEpoch, epoch + 1)
            return env unless PWN.const_defined?(:MeshRxHeaderWin)

            win = PWN.const_get(:MeshRxHeaderWin)
            mutex = PWN.const_defined?(:MeshMutex) ? PWN.const_get(:MeshMutex) : Mutex.new
            active = ch[:active].to_s
            transport = mesh_bound_transport(env: env).to_s.upcase
            dispatch = env[:dispatch_to_pwn_ai] == true ? 'AI REPLIES ON' : 'AI REPLIES OFF'
            rx_header = " PWN / MESH     #{transport}   ·   #{active} "
            mutex.synchronize do
              win.clear
              mesh_box!(win: win)
              inner = [win.maxx - 2, 1].max
              win.attron(Curses.color_pair(20) | Curses::A_BOLD)
              win.setpos(1, 1)
              win.addstr(rx_header.to_s[0, inner].ljust(inner))
              win.attroff(Curses.color_pair(20) | Curses::A_BOLD)
              if win.maxy >= 5
                win.setpos(2, 2)
                win.addstr("#{link}   /   #{region}/#{topic}"[0, inner - 2])
                win.setpos(3, 2)
                win.attron(Curses.color_pair(23)) do
                  win.addstr("CHANNEL #{active}   ·   #{dispatch}   ·   /status"[0, inner - 2])
                end
              end
              win.refresh
            end
            env
          end

          # Reopen the Meshtastic session after a live /transport /device /channel change.
          def mesh_reconnect!(opts = {})
            env = opts[:env] || mesh_env_hash
            return :skipped unless PWN.const_defined?(:MeshObj)

            old = PWN.const_get(:MeshObj)
            old_transport = PWN.const_defined?(:MeshTransport) ? PWN.const_get(:MeshTransport) : mesh_transport(env: env)
            begin
              mesh_disconnect(env: { transport: old_transport }, obj: old)
            rescue StandardError => e
              mesh_ui_puts(text: "[pwn-mesh] disconnect: #{e.class}: #{e.message}")
            end
            if PWN.const_defined?(:MeshSubThread)
              thr = PWN.const_get(:MeshSubThread)
              thr.kill if thr.respond_to?(:alive?) && thr.alive?
              PWN.send(:remove_const, :MeshSubThread)
            end
            PWN.send(:remove_const, :MeshObj)
            PWN.send(:remove_const, :MqttObj) if PWN.const_defined?(:MqttObj)
            obj = mesh_connect(env: env)
            PWN.const_set(:MeshObj, obj)
            PWN.const_set(:MqttObj, obj)
            mesh_start_rx!(env: env, obj: obj)
            mesh_refresh_ui!(env: env)
            :reconnected
          rescue StandardError => e
            mesh_ui_puts(text: "[pwn-mesh] reconnect failed: #{e.class}: #{e.message}")
            :failed
          end

          PWN_MESH_SLASH_COMMANDS = %w[
            /back /channel /device /help /menu /msg /status /toggle-dispatch-to-pwn-ai /transport
          ].freeze

          PWN_MESH_SLASH_SUBCOMMANDS = {
            '/channel' => %w[list],
            '/device' => %w[list],
            '/msg' => [],
            '/help' => [],
            '/back' => [],
            '/status' => [],
            '/toggle-dispatch-to-pwn-ai' => [],
            '/transport' => %w[list auto serial bluetooth tcp mqtt]
          }.freeze

          # Curses overlay rows for the pwn-mesh slash menu (Reline's dropdown is hidden by ncurses).
          def pwn_mesh_menu_rows(opts = {})
            line = opts[:line].to_s
            return [] unless line.start_with?('/')

            target = line.split(/\s+/, -1).last.to_s
            pwn_mesh_complete(target: target, line: line)
          end

          # TAB hits for pwn-mesh slash menus (commands, channel names, transports, devices).
          def pwn_mesh_complete(opts = {})
            target = opts[:target].to_s
            line = opts[:line].to_s
            line = target if line.empty?
            return [] unless line.start_with?('/')

            pwn_mesh_complete_command(target: target, line: line)
          end

          def pwn_mesh_complete_command(opts = {})
            line = opts[:line].to_s
            target = opts[:target].to_s
            tokens = line.split(/\s+/, -1)
            tokens = [''] if tokens.empty?
            if tokens.length <= 1
              prefix = tokens.first.to_s
              prefix = '/' if prefix.empty?
              return PWN_MESH_SLASH_COMMANDS.select { |c| c.start_with?(prefix) }
            end

            cmd = tokens.first
            sub_prefix = tokens.last.to_s
            env = mesh_env_hash
            pool =
              case cmd
              when '/channel'
                (%w[list] + mesh_channel_names(env: env)).uniq
              when '/msg'
                mesh_channel_names(env: env)
              when '/transport'
                %w[list auto serial bluetooth tcp mqtt]
              when '/device'
                (%w[list] + mesh_list_devices(env: env).map { |d| d.to_s.split.first }.compact).uniq
              else
                Array(PWN_MESH_SLASH_SUBCOMMANDS[cmd])
              end
            hits = pool.select { |s| sub_prefix.empty? || s.start_with?(sub_prefix) }
            hits = [target] if hits.empty? && !target.empty?
            hits
          end

          # Install Reline dropdown for pwn-mesh slash commands.
          def install_pwn_mesh_completer!(opts = {})
            return unless defined?(Reline)

            Thread.current[:pwn_ai_completer_pry] = opts[:pry]
            @pwn_ai_prev_completion_proc = Reline.completion_proc
            if Reline.respond_to?(:completer_word_break_characters)
              @pwn_ai_prev_word_break = Reline.completer_word_break_characters
              Reline.completer_word_break_characters = Reline.completer_word_break_characters.to_s.delete('/')
            end
            # Curses owns the TTY; Reline's completion dialog would paint off-screen.
            Reline.autocompletion = false
            Reline.completion_proc = proc do |target|
              line = Reline.respond_to?(:line_buffer) ? Reline.line_buffer.to_s : target.to_s
              pwn_mesh_complete(target: target, line: line)
            end
            Reline.completion_proc
          end

          # Run a leading-slash pwn-mesh command locally. Returns true when handled
          # (caller should not TX the line as mesh text).
          def pwn_mesh_dispatch_slash!(opts = {})
            request = opts[:request].to_s
            return false unless request.strip.start_with?('/')

            tokens = request.strip.split(/\s+/)
            cmd = tokens[0].to_s
            pi = opts[:pry]
            env = mesh_env_hash
            if ['/', '/menu'].include?(cmd)
              mesh_menu_root(pry: pi, env: env)
              return true
            end
            return false unless PWN_MESH_SLASH_COMMANDS.include?(cmd)

            args = tokens[1..]
            case cmd
            when '/help'
              mesh_ui_puts(text: pwn_mesh_help_text)
            when '/back'
              if pi.respond_to?(:config)
                PWN::Plugins::REPL.leave_special_mode!(pry: pi)
              else
                mesh_ui_puts(text: "[*] Type 'back' to leave pwn-mesh.")
              end
            when '/status'
              mesh_ui_puts(text: pwn_mesh_status_text(env: env))
            when '/channel'
              pwn_mesh_run_channel(args: args, env: env)
            when '/msg'
              pwn_mesh_run_msg(args: args, env: env)
            when '/transport'
              pwn_mesh_run_transport(args: args, env: env)
            when '/device'
              pwn_mesh_run_device(args: args, env: env)
            when '/toggle-dispatch-to-pwn-ai'
              pwn_mesh_run_toggle_dispatch(env: env)
            end
            true
          rescue StandardError => e
            mesh_ui_puts(text: "[pwn-mesh] #{cmd}: #{e.class}: #{e.message}")
            true
          end

          def pwn_mesh_help_text(opts = {})
            lines = [opts[:banner] || 'pwn-mesh commands:']
            PWN_MESH_SLASH_COMMANDS.each do |c|
              subs = Array(PWN_MESH_SLASH_SUBCOMMANDS[c])
              extra = ''
              extra = '|<name>' if c == '/channel'
              extra = ' [!nodeid|channel] <text>' if c == '/msg'
              extra = '|<path|address|host:port>' if c == '/device'
              extra = '|mqtt|serial|bluetooth|tcp' if c == '/transport' && !subs.include?('mqtt')
              lines << (subs.empty? ? "  #{c}#{extra}" : "  #{c} #{subs.join('|')}#{extra}")
            end
            lines << '  TAB: /… command menu · else send as mesh text'
            lines.join("\n")
          end

          def pwn_mesh_status_text(opts = {})
            env = opts[:env] || mesh_env_hash
            ch = env[:channel] || {}
            active = ch[:active].to_s
            slot = ch[active.to_sym] || ch[active] || {}
            transport = mesh_bound_transport(env: env)
            pin = mesh_transport(env: env)
            shown = pin == :auto ? "#{transport} (auto)" : transport.to_s
            [
              "active transport=#{shown} device=#{mesh_link_label(env: env)}",
              "active channel=#{active.empty? ? '(none)' : active} region=#{slot[:region]} topic=#{slot[:topic]} ch=#{slot[:channel_num]}",
              "dispatch-to-pwn-ai=#{env[:dispatch_to_pwn_ai] == true ? 'on' : 'off'}"
            ].join("\n")
          end

          def pwn_mesh_run_toggle_dispatch(opts = {})
            return false unless opts.is_a?(Hash)

            env = opts[:env] || mesh_env_hash
            env[:dispatch_to_pwn_ai] = env[:dispatch_to_pwn_ai] != true
            persist_mesh_env(mesh: env)
            state = env[:dispatch_to_pwn_ai] ? 'on' : 'off'
            mesh_refresh_ui!(env: env)
            mesh_ui_puts(text: "[*] dispatch-to-pwn-ai=#{state} (encrypted + ai_whitelist + @ai; DMs if whitelisted)")
            env[:dispatch_to_pwn_ai]
          end

          def pwn_mesh_run_msg(opts = {})
            env = opts[:env] || mesh_env_hash
            tokens = Array(opts[:args]).map(&:to_s)
            if tokens.empty? && PWN.const_defined?(:MeshPendingDm) && PWN::MeshPendingDm
              pending = PWN::MeshPendingDm
              tokens = [pending[:to], pending[:text]]
            end
            names = mesh_channel_names(env: env)
            dest = nil
            channel_name = ''
            if tokens[0].to_s.match?(/\A![0-9a-fA-F]{8}\z/)
              dest = tokens.shift
              channel_name = env.dig(:channel, :active).to_s
            elsif names.any? { |n| n.casecmp?(tokens[0].to_s) }
              channel_name = names.find { |n| n.casecmp?(tokens[0].to_s) }.to_s
              tokens.shift
              dest = '!ffffffff'
            end
            dest = PWN.const_get(:MeshLastDm).to_s if dest.nil? && PWN.const_defined?(:MeshLastDm)
            if dest.nil? && PWN.const_defined?(:MeshLastChannel)
              channel_name = PWN.const_get(:MeshLastChannel).to_s
              dest = '!ffffffff'
            end
            text = tokens.join(' ').strip
            raise ArgumentError, 'usage: /msg [!nodeid|channel] <text>' if dest.to_s.empty? || text.empty?

            channel_name = PWN.const_get(:MeshLastChannel).to_s if channel_name.empty? && PWN.const_defined?(:MeshLastChannel)
            channel_name = env.dig(:channel, :active).to_s if channel_name.empty?
            ch = env[:channel] || {}
            slot = ch[channel_name.to_sym] || ch[channel_name] || {}
            obj = PWN.const_defined?(:MeshObj) ? PWN.const_get(:MeshObj) : nil
            mesh_send_text(
              env: env,
              obj: obj,
              from: mesh_self_node_id(env: env, obj: obj),
              to: dest,
              text: text,
              channel_name: channel_name,
              radio: mesh_radio_index_for_name(env: env, obj: obj, name: channel_name),
              region: slot[:region],
              topic: slot[:topic],
              channel: slot[:channel_num] || channel_name,
              psks: mesh_channel_psks(env: env)
            )
          end

          def pwn_mesh_run_channel(opts = {})
            args = Array(opts[:args]).map(&:to_s)
            env = opts[:env] || mesh_env_hash
            env[:channel] ||= {}
            names = mesh_channel_names(env: env)
            sub = args.join(' ').strip
            if sub.empty? || sub == 'list'
              active = env[:channel][:active].to_s
              choice = mesh_menu_pick(title: 'pwn-mesh channel', items: names, current: active)
              return names if choice.nil?

              sub = choice
            end

            raise "unknown channel #{sub.inspect} — try: #{names.join(', ')}" unless names.include?(sub)

            env[:channel][:active] = sub
            persisted = persist_mesh_env(mesh: env)
            mesh_reconnect!(env: env)
            msg = "active channel=#{sub}"
            msg = "#{msg} (session only)" unless persisted
            mesh_ui_puts(text: "[*] #{msg}")
            sub
          end

          def pwn_mesh_run_transport(opts = {})
            args = Array(opts[:args]).map(&:to_s)
            env = opts[:env] || mesh_env_hash
            names = %w[auto serial bluetooth tcp mqtt]
            sub = args[0].to_s.downcase
            if sub.empty? || sub == 'list'
              current = mesh_transport(env: env).to_s
              choice = mesh_menu_pick(title: 'pwn-mesh transport', items: names, current: current)
              return names if choice.nil?

              sub = choice
            end

            raise "unknown transport #{sub.inspect} — try: #{names.join(', ')}" unless names.include?(sub)

            env[:transport] = sub
            persisted = persist_mesh_env(mesh: env)
            mesh_reconnect!(env: env)
            msg = "active transport=#{sub} device=#{mesh_link_label(env: env)}"
            msg = "#{msg} (session only)" unless persisted
            mesh_ui_puts(text: "[*] #{msg}")
            sub
          end

          def pwn_mesh_run_device(opts = {})
            args = Array(opts[:args]).map(&:to_s)
            env = opts[:env] || mesh_env_hash
            sub = args.join(' ').strip
            if sub.empty? || sub == 'list'
              devices = mesh_list_devices(env: env).map { |d| d.to_s.split.first }.compact
              choice = mesh_menu_pick(title: 'pwn-mesh device', items: devices, current: mesh_link_label(env: env))
              return devices if choice.nil?

              sub = choice
            end

            case mesh_transport(env: env)
            when :serial
              env[:serial] ||= {}
              env[:serial][:port] = sub
            when :bluetooth
              env[:bluetooth] ||= {}
              env[:bluetooth][:address] = sub.split.first
            when :tcp
              host, port = sub.split(':', 2)
              env[:tcp] ||= {}
              env[:tcp][:host] = host
              env[:tcp][:port] = port.to_i.positive? ? port.to_i : 4403
            else
              host, port = sub.split(':', 2)
              env[:mqtt] ||= {}
              env[:mqtt][:host] = host
              env[:mqtt][:port] = port.to_i.positive? ? port.to_i : 1883
            end
            persisted = persist_mesh_env(mesh: env)
            mesh_reconnect!(env: env)
            msg = "active device=#{mesh_link_label(env: env)}"
            msg = "#{msg} (session only)" unless persisted
            mesh_ui_puts(text: "[*] #{msg}")
            sub
          end

          # Write plugins.meshtastic from the live Env into ~/.pwn/pwn.yaml (vault).
          def persist_mesh_env(opts = {})
            mesh = opts[:mesh]
            mesh = mesh_env_hash if mesh.nil?
            return false unless mesh.is_a?(Hash)

            env_path = nil
            dec_path = nil
            if defined?(PWN::Env) && PWN::Env.is_a?(Hash)
              env_path = PWN::Env.dig(:driver_opts, :pwn_env_path)
              dec_path = PWN::Env.dig(:driver_opts, :pwn_dec_path)
            end
            env_path = env_path.to_s.strip
            env_path = File.join(Dir.home, '.pwn', 'pwn.yaml') if env_path.empty?
            dec_path = dec_path.to_s.strip
            dec_path = "#{env_path}.decryptor" if dec_path.empty?
            return false unless File.exist?(env_path) && File.exist?(dec_path) && File.readable?(dec_path)

            decryptor = YAML.load_file(dec_path, symbolize_names: true)
            key = decryptor.is_a?(Hash) ? decryptor[:key] : nil
            iv = decryptor.is_a?(Hash) ? decryptor[:iv] : nil
            return false if key.to_s.strip.empty? || iv.to_s.strip.empty?

            PWN::Plugins::Vault.decrypt(file: env_path, key: key, iv: iv)
            begin
              cfg = YAML.load_file(env_path, symbolize_names: true)
              cfg = {} unless cfg.is_a?(Hash)
              cfg[:plugins] = {} unless cfg[:plugins].is_a?(Hash)
              dst = cfg[:plugins][:meshtastic]
              dst = {} unless dst.is_a?(Hash)
              mesh.each do |key, val|
                k = key.respond_to?(:to_sym) ? key.to_sym : key
                if dst[k].is_a?(Hash) && val.is_a?(Hash)
                  nested = dst[k].dup
                  val.each do |nk, nv|
                    nested[nk.respond_to?(:to_sym) ? nk.to_sym : nk] = nv
                  end
                  dst[k] = nested
                else
                  dst[k] = val
                end
              end
              cfg[:plugins][:meshtastic] = dst
              yaml_env = YAML.dump(cfg).gsub(/^(\s*):/, '\1')
              File.write(env_path, yaml_env)
              File.chmod(0o600, env_path)
            ensure
              PWN::Plugins::Vault.encrypt(file: env_path, key: key, iv: iv)
            end
            true
          rescue StandardError => e
            mesh_ui_puts(text: "[pwn-mesh] persist skipped: #{e.class}: #{e.message}")
            false
          end

          private :mesh_transport, :mesh_bound_transport, :mesh_layout, :mesh_box!, :mesh_mqtt_region, :mesh_mqtt_topic, :mesh_active_psks, :mesh_device_channel_meta, :mesh_device_channels
          private :mesh_radio_channel, :mesh_radio_index_for_name, :mesh_channel_name_for_index, :mesh_unassigned_slot_map, :mesh_psk_b64, :mesh_psk_same?, :mesh_env_channel_name_for_psk, :mesh_whitelist_name_for_index, :mesh_channel_name_from_topic, :mesh_link_label
          private :mesh_connect_one, :mesh_connect, :mesh_mqtt_tls?, :mesh_subscribe, :mesh_text_payload_max, :mesh_payload_fits?, :mesh_text_chunks, :mesh_tx_row_ready?, :mesh_tx_outcome, :mesh_wait_tx_slot, :mesh_send_text, :mesh_disconnect, :mesh_compose_send, :mesh_channel_names, :mesh_env_hash
          private :mesh_submit, :mesh_console_loop, :mesh_drain_events, :mesh_draw_input, :mesh_wrap_text, :mesh_ui_puts, :mesh_menu_root, :mesh_list_devices
          private :mesh_start_rx!, :mesh_channel_psks, :mesh_text_app?, :mesh_rx_text, :mesh_self_node_id, :mesh_decorate_local_id, :mesh_public_psk?, :mesh_channel_securely_encrypted?
          private :mesh_ai_whitelisted?, :mesh_ai_prompt, :mesh_broadcast?, :mesh_reply_target_label, :mesh_handle_rx, :mesh_maybe_dispatch_to_pwn_ai, :mesh_refresh_ui!, :mesh_reconnect!
          private :pwn_mesh_complete_command, :pwn_mesh_help_text, :pwn_mesh_status_text, :pwn_mesh_run_toggle_dispatch, :pwn_mesh_run_msg, :pwn_mesh_run_channel, :pwn_mesh_run_transport, :pwn_mesh_run_device
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):
            0day Inc. <support@0dayinc.com>
          "
        end

        # Display usage for this module.

        public_class_method def self.help
          puts "USAGE:
            # Register the pwn-mesh Pry command.
            #{self}.add_commands

            # Curses arrow-key picker for pwn-mesh channel, transport, and device lists.
            #{self}.mesh_menu_pick(
              title: 'optional - window title drawn on the boxed curses menu',
              items: 'required - Array of selectable strings such as channel names',
              current: 'optional - currently selected item to highlight',
              getch: 'optional - proc returning the next key so specs can drive the menu without a TTY'
            )

            # Clear the pwn-mesh TX buffer after a slash command or sent mesh line.
            #{self}.mesh_reset_input!(
              pry: 'optional - Pry instance whose Reline/line_buffer should be emptied',
              submitted: 'optional - the line that was just accepted so the TX pane can hide it'
            )

            # Curses overlay rows for the pwn-mesh slash menu while typing a leading slash.
            #{self}.pwn_mesh_menu_rows(
              line: 'optional - current TX buffer; leading slash lists matching mesh commands'
            )

            # TAB hits for pwn-mesh slash menus (commands, named channels, transports, devices).
            #{self}.pwn_mesh_complete(
              target: 'required - token Reline is completing in pwn-mesh',
              line: 'optional - full line buffer so /channel P<TAB> can list named channels'
            )

            # Install Reline dropdown for pwn-mesh slash commands.
            #{self}.install_pwn_mesh_completer!(
              pry: 'optional - Pry instance stored for mesh TAB completion'
            )

            # Run a leading-slash pwn-mesh command locally instead of sending it as mesh text.
            #{self}.pwn_mesh_dispatch_slash!(
              request: 'optional - full line such as /channel list or /transport serial',
              pry: 'optional - Pry instance used by /back to leave pwn-mesh'
            )

            # Write plugins.meshtastic from the live Env into the encrypted pwn.yaml vault.
            #{self}.persist_mesh_env(
              mesh: 'optional - meshtastic Hash to persist (defaults to PWN::Env plugins.meshtastic)'
            )

            # Print the AUTHOR(S) string for this module.
            #{self}.authors
          "
          constants.sort
        end
      end
    end
  end
end
