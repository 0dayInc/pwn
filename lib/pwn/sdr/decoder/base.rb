# frozen_string_literal: true

require 'json'
require 'open3'
require 'tty-spinner'
require 'tty-screen'
require 'io/wait'

module PWN
  module SDR
    module Decoder
      # Shared pipeline plumbing for every PWN::SDR::Decoder::* module.
      #
      # Encapsulates the pattern established by PWN::SDR::Decoder::Flex and
      # PWN::SDR::Decoder::RDS:
      #
      #   1. Bind to the GQRX UDP audio stream (48 kHz s16le mono).
      #   2. Feed it through `sox` (resample to 22 050 Hz) into an external
      #      demodulator (multimon-ng, rtl_433, acarsdec, dsd, ...).
      #   3. Read decoded lines back on a background thread, hand each to a
      #      caller-supplied parser Proc, merge with freq_obj, JSON-log it.
      #   4. Show a TTY::Spinner status line and exit cleanly on [ENTER].
      #
      # Decoders whose external tool needs raw I/Q direct from the SDR (ADSB,
      # GSM, LoRa, WiFi, ZigBee, ...) can instead pass `direct_cmd:` — Base
      # will spawn it stand-alone (no UDP → sox bridge) and still handle the
      # spinner / stdout parser / logging / [ENTER]-to-skip loop uniformly.
      module Base
        # Supported Method Parameters::
        # PWN::SDR::Decoder::Base.run_pipeline(
        #   freq_obj:    'required - freq_obj Hash from PWN::SDR::GQRX.init_freq',
        #   protocol:    'required - short name used in banner / log filename',
        #   decode_cmd:  'optional - shell pipeline reading 22 050 Hz s16le on stdin',
        #   direct_cmd:  'optional - stand-alone shell cmd (owns the SDR itself)',
        #   line_match:  'optional - Regexp/String a stdout line must match',
        #   parser:      'optional - Proc.new { |line| Hash } to structure a line',
        #   required_bins: 'optional - Array of executables that must exist on PATH',
        #   resample_hz: 'optional - sox output rate for decode_cmd (default 22050)'
        # )

        public_class_method def self.run_pipeline(opts = {})
          freq_obj      = opts[:freq_obj]
          protocol      = opts[:protocol] || 'SIGNAL'
          decode_cmd    = opts[:decode_cmd]
          direct_cmd    = opts[:direct_cmd]
          line_match    = opts[:line_match]
          parser        = opts[:parser]
          required_bins = Array(opts[:required_bins])
          resample_hz   = opts[:resample_hz] || 22_050

          raise 'ERROR: :freq_obj is required' unless freq_obj.is_a?(Hash)

          gqrx_sock = freq_obj[:gqrx_sock]
          udp_ip    = freq_obj[:udp_ip]   || '127.0.0.1'
          udp_port  = freq_obj[:udp_port] || 7355
          freq_obj  = freq_obj.dup
          freq_obj.delete(:gqrx_sock)
          freq_obj.delete(:decoder_module)

          skip_freq_char = "\n"

          puts JSON.pretty_generate(freq_obj)
          puts "\n*** #{protocol} Decoder ***"
          puts 'Press [ENTER] to continue to next frequency...'

          missing = required_bins.reject { |b| bin_available?(bin: b) }
          unless missing.empty?
            puts "[!] Missing required executable(s): #{missing.join(', ')}"
            puts '    Install them and re-run, or press [ENTER] to skip.'
          end

          spinner = TTY::Spinner.new(
            '[:spinner] :status',
            format: :arrow_pulse,
            clear: true,
            hide_cursor: true
          )
          spinner_overhead = 12
          max_title_length = [TTY::Screen.width - spinner_overhead, 50].max
          banner = "INFO: Decoding #{protocol} on udp://#{udp_ip}:#{udp_port} ..."
          banner = "INFO: Decoding #{protocol} via `#{direct_cmd.to_s.split.first}` ..." if direct_cmd
          banner = banner[0...max_title_length] if banner.length > max_title_length
          spinner.update(status: banner)
          spinner.auto_spin

          log_file = "/tmp/#{protocol.downcase.gsub(/[^a-z0-9]+/, '_')}_decoder_#{Time.now.strftime('%Y%m%d')}.log"

          udp_listener = nil
          receiver_thread = nil
          mm_stdin = mm_stdout = mm_stderr = mm_wait_thr = nil

          if direct_cmd && missing.empty?
            mm_stdin, mm_stdout, mm_stderr, mm_wait_thr = Open3.popen3(direct_cmd)
          elsif decode_cmd && missing.empty?
            udp_listener = PWN::SDR::GQRX.listen_udp(udp_ip: udp_ip, udp_port: udp_port)

            full_cmd = 'sox -t raw -e signed-integer -b 16 -r 48000 -c 1 - ' \
                       "-t raw -e signed-integer -b 16 -r #{resample_hz} -c 1 - | #{decode_cmd}"
            mm_stdin, mm_stdout, mm_stderr, mm_wait_thr = Open3.popen3(full_cmd)

            receiver_thread = Thread.new do
              loop do
                data, = udp_listener.recv(4096)
                next unless data.to_s.bytesize.positive?

                mm_stdin.write(data)
                begin
                  mm_stdin.flush
                rescue StandardError
                  nil
                end
              end
            rescue IOError, Errno::EPIPE, Errno::ECONNRESET
              nil
            end
          end

          current_title = 'Waiting for data frames...'
          decoder_thread = nil
          if mm_stdout
            decoder_thread = Thread.new do
              buffer = ''
              loop do
                chunk = mm_stdout.readpartial(4096)
                buffer = "#{buffer}#{chunk}"
                while (line = buffer.slice!(/^.*\n/))
                  line = line.chomp
                  next if line.empty?
                  next if line_match && !match_line?(line: line, matcher: line_match)

                  dec_msg = { decoded_at: Time.now.strftime('%Y-%m-%d %H:%M:%S%z'), raw: line }
                  dec_msg.merge!(parser.call(line)) if parser.respond_to?(:call)
                  final_msg = freq_obj.merge(dec_msg)

                  spinner.stop
                  puts JSON.pretty_generate(final_msg)
                  spinner.auto_spin

                  File.open(log_file, 'a') { |f| f.puts("#{JSON.generate(final_msg)},") }
                  disp = dec_msg[:summary] || line
                  current_title = disp[0...max_title_length]
                end
              rescue IOError
                break
              end
            end
          elsif gqrx_sock
            # No external decoder — fall back to live signal-strength telemetry
            decoder_thread = Thread.new do
              loop do
                lvl = PWN::SDR::GQRX.cmd(gqrx_sock: gqrx_sock, cmd: 'l STRENGTH').to_f
                current_title = "signal #{format('%+.1f', lvl)} dBFS (analog / no external demod)"
                sleep 0.3
              end
            rescue StandardError
              nil
            end
          end

          loop do
            spinner.update(status: current_title)
            next unless $stdin.wait_readable(0)

            begin
              char = $stdin.read_nonblock(1)
              next unless char == skip_freq_char

              puts "\n[!] ENTER pressed → stopping #{protocol} decoder..."
              break
            rescue IO::WaitReadable, EOFError
              nil
            end
          end

          spinner.success('Decoding stopped')
        rescue StandardError => e
          spinner.error("Decoding failed: #{e.message}") if defined?(spinner) && spinner
          raise
        ensure
          [receiver_thread, decoder_thread].compact.each { |t| t.kill if t.alive? }
          [mm_stdin, mm_stdout, mm_stderr].compact.each do |io|
            io.close
          rescue StandardError
            nil
          end
          begin
            mm_wait_thr&.value
          rescue StandardError
            nil
          end
          PWN::SDR::GQRX.disconnect_udp(udp_listener: udp_listener) if udp_listener
          spinner.stop if defined?(spinner) && spinner
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::Base.bin_available?(bin: 'multimon-ng')

        public_class_method def self.bin_available?(opts = {})
          bin = opts[:bin].to_s
          return false if bin.empty?

          ENV.fetch('PATH', '').split(File::PATH_SEPARATOR).any? do |dir|
            File.executable?(File.join(dir, bin))
          end
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::Base.match_line?(line: str, matcher: Regexp|String|Array)

        public_class_method def self.match_line?(opts = {})
          line    = opts[:line].to_s
          matcher = opts[:matcher]
          case matcher
          when Regexp then line.match?(matcher)
          when String then line.start_with?(matcher)
          when Array  then matcher.any? { |m| match_line?(line: line, matcher: m) }
          else true
          end
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts "USAGE:
            #{self}.run_pipeline(
              freq_obj:      'required - freq_obj from PWN::SDR::GQRX.init_freq',
              protocol:      'required - short protocol name',
              decode_cmd:    'optional - stdin pipeline (sox-resampled 22 050 Hz s16le)',
              direct_cmd:    'optional - stand-alone cmd that owns the SDR',
              line_match:    'optional - Regexp/String/Array line filter',
              parser:        'optional - Proc { |line| Hash } structured extractor',
              required_bins: 'optional - Array of executables that must be on PATH',
              resample_hz:   'optional - sox output rate (default 22050)'
            )

            #{self}.bin_available?(bin: 'multimon-ng')
            #{self}.match_line?(line: str, matcher: Regexp|String|Array)

            #{self}.authors
          "
        end
      end
    end
  end
end
