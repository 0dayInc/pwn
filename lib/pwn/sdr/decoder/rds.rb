# frozen_string_literal: true

require 'json'
require 'tty-spinner'

module PWN
  module SDR
    module Decoder
      # RDS Decoder Module for FM Radio Signals.
      #
      # Two entry points:
      #   .sample  — non-interactive structured Hash (agents / cron / tools)
      #   .decode  — interactive TTY spinner (human REPL via GQRX.init_freq)
      #
      # Both share the same GQRX RDS protocol path (U RDS, p RDS_PI / PS_NAME /
      # RADIOTEXT). .sample is the canonical mid-layer API that Extrospection
      # and any other automation should call.
      module RDS
        DEFAULT_SETTLE_SECS = 8.0
        DEFAULT_INTERVAL    = 0.75
        CALLSIGN_RX         = /\A[A-Z]{1,2}[A-Z0-9]{2,4}\z/
        CALLSIGN_RT_RX      = /\A([A-Z]{1,2}[A-Z0-9]{2,4})\b/

        # Supported Method Parameters::
        # rds_hash = PWN::SDR::Decoder::RDS.sample(
        #   gqrx_sock:   'required unless freq_obj - TCPSocket from GQRX.connect',
        #   freq_obj:    'required unless gqrx_sock - Hash from GQRX.init_freq',
        #   settle_secs: 'optional - seconds to sample (default 8, max 30)',
        #   interval:    'optional - poll interval seconds (default 0.75)',
        #   leave_enabled: 'optional - leave RDS decoder ON after sample (default false)'
        # )
        #
        # Returns::
        #   {
        #     pi:, ps_name:, radiotext:, station:,
        #     samples: Integer, settle_secs: Float,
        #     error: String?   # present when RDS backend is unavailable
        #   }

        public_class_method def self.sample(opts = {})
          sock = resolve_sock(opts)
          raise ArgumentError, 'gqrx_sock: or freq_obj: with :gqrx_sock required' unless sock

          settle   = (opts[:settle_secs] || DEFAULT_SETTLE_SECS).to_f.clamp(0.5, 30.0)
          interval = [(opts[:interval] || DEFAULT_INTERVAL).to_f, 0.1].max
          leave_on = opts[:leave_enabled] ? true : false
          samples  = []

          unless enable_rds!(sock: sock)
            return {
              pi: nil,
              ps_name: nil,
              radiotext: nil,
              station: nil,
              samples: 0,
              settle_secs: settle,
              error: 'RDS not supported by this radio backend'
            }
          end

          deadline = Time.now + settle
          while Time.now < deadline
            snap = poll_once(sock: sock)
            samples << snap unless snap[:pi].empty? && snap[:ps].empty? && snap[:rt].empty?

            # Early exit once we have a non-zero PI and a non-trivial RT —
            # give one more interval for RadioText to finish filling.
            pi = snap[:pi]
            rt = snap[:rt]
            if pi =~ /\A[0-9A-F]{4}\z/ && pi != '0000' && rt.length >= 8
              sleep interval
              snap2 = poll_once(sock: sock)
              samples << snap2
              break if snap2[:rt].length >= rt.length
            end

            sleep interval
          end

          disable_rds!(sock: sock) unless leave_on

          aggregate(samples: samples, settle_secs: settle)
        rescue ArgumentError
          raise
        rescue StandardError => e
          disable_rds!(sock: sock) if sock && !leave_on
          {
            pi: nil,
            ps_name: nil,
            radiotext: nil,
            station: nil,
            samples: samples&.length.to_i,
            settle_secs: settle,
            error: "#{e.class}: #{e.message}"
          }
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::RDS.decode(
        #   freq_obj: 'required - Hash returned from PWN::SDR::GQRX.init_freq'
        # )
        #
        # Interactive TTY UX: enables RDS, spins a live status line until the
        # operator presses ENTER, then disables RDS. Does not return a Hash —
        # callers that need structured data should use .sample instead.

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          raise ArgumentError, 'freq_obj: required' unless freq_obj.is_a?(Hash)

          gqrx_sock = freq_obj[:gqrx_sock]
          raise ArgumentError, 'freq_obj[:gqrx_sock] required' unless gqrx_sock

          # Pretty-print the tuned frequency context without leaking the socket.
          display = freq_obj.dup
          display.delete(:gqrx_sock)
          skip_freq_char = "\n"
          puts JSON.pretty_generate(display)
          puts "\n*** FM Radio RDS Decoder ***"
          puts 'Press [ENTER] to continue to next frequency...'

          unless enable_rds!(sock: gqrx_sock)
            puts 'ERROR: RDS not supported by this radio backend'
            return nil
          end

          spinner = TTY::Spinner.new(
            '[:spinner] :status',
            format: :arrow_pulse,
            clear: true,
            hide_cursor: true
          )

          spinner_overhead = 12
          max_title_length = [TTY::Screen.width - spinner_overhead, 50].max

          initial_title = 'INFO: Decoding FM radio RDS data...'
          initial_title = initial_title[0...max_title_length] if initial_title.length > max_title_length
          spinner.update(status: initial_title)
          spinner.auto_spin

          last_resp = {}

          loop do
            snap = poll_once(sock: gqrx_sock)
            rds_resp = {
              rds_pi: snap[:pi],
              rds_ps_name: snap[:ps],
              rds_radiotext: snap[:rt]
            }

            if rds_resp[:rds_pi] != '0000' && !rds_resp[:rds_pi].empty? && rds_resp != last_resp
              rds_pi = rds_resp[:rds_pi].upcase.rjust(4, '0')[0, 4]
              rds_ps = "#{rds_resp[:rds_ps_name]}        "[0, 8]
              rds_rt = rds_resp[:rds_radiotext].rstrip

              prefix = "Program ID: #{rds_pi} | Station Name: #{rds_ps} | Radio Txt: "
              available_for_term = [max_title_length - prefix.length, 10].max
              rt_display = rds_rt
              rt_display = "#{rt_display[0...available_for_term]}..." if rt_display.length > available_for_term

              spinner.update(status: "#{prefix}#{rt_display}")
              last_resp = rds_resp.dup
            end

            if $stdin.wait_readable(0)
              begin
                char = $stdin.read_nonblock(1)
                break if char == skip_freq_char
              rescue IO::WaitReadable, EOFError
                # No-op
              end
            end

            sleep 0.01
          end
        rescue StandardError => e
          spinner.error('Decoding failed') if defined?(spinner) && spinner
          raise e
        ensure
          disable_rds!(sock: gqrx_sock) if defined?(gqrx_sock) && gqrx_sock
          spinner.stop if defined?(spinner) && spinner
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):
            0day Inc. <support@0dayinc.com>
          "
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts "USAGE:
            # Non-interactive (agents / automation) — returns a Hash:
            rds = #{self}.sample(
              gqrx_sock: sock,          # or freq_obj: from init_freq
              settle_secs: 8,           # default 8, max 30
              leave_enabled: false
            )
            # => { pi:, ps_name:, radiotext:, station:, samples:, settle_secs: }

            # Interactive TTY spinner (human REPL via GQRX.init_freq decoder: :rds):
            #{self}.decode(
              freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq method'
            )

            #{self}.authors
          "
        end

        # ---- internals -------------------------------------------------------

        private_class_method def self.resolve_sock(opts = {})
          return opts[:gqrx_sock] if opts[:gqrx_sock]

          fo = opts[:freq_obj]
          return fo[:gqrx_sock] if fo.is_a?(Hash)

          nil
        end

        private_class_method def self.enable_rds!(opts = {})
          sock = opts[:sock]
          begin
            PWN::SDR::GQRX.cmd(gqrx_sock: sock, cmd: 'U RDS 0', resp_ok: 'RPRT 0')
          rescue StandardError
            nil
          end
          begin
            PWN::SDR::GQRX.cmd(gqrx_sock: sock, cmd: 'U RDS 1', resp_ok: 'RPRT 0')
            true
          rescue StandardError
            false
          end
        end

        private_class_method def self.disable_rds!(opts = {})
          sock = opts[:sock]
          PWN::SDR::GQRX.cmd(gqrx_sock: sock, cmd: 'U RDS 0')
        rescue StandardError
          nil
        end

        private_class_method def self.poll_once(opts = {})
          sock = opts[:sock]
          pi = begin
            PWN::SDR::GQRX.cmd(gqrx_sock: sock, cmd: 'p RDS_PI').to_s.strip.chomp.delete('.').upcase
          rescue StandardError
            ''
          end
          ps = begin
            PWN::SDR::GQRX.cmd(gqrx_sock: sock, cmd: 'p RDS_PS_NAME').to_s.strip.chomp
          rescue StandardError
            ''
          end
          rt = begin
            PWN::SDR::GQRX.cmd(gqrx_sock: sock, cmd: 'p RDS_RADIOTEXT').to_s.strip.chomp
          rescue StandardError
            ''
          end
          { pi: pi, ps: ps, rt: rt }
        end

        # Fold raw poll samples into the public Hash shape expected by
        # Extrospection.rf_tune / agents (pi / ps_name / radiotext / station).
        private_class_method def self.aggregate(opts = {})
          samples = opts[:samples] || []
          settle  = opts[:settle_secs]

          best_pi = samples.map { |s| s[:pi] }.find { |p| p =~ /\A[0-9A-F]{4}\z/ && p != '0000' }
          best_pi = best_pi.to_s.rjust(4, '0')[0, 4] if best_pi

          # PS often scrolls (artist / title / callsign cycle) — collect every
          # non-empty sample, prefer a short all-caps callsign-like token, and
          # fall back to the longest only when no callsign was seen.
          ps_candidates = samples.map { |s| s[:ps].to_s.strip }.reject(&:empty?)
          callsign_like = ps_candidates.find { |p| p =~ CALLSIGN_RX }
          best_ps = callsign_like || ps_candidates.max_by(&:length)
          best_ps = "#{best_ps}        "[0, 8].rstrip if best_ps
          best_rt = samples.map { |s| s[:rt].to_s.rstrip }.reject(&:empty?).max_by(&:length)

          station = nil
          if best_rt && best_rt =~ CALLSIGN_RT_RX
            station = Regexp.last_match(1)
          elsif callsign_like
            station = callsign_like
          elsif best_ps && best_ps =~ CALLSIGN_RX
            station = best_ps
          end

          # If station callsign is known and best_ps is just a mid-scroll
          # fragment of RadioText, prefer station so callers use station + RT.
          best_ps = station if station && best_ps && best_rt && best_ps != station && best_rt.include?(best_ps)

          {
            pi: best_pi,
            ps_name: best_ps,
            radiotext: best_rt,
            station: station,
            samples: samples.length,
            settle_secs: settle
          }
        end
      end
    end
  end
end
