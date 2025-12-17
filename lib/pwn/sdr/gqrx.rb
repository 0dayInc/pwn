# frozen_string_literal: true

require 'json'
require 'time'

module PWN
  module SDR
    # This plugin interacts with the remote control interface of GQRX.
    module GQRX
      # Monkey patches for frequency handling
      String.class_eval do
        def raw_hz
          gsub('.', '').to_i
        end
      end

      Integer.class_eval do
        # Should always return format of X.XXX.XXX.XXX
        # So 002_450_000_000 becomes 2.450.000.000
        # So 2_450_000_000 becomes 2.450.000.000
        # So 960_000_000 becomes 960.000.000
        # 1000 should be 1.000
        def pretty_hz
          str_hz = to_s
          # Nuke leading zeros
          # E.g., 002450000000 -> 2450000000
          str_hz = str_hz.sub(/^0+/, '')
          # Insert dots every 3 digits from the right
          str_hz.reverse.scan(/.{1,3}/).join('.').reverse
        end
      end

      # Supported Method Parameters::
      # scan_resp = PWN::SDR::GQRX.log_signals(
      #   signals_arr: 'required - Array of detected signals',
      #   timestamp_start: 'required - Scan start timestamp',
      #   scan_log: 'required - Path to save detected signals log'
      # )
      private_class_method def self.log_signals(opts = {})
        signals_arr = opts[:signals_arr]
        timestamp_start = opts[:timestamp_start]
        scan_log = opts[:scan_log]

        signals = signals_arr.sort_by { |s| s[:freq].to_s.raw_hz }
        timestamp_end = Time.now.strftime('%Y-%m-%d %H:%M:%S%z')
        duration_secs = Time.parse(timestamp_end) - Time.parse(timestamp_start)
        # Convert duration seconds to hours minutes seconds
        hours = (duration_secs / 3600).to_i
        minutes = ((duration_secs % 3600) / 60).to_i
        seconds = (duration_secs % 60).to_i
        duration = format('%<hrs>02d:%<mins>02d:%<secs>02d', hrs: hours, mins: minutes, secs: seconds)

        scan_resp = {
          signals: signals,
          timestamp_start: timestamp_start,
          timestamp_end: timestamp_end,
          duration: duration
        }

        File.write(
          scan_log,
          JSON.pretty_generate(scan_resp)
        )

        scan_resp
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # gqrx_sock = PWN::SDR::GQRX.connect(
      #   target: 'optional - GQRX target IP address (defaults to 127.0.0.1)',
      #   port: 'optional - GQRX target port (defaults to 7356)'
      # )
      public_class_method def self.connect(opts = {})
        target = opts[:target] ||= '127.0.0.1'
        port = opts[:port] ||= 7356

        PWN::Plugins::Sock.connect(target: target, port: port)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # gqrx_resp = PWN::SDR::GQRX.gqrx_cmd(
      #   gqrx_sock: 'required - GQRX socket object returned from #connect method',
      #   cmd: 'required - GQRX command to execute',
      #   resp_ok: 'optional - Expected response from GQRX to indicate success'
      # )

      public_class_method def self.gqrx_cmd(opts = {})
        gqrx_sock = opts[:gqrx_sock]
        cmd = opts[:cmd]
        resp_ok = opts[:resp_ok]

        # Most Recent GQRX Command Set:
        # https://raw.githubusercontent.com/gqrx-sdr/gqrx/master/resources/remote-control.txt
        # Supported commands:
        #  f Get frequency [Hz]
        #  F <frequency> Set frequency [Hz]
        #  m Get demodulator mode and passband
        #  M <mode> [passband]
        #     Set demodulator mode and passband [Hz]
        #     Passing a '?' as the first argument instead of 'mode' will return
        #     a space separated list of radio backend supported modes.
        #  l|L ?
        #     Get a space separated list of settings available for reading (l) or writing (L).
        #  l STRENGTH
        #     Get signal strength [dBFS]
        #  l SQL
        #     Get squelch threshold [dBFS]
        #  L SQL <sql>
        #     Set squelch threshold to <sql> [dBFS]
        #  l AF
        #     Get audio gain [dB]
        #  L AF <gain>
        #     Set audio gain to <gain> [dB]
        #  l <gain_name>_GAIN
        #     Get the value of the gain setting with the name <gain_name>
        #  L <gain_name>_GAIN <value>
        #     Set the value of the gain setting with the name <gain_name> to <value>
        #  p RDS_PI
        #     Get the RDS PI code (in hexadecimal). Returns 0000 if not applicable.
        #  u RECORD
        #     Get status of audio recorder
        #  U RECORD <status>
        #     Set status of audio recorder to <status>
        #  u DSP
        #     Get DSP (SDR receiver) status
        #  U DSP <status>
        #     Set DSP (SDR receiver) status to <status>
        #  u RDS
        #     Get RDS decoder to <status>.  Only functions in WFM mode.
        #  U RDS <status>
        #     Set RDS decoder to <status>.  Only functions in WFM mode.
        #  q|Q
        #     Close connection
        #  AOS
        #     Acquisition of signal (AOS) event, start audio recording
        #  LOS
        #     Loss of signal (LOS) event, stop audio recording
        #  LNB_LO [frequency]
        #     If frequency [Hz] is specified set the LNB LO frequency used for
        #     display. Otherwise print the current LNB LO frequency [Hz].
        #  \chk_vfo
        #     Get VFO option status (only usable for hamlib compatibility)
        #  \dump_state
        #     Dump state (only usable for hamlib compatibility)
        #  \get_powerstat
        #     Get power status (only usable for hamlib compatibility)
        #  v
        #     Get 'VFO' (only usable for hamlib compatibility)
        #  V
        #     Set 'VFO' (only usable for hamlib compatibility)
        #  s
        #     Get 'Split' mode (only usable for hamlib compatibility)
        #  S
        #     Set 'Split' mode (only usable for hamlib compatibility)
        #  _
        #     Get version
        #
        # Reply:
        #  RPRT 0
        #     Command successful
        #  RPRT 1
        #     Command failed

        gqrx_sock.write("#{cmd}\n")
        response = []
        start_time = Time.now

        # Wait up to 2 seconds for initial response
        if gqrx_sock.wait_readable(2.0)
          response.push(gqrx_sock.readline.chomp)
          # Drain any additional lines quickly
          loop do
            # This is the main contributing factor to this scanner being slow.
            # We're trading speed for accuracy here.
            # break if gqrx_sock.wait_readable(0.0625).nil? && cmd == 'l STRENGTH'
            break if gqrx_sock.wait_readable(0.04).nil? && cmd == 'l STRENGTH'
            break if gqrx_sock.wait_readable(0.001).nil? && cmd != 'l STRENGTH'

            response.push(gqrx_sock.readline.chomp)
          end
        end

        raise "No response for command: #{cmd}" if response.empty?

        response_str = response.length == 1 ? response.first : response.join(' ')

        raise "ERROR!!! Command: #{cmd} Expected Resp: #{resp_ok}, Got: #{response_str}" if resp_ok && response_str != resp_ok

        # Reformat positive integer frequency responses (e.g., from 'f')
        response_str = response_str.to_i.pretty_hz if response_str.match?(/^\d+$/) && response_str.to_i.positive?

        response_str
      rescue RuntimeError => e
        puts 'WARNING: RF Gain is not supported by the radio backend.' if e.message.include?('Command: L RF_GAIN')
        puts 'WARNING: Intermediate Gain is not supported by the radio backend.' if e.message.include?('Command: L IF_GAIN')
        puts 'WARNING: Baseband Gain is not supported by the radio backend.' if e.message.include?('Command: L BB_GAIN')

        raise e unless e.message.include?('Command: L RF_GAIN') ||
                       e.message.include?('Command: L IF_GAIN') ||
                       e.message.include?('Command: L BB_GAIN')
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # freq_obj = PWN::SDR::GQRX.init_freq(
      #   gqrx_sock: 'required - GQRX socket object returned from #connect method',
      #   freq: 'required - Frequency to set',
      #   demodulator_mode: 'optional - Demodulator mode (defaults to WFM)',
      #   bandwidth: 'optional - Bandwidth (defaults to 200_000)',
      #   squelch: 'optional - Squelch level to set (Defaults to current value)',
      #   decoder: 'optional - Decoder key (e.g., :gsm) to start live decoding (starts recording if provided)',
      #   record_dir: 'optional - Directory where GQRX saves recordings (required if decoder provided; defaults to /tmp/gqrx_recordings)',
      #   suppress_details: 'optional - Boolean to include extra frequency details in return hash (defaults to false)',
      #   keep_alive: 'optional - Boolean to keep GQRX connection alive after method completion (defaults to false)'
      # )
      public_class_method def self.init_freq(opts = {})
        gqrx_sock = opts[:gqrx_sock]
        freq = opts[:freq]
        valid_demodulator_modes = %i[
          AM
          AM_SYNC
          CW
          CWL
          CWU
          FM
          OFF
          LSB
          RAW
          USB
          WFM
          WFM_ST
          WFM_ST_OIRT
        ]
        demodulator_mode = opts[:demodulator_mode] ||= :WFM
        raise "ERROR: Invalid demodulator_mode '#{demodulator_mode}'. Valid modes: #{valid_demodulator_modes.join(', ')}" unless valid_demodulator_modes.include?(demodulator_mode.to_sym)

        bandwidth = opts[:bandwidth] ||= 200_000
        squelch = opts[:squelch]
        decoder = opts[:decoder]
        record_dir = opts[:record_dir] ||= '/tmp'
        suppress_details = opts[:suppress_details] || false
        keep_alive = opts[:keep_alive] || false

        raise "ERROR: record_dir '#{record_dir}' does not exist. Please create it or provide a valid path." if decoder && !Dir.exist?(record_dir)

        if squelch.is_a?(Float) && squelch >= -100.0 && squelch <= 0.0 && !keep_alive
          change_squelch_resp = gqrx_cmd(
            gqrx_sock: gqrx_sock,
            cmd: "L SQL #{squelch}",
            resp_ok: 'RPRT 0'
          )
        end

        change_freq_resp = gqrx_cmd(
          gqrx_sock: gqrx_sock,
          cmd: "F #{freq.to_s.raw_hz}",
          resp_ok: 'RPRT 0'
        )

        # Set demod mode and bandwidth (always, using defaults if not provided)
        unless keep_alive
          mode_str = demodulator_mode.to_s.upcase
          passband_hz = bandwidth.to_s.raw_hz
          gqrx_cmd(
            gqrx_sock: gqrx_sock,
            cmd: "M #{mode_str} #{passband_hz}",
            resp_ok: 'RPRT 0'
          )
        end

        # Get demodulator mode n passband
        demod_n_passband = gqrx_cmd(
          gqrx_sock: gqrx_sock,
          cmd: 'm'
        )

        # Get current frequency
        current_freq = gqrx_cmd(
          gqrx_sock: gqrx_sock,
          cmd: 'f'
        )

        freq_obj = {
          demodulator_mode: demodulator_mode,
          demod_mode_n_passband: demod_n_passband,
          freq: current_freq,
          bandwidth: bandwidth
        }

        unless suppress_details
          audio_gain_db = gqrx_cmd(
            gqrx_sock: gqrx_sock,
            cmd: 'l AF'
          ).to_f

          strength_db_float = gqrx_cmd(
            gqrx_sock: gqrx_sock,
            cmd: 'l STRENGTH'
          ).to_f
          strength_db = strength_db_float.round(1)

          current_squelch = gqrx_cmd(
            gqrx_sock: gqrx_sock,
            cmd: 'l SQL'
          ).to_f

          rf_gain = gqrx_cmd(
            gqrx_sock: gqrx_sock,
            cmd: 'l RF_GAIN'
          )

          if_gain = gqrx_cmd(
            gqrx_sock: gqrx_sock,
            cmd: 'l IF_GAIN'
          )

          bb_gain = gqrx_cmd(
            gqrx_sock: gqrx_sock,
            cmd: 'l BB_GAIN'
          )

          freq_obj[:audio_gain_db] = audio_gain_db
          freq_obj[:squelch_set] = current_squelch
          freq_obj[:rf_gain] = rf_gain
          freq_obj[:if_gain] = if_gain
          freq_obj[:bb_gain] = bb_gain
          freq_obj[:strength_db] = strength_db
        end

        # Start recording and decoding if decoder provided
        decoder_module = nil
        decoder_thread = nil
        record_path = nil
        if decoder
          # Resolve decoder module via case statement for extensibility
          case decoder
          when :gsm
            decoder_module = PWN::SDR::Decoder::GSM
          else
            raise "ERROR: Unknown decoder key: #{decoder}. Supported: :gsm"
          end

          # Ensure recording is off before starting
          record_status = gqrx_cmd(gqrx_sock: gqrx_sock, cmd: 'u RECORD')
          gqrx_cmd(gqrx_sock: gqrx_sock, cmd: 'U RECORD 0', resp_ok: 'RPRT 0') if record_status == '1'

          # Start recording
          gqrx_cmd(gqrx_sock: gqrx_sock, cmd: 'U RECORD 1', resp_ok: 'RPRT 0')

          # Prepare for decoder
          start_time = Time.now
          expected_filename = "gqrx_#{start_time.strftime('%Y%m%d_%H%M%S')}_#{current_freq_raw}.wav"
          record_path = File.join(record_dir, expected_filename)

          # Build partial gqrx_obj for decoder start
          freq_obj[:record_path] = record_path

          # Initialize and start decoder (module style: .start returns thread)
          freq_obj[:gqrx_sock] = gqrx_sock
          decoder_thread = decoder_module.start(freq_obj: freq_obj)
          freq_obj.delete(:gqrx_sock)

          freq_obj[:decoder] = decoder
          freq_obj[:decoder_module] = decoder_module
          freq_obj[:decoder_thread] = decoder_thread
          freq_obj[:record_path] = record_path
        end

        freq_obj
      rescue StandardError => e
        raise e
      ensure
        # Ensure decoder recording stops
        if decoder
          gqrx_cmd(
            gqrx_sock: gqrx_sock,
            cmd: 'U RECORD 0',
            resp_ok: 'RPRT 0'
          )
          decoder_module.stop(freq_obj: freq_obj)
        end
        disconnect(gqrx_sock: gqrx_sock) if gqrx_sock.is_a?(TCPSocket) && !keep_alive
      end

      # Supported Method Parameters::
      # scan_resp = PWN::SDR::GQRX.scan_range(
      #   gqrx_sock: 'required - GQRX socket object returned from #connect method',
      #   start_freq: 'required - Start frequency of scan range',
      #   target_freq: 'required - Target frequency of scan range',
      #   demodulator_mode: 'optional - Demodulator mode (e.g. WFM, AM, FM, USB, LSB, RAW, CW, RTTY / defaults to WFM)',
      #   bandwidth: 'optional - Bandwidth in Hz (Defaults to 200_000)',
      #   overlap_protection: 'optional - Boolean to enable/disable bandwidth overlap protection (defaults to false)',
      #   precision: 'optional - Frequency step precision (number of digits; defaults to 1)',
      #   lock_freq_duration: 'optional - Lock frequency duration in seconds (defaults to 0.04)',
      #   strength_lock: 'optional - Strength lock in dBFS (defaults to -70.0)',
      #   squelch: 'optional - Squelch level in dBFS (defaults to strength_lock - 3.0)',
      #   audio_gain_db: 'optional - Audio gain in dB (defaults to 1.0)',
      #   rf_gain: 'optional - RF gain (defaults to 0.0)',
      #   intermediate_gain: 'optional - Intermediate gain (defaults to 32.0)',
      #   baseband_gain: 'optional - Baseband gain (defaults to 10.0)',
      #   scan_log: 'optional - Path to save detected signals log (defaults to /tmp/pwn_sdr_gqrx_scan_<start_freq>-<target_freq>_<timestamp>.json)',
      #   location: 'optional - Location string to include in AI analysis (e.g., "New York, NY", 90210, GPS coords, etc.)'
      # )

      public_class_method def self.scan_range(opts = {})
        timestamp_start = Time.now.strftime('%Y-%m-%d %H:%M:%S%z')
        log_timestamp = Time.now.strftime('%Y-%m-%d')

        gqrx_sock = opts[:gqrx_sock]

        start_freq = opts[:start_freq]
        hz_start = start_freq.to_s.raw_hz

        target_freq = opts[:target_freq]
        hz_target = target_freq.to_s.raw_hz

        demodulator_mode = opts[:demodulator_mode]
        bandwidth = opts[:bandwidth] ||= 200_000
        overlap_protection = opts[:overlap_protection] || false
        precision = opts[:precision] ||= 1
        lock_freq_duration = opts[:lock_freq_duration] ||= 0.04
        strength_lock = opts[:strength_lock] ||= -70.0
        squelch = opts[:squelch] ||= (strength_lock - 3.0)
        scan_log = opts[:scan_log] ||= "/tmp/pwn_sdr_gqrx_scan_#{hz_start.pretty_hz}-#{hz_target.pretty_hz}_#{log_timestamp}.json"
        location = opts[:location] ||= 'United States'

        step_hz = 10**(precision - 1)
        step = hz_start > hz_target ? -step_hz : step_hz

        # Set squelch once for the scan
        change_squelch_resp = gqrx_cmd(
          gqrx_sock: gqrx_sock,
          cmd: "L SQL #{squelch}",
          resp_ok: 'RPRT 0'
        )

        # Set demodulator mode & passband once for the scan
        mode_str = demodulator_mode.to_s.upcase
        passband_hz = bandwidth.to_s.raw_hz
        gqrx_cmd(
          gqrx_sock: gqrx_sock,
          cmd: "M #{mode_str} #{passband_hz}",
          resp_ok: 'RPRT 0'
        )

        audio_gain_db = opts[:audio_gain_db] ||= 9.0
        audio_gain_db = audio_gain_db.to_f
        audio_gain_db_resp = PWN::SDR::GQRX.gqrx_cmd(
          gqrx_sock: gqrx_sock,
          cmd: "L AF #{audio_gain_db}",
          resp_ok: 'RPRT 0'
        )

        rf_gain = opts[:rf_gain] ||= 0.0
        rf_gain = rf_gain.to_f
        rf_gain_resp = PWN::SDR::GQRX.gqrx_cmd(
          gqrx_sock: gqrx_sock,
          cmd: "L RF_GAIN #{rf_gain}",
          resp_ok: 'RPRT 0'
        )

        intermediate_gain = opts[:intermediate_gain] ||= 32.0
        intermediate_gain = intermediate_gain.to_f
        intermediate_resp = PWN::SDR::GQRX.gqrx_cmd(
          gqrx_sock: gqrx_sock,
          cmd: "L IF_GAIN #{intermediate_gain}",
          resp_ok: 'RPRT 0'
        )

        baseband_gain = opts[:baseband_gain] ||= 10.0
        baseband_gain = baseband_gain.to_f
        baseband_resp = PWN::SDR::GQRX.gqrx_cmd(
          gqrx_sock: gqrx_sock,
          cmd: "L BB_GAIN #{baseband_gain}",
          resp_ok: 'RPRT 0'
        )

        prev_freq_obj = {}

        in_signal = false
        candidate_signals = []
        strength_history = []

        # Adaptive peak finder – trims weakest ends after each pass
        # Converges quickly to the true center of the bell curve
        find_best_peak = lambda do |opts = {}|
          beg_of_signal_hz = opts[:beg_of_signal_hz].to_s.raw_hz
          top_of_signal_hz = opts[:top_of_signal_hz].to_s.raw_hz
          end_of_signal_hz = top_of_signal_hz + step_hz

          # current_hz = gqrx_cmd(gqrx_sock: gqrx_sock, cmd: 'f').to_s.raw_hz
          # puts "Current Frequency: #{current_hz.pretty_hz}"
          puts "Signal Began: #{beg_of_signal_hz.pretty_hz}"
          puts "Signal Appeared to Peak at: #{top_of_signal_hz.pretty_hz}"
          puts "Calculated Signal End: #{end_of_signal_hz.pretty_hz}"
          # steps_between_beg_n_end = ((end_of_signal_hz - beg_of_signal_hz) / step_hz).abs
          # puts steps_between_beg_n_end.inspect

          samples = []
          prev_best_sample = nil
          consecutive_best = 0
          direction_up = true

          pass_count = 0
          infinite_loop_safeguard = false
          while true
            pass_count += 1

            # Safeguard against infinite loop
            infinite_loop_safeguard = true if pass_count >= 100
            puts 'WARNING: Infinite loop safeguard triggered in find_best_peak!' if infinite_loop_safeguard
            break if infinite_loop_safeguard

            direction_up = !direction_up
            start_hz_direction = direction_up ? beg_of_signal_hz : end_of_signal_hz
            end_hz_direction = direction_up ? end_of_signal_hz : beg_of_signal_hz
            step_hz_direction = direction_up ? step_hz : -step_hz

            start_hz_direction.step(by: step_hz_direction, to: end_hz_direction) do |hz|
              print '>' if direction_up
              print '<' unless direction_up
              gqrx_cmd(gqrx_sock: gqrx_sock, cmd: "F #{hz}")
              sleep lock_freq_duration
              strength_db_float = gqrx_cmd(gqrx_sock: gqrx_sock, cmd: 'l STRENGTH').to_f
              strength_db = strength_db_float.round(1)
              samples.push({ hz: hz, strength_db: strength_db })

              # current_hz = gqrx_cmd(gqrx_sock: gqrx_sock, cmd: 'f').to_s.raw_hz
              # puts "Sampled Frequency: #{current_hz.pretty_hz} => Strength: #{strength_db} dBFS"
            end

            # Compute fresh averaged_samples from all cumulative samples
            averaged_samples = []
            samples.group_by { |s| s[:hz] }.each do |hz, grouped_samples|
              avg_strength = (grouped_samples.map { |s| s[:strength_db] }.sum / grouped_samples.size).round(1)
              averaged_samples.push({ hz: hz, strength_db: avg_strength })
            end

            # Sort by hz for trimming
            averaged_samples.sort_by! { |s| s[:hz] }

            # Find current best for trimming threshold
            best_sample = averaged_samples.max_by { |s| s[:strength_db] }
            max_strength = best_sample[:strength_db]

            # trim_db_threshold should bet average difference between
            # samples near peak, floor to nearest 0.1 dB
            trim_db_threshold = samples.map { |s| (s[:strength_db] - max_strength).abs }.sum / samples.size
            trim_db_threshold = (trim_db_threshold * 10).floor / 10.0
            puts "\nPass #{pass_count}: Calculated trim_db_threshold: #{trim_db_threshold} dB"
            # Adaptive trim: Remove weak ends (implements the comment about trimming weakest ends)
            averaged_samples.shift while !averaged_samples.empty? && averaged_samples.first[:strength_db] < max_strength - trim_db_threshold
            averaged_samples.pop while !averaged_samples.empty? && averaged_samples.last[:strength_db] < max_strength - trim_db_threshold

            # Update range for next pass if trimmed
            unless averaged_samples.empty?
              beg_of_signal_hz = averaged_samples.first[:hz]
              end_of_signal_hz = averaged_samples.last[:hz]
            end

            # Recalculate best_sample after trim
            best_sample = averaged_samples.max_by { |s| s[:strength_db] }

            # Check for improvement
            if best_sample == prev_best_sample
              consecutive_best += 1
            else
              consecutive_best = 0
            end

            # Dup to avoid reference issues
            prev_best_sample = best_sample.dup

            puts "Pass #{pass_count}: Best #{best_sample[:hz].pretty_hz} => #{best_sample[:strength_db]} dBFS, consecutive best count: #{consecutive_best}"

            # Break if no improvement in 3 consecutive passes or theres only one sample left
            break if consecutive_best.positive? || averaged_samples.size == 1
          end

          best_sample
        end

        # Begin scanning range
        puts "INFO: Scanning from #{hz_start.pretty_hz} to #{hz_target.pretty_hz} in steps of #{step.abs.pretty_hz} Hz.\nIf scans are slow and/or you're experiencing false positives/negatives, consider adjusting:\n1. The SDR's sample rate in GQRX\n\s\s- Click on `Configure I/O devices`.\n\s\s- A lower `Input rate` value seems counter-intuitive but works well (e.g. ADALM PLUTO ~ 1000000).\n2. Adjust the :strength_lock parameter.\n3. Adjust the :lock_freq_duration parameter.\n4. Adjust the :precision parameter.\n5. Disable AI introspection in PWN::Env\nHappy scanning!\n\n"

        signals_arr = []
        # Format timestamp_start for filename
        hz_start.step(by: step, to: hz_target) do |hz|
          gqrx_cmd(gqrx_sock: gqrx_sock, cmd: "F #{hz}")
          sleep lock_freq_duration
          strength_db_float = gqrx_cmd(gqrx_sock: gqrx_sock, cmd: 'l STRENGTH').to_f
          strength_db = strength_db_float.round(1)
          prev_strength_db = strength_history.last || -Float::INFINITY

          if strength_db >= strength_lock && strength_db > prev_strength_db
            in_signal = true
            strength_history.push(strength_db)
            strength_history.shift if strength_history.size > 5
            current_strength = (strength_history.sum / strength_history.size).round(1)

            print '.'
            puts "#{hz.pretty_hz} => #{strength_db}"

            candidate = { hz: hz, freq: hz.pretty_hz, strength: current_strength }
            candidate_signals.push(candidate)
          else
            if in_signal
              beg_of_signal_hz = candidate_signals.map { |s| s[:hz] }.min
              # Previous max step_hz was actually the top of the signal
              top_of_signal_hz = candidate_signals.map { |s| s[:hz] }.max - step_hz

              skip_signal = false
              prev_freq = prev_freq_obj[:freq].to_s.raw_hz
              distance_from_prev_detected_freq_hz = (beg_of_signal_hz - prev_freq).abs
              half_bandwidth = (bandwidth / 2).to_i
              skip_signal = true if distance_from_prev_detected_freq_hz < half_bandwidth && overlap_protection
              puts "Prev Dect Freq: #{prev_freq} | New Freq Edge: #{beg_of_signal_hz} | Distance from Prev Dect Freq: #{distance_from_prev_detected_freq_hz} Hz | Step Hz: #{step_hz} | Bandwidth: #{bandwidth} Hz | Half Bandwidth: #{half_bandwidth} Hz | Overlap Protection? #{overlap_protection} | Skip Signal? #{skip_signal}"
              next if skip_signal

              best_peak = find_best_peak.call(
                beg_of_signal_hz: beg_of_signal_hz,
                top_of_signal_hz: top_of_signal_hz
              )

              if best_peak[:hz] && best_peak[:strength_db] > strength_lock
                prev_freq_obj = init_freq(
                  gqrx_sock: gqrx_sock,
                  freq: best_peak[:hz],
                  demodulator_mode: demodulator_mode,
                  bandwidth: bandwidth,
                  squelch: squelch,
                  suppress_details: true,
                  keep_alive: true
                )
                prev_freq_obj[:lock_freq_duration] = lock_freq_duration
                prev_freq_obj[:strength_lock] = strength_lock

                system_role_content = "Analyze signal data captured by a software-defined-radio using GQRX at the following location: #{location}. Respond with just FCC information about the transmission if available.  If the frequency is unlicensed or not found in FCC records, state that clearly.  Be clear and concise in your analysis."
                ai_analysis = PWN::AI::Introspection.reflect_on(
                  request: prev_freq_obj.to_json,
                  system_role_content: system_role_content,
                  suppress_pii_warning: true
                )
                prev_freq_obj[:ai_analysis] = ai_analysis unless ai_analysis.nil?
                puts "\n**** Detected Signal ****"
                puts JSON.pretty_generate(prev_freq_obj)
                signals_arr.push(prev_freq_obj)
                log_signals(
                  signals_arr: signals_arr,
                  timestamp_start: timestamp_start,
                  scan_log: scan_log
                )
              end
              candidate_signals.clear
              sleep lock_freq_duration
            end
            in_signal = false
            strength_history = []
          end
        end

        log_signals(
          signals_arr: signals_arr,
          timestamp_start: timestamp_start,
          scan_log: scan_log
        )
      rescue StandardError => e
        raise e
      ensure
        disconnect(gqrx_sock: gqrx_sock)
      end

      # Supported Method Parameters::
      # PWN::SDR::GQRX.analyze_scan(
      #   scan_resp: 'required - Scan response hash returned from #scan_range method',
      #   target: 'optional - GQRX target IP address (defaults to 127.0.0.1)',
      #   port: 'optional - GQRX target port (defaults to 7356)'
      # )
      public_class_method def self.analyze_scan(opts = {})
        scan_resp = opts[:scan_resp]
        raise 'ERROR: scan_resp is required.' if scan_resp.nil? || scan_resp[:signals].nil? || scan_resp[:signals].empty?

        target = opts[:target]
        port = opts[:port]
        gqrx_sock = connect(
          target: target,
          port: port
        )

        scan_resp[:signals].each do |signal|
          freq_obj = { gqrx_sock: gqrx_sock, keep_alive: true }
          freq_obj = signal.merge(freq_obj)
          freq_obj = init_freq(freq_obj)
          # Redact gqrx_sock from output
          freq_obj.delete(:gqrx_sock)
          puts JSON.pretty_generate(freq_obj)
          print 'Press [ENTER] to continue...'
          gets
          puts "\n" * 3
        end
      rescue StandardError => e
        raise e
      ensure
        disconnect(gqrx_sock: gqrx_sock)
      end

      # Supported Method Parameters::
      # PWN::SDR::GQRX.analyze_log(
      #   scan_log: 'required - Path to signals log file',
      #   target: 'optional - GQRX target IP address (defaults to 127.0.0.1)',
      #   port: 'optional - GQRX target port (defaults to 7356)'
      # )
      public_class_method def self.analyze_log(opts = {})
        scan_log = opts[:scan_log]
        raise 'ERROR: scan_log path is required.' unless File.exist?(scan_log)

        scan_resp = JSON.parse(File.read(scan_log), symbolize_names: true)
        raise 'ERROR: No signals found in log.' if scan_resp[:signals].nil? || scan_resp[:signals].empty?

        target = opts[:target]
        port = opts[:port]

        analyze_scan(
          scan_resp: scan_resp,
          target: target,
          port: port
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::SDR::GQRX.disconnect(
      #   gqrx_sock: 'required - GQRX socket object returned from #connect method'
      # )
      public_class_method def self.disconnect(opts = {})
        gqrx_sock = opts[:gqrx_sock]

        PWN::Plugins::Sock.disconnect(sock_obj: gqrx_sock)
      rescue StandardError => e
        raise e
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
          gqrx_sock = #{self}.connect(
            target: 'optional - GQRX target IP address (defaults to 127.0.0.1)',
            port: 'optional - GQRX target port (defaults to 7356)'
          )

          gqrx_resp = #{self}.gqrx_cmd(
            gqrx_sock: 'required - GQRX socket object returned from #connect method',
            cmd: 'required - GQRX command to execute',
            resp_ok: 'optional - Expected response from GQRX to indicate success'
          )

          freq_obj = #{self}.init_freq(
            gqrx_sock: 'required - GQRX socket object returned from #connect method',
            freq: 'required - Frequency to set',
            demodulator_mode: 'optional - Demodulator mode (defaults to WFM)',
            bandwidth: 'optional - Bandwidth (defaults to 200_000)',
            decoder: 'optional - Decoder key (e.g., :gsm) to start live decoding (starts recording if provided)',
            record_dir: 'optional - Directory where GQRX saves recordings (required if decoder provided; defaults to /tmp/gqrx_recordings)',
            suppress_details: 'optional - Boolean to include extra frequency details in return hash (defaults to false)',
            keep_alive: 'optional - Boolean to keep GQRX connection alive after method completion (defaults to false)'
          )

          scan_resp = #{self}.scan_range(
            gqrx_sock: 'required - GQRX socket object returned from #connect method',
            start_freq: 'required - Starting frequency',
            target_freq: 'required - Target frequency',
            demodulator_mode: 'optional - Demodulator mode (e.g. WFM, AM, FM, USB, LSB, RAW, CW, RTTY / defaults to WFM)',
            bandwidth: 'optional - Bandwidth in Hz (Defaults to 200_000)',
            overlap_protection: 'optional - Boolean to enable/disable bandwidth overlap protection (defaults to false)',
            precision: 'optional - Precision (Defaults to 1)',
            lock_freq_duration: 'optional - Lock frequency duration in seconds (defaults to 0.04)',
            strength_lock: 'optional - Strength lock (defaults to -70.0)',
            squelch: 'optional - Squelch level (defaults to strength_lock - 3.0)',
            scan_log: 'optional - Path to save detected signals log (defaults to /tmp/pwn_sdr_gqrx_scan_<start_freq>-<target_freq>_<timestamp>.json)',
            location: 'optional - Location string to include in AI analysis (e.g., \"New York, NY\", 90210, GPS coords, etc.)'
          )

          #{self}.analyze_scan(
            scan_resp: 'required - Scan response object from #scan_range method',
            target: 'optional - GQRX target IP address (defaults to 127.0.0.1)',
            port: 'optional - GQRX target port (defaults to 7356)'
          )

          #{self}.analyze_log(
            scan_log: 'required - Path to signals log file',
            target: 'optional - GQRX target IP address (defaults to 127.0.0.1)',
            port: 'optional - GQRX target port (defaults to 7356)'
          )

          #{self}.disconnect(
            gqrx_sock: 'required - GQRX socket object returned from #connect method'
          )

          #{self}.authors
        "
      end
    end
  end
end
