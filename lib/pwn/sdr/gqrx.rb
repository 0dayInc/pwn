# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'time'

module PWN
  module SDR
    # This plugin interacts with the remote control interface of GQRX.
    module GQRX
      # Supported Method Parameters::
      # gqrx_resp = PWN::SDR::GQRX.cmd(
      #   gqrx_sock: 'required - GQRX socket object returned from #connect method',
      #   cmd: 'required - GQRX command to execute',
      #   resp_ok: 'optional - Expected response from GQRX to indicate success'
      # )

      public_class_method def self.cmd(opts = {})
        gqrx_sock = opts[:gqrx_sock]
        cmd = opts[:cmd]
        resp_ok = opts[:resp_ok]

        # Most Recent GQRX Command Set:
        # https://raw.githubusercontent.com/gqrx-sdr/gqrx/master/resources/remote-control.txt
        # Remote control protocol.
        #
        # Supported commands:
        #  f
        #     Get frequency [Hz]
        #  F <frequency>
        #     Set frequency [Hz]
        #  m
        #     Get demodulator mode and passband
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
        #  p RDS_PS_NAME
        #     Get the RDS Program Service (PS) name
        #  p RDS_RADIOTEXT
        #     Get the RDS RadioText message
        #  u RECORD
        #     Get status of audio recorder
        #  U RECORD <status>
        #     Set status of audio recorder to <status>
        #  u IQRECORD
        #     Get status of IQ recorder
        #  U IQRECORD <status>
        #     Set status of IQ recorder to <status>
        #  u DSP
        #     Get DSP (SDR receiver) status
        #  U DSP <status>
        #     Set DSP (SDR receiver) status to <status>
        #  u RDS
        #     Get RDS decoder status.  Only functions in WFM mode.
        #  U RDS <status>
        #     Set RDS decoder to <status>.  Only functions in WFM mode.
        #  u MUTE
        #     Get audio mute status
        #  U MUTE <status>
        #     Set audio mute to <status>
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
            break if gqrx_sock.wait_readable(0.0001).nil?

            response.push(gqrx_sock.readline.chomp)
          end
        end

        raise "No response for command: #{cmd}" if response.empty?

        response_str = response.length == 1 ? response.first : response.join(' ')

        raise "ERROR!!! Command: #{cmd} Expected Resp: #{resp_ok}, Got: #{response_str}" if resp_ok && response_str != resp_ok

        # Reformat positive integer frequency responses (e.g., from 'f')
        response_str = PWN::SDR.hz_to_s(freq: response_str) if response_str.match?(/^\d+$/) && response_str.to_i.positive?

        response_str
      rescue RuntimeError => e
        response_str = 'Function not supported by this radio backend.' if e.message.include?('RF_GAIN') || e.message.include?('IF_GAIN') || e.message.include?('BB_GAIN')

        raise e unless e.message.include?('RF_GAIN') ||
                       e.message.include?('IF_GAIN') ||
                       e.message.include?('BB_GAIN')
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # noise_floor = PWN::SDR::GQRX.measure_noise_floor(
      #   gqrx_sock: 'required - GQRX socket object returned from #connect method',
      #   freq: 'required - Frequency to measure noise floor',
      #   precision: 'required - Frequency step precision',
      #   step_hz_direction: 'required - Frequency step in Hz direction for noise floor measurement'
      # )
      private_class_method def self.measure_noise_floor(opts = {})
        gqrx_sock = opts[:gqrx_sock]
        freq = opts[:freq]
        precision = opts[:precision]
        step_hz_direction = opts[:step_hz_direction]
        freqs_to_sample = 10
        samples_per_freq = 100

        # Quickly sample multiple frequencies around target frequency
        start_hz = PWN::SDR.hz_to_i(freq: freq)
        hz = start_hz
        # puts step_hz_direction.class; gets
        target_hz = start_hz + (step_hz_direction * freqs_to_sample)
        noise_floors = []
        puts "*** Sampling #{freqs_to_sample} Noise Floor to Dynamically Determine Squelch Level"
        while (step_hz_direction.positive? && hz <= target_hz) || (step_hz_direction.negative? && hz >= target_hz)
          tune_to(gqrx_sock: gqrx_sock, hz: hz)
          print '.'

          strengths = []
          samples_per_freq.times do
            strength_db = cmd(gqrx_sock: gqrx_sock, cmd: 'l STRENGTH').to_f
            strengths << strength_db
            sleep 0.001
          end
          freq_noise_floor = strengths.sum / strengths.size
          noise_floors.push(freq_noise_floor)
          hz += step_hz_direction
        end

        noise_floor = noise_floors.min
        noise_floor.round(1)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # strength_db = PWN::SDR::GQRX.measure_signal_strength(
      #   gqrx_sock: 'required - GQRX socket object returned from #connect method',
      #   freq: 'required - Frequency to measure signal strength',
      #   precision: 'required - Frequency step precision',
      #   strength_lock: 'optional - Strength lock in dBFS to determine signal edges (defaults to -70.0)',
      #   phase: 'optional - Phase of measurement for logging purposes (defaults to :find_candidates)'
      # )
      private_class_method def self.measure_signal_strength(opts = {})
        gqrx_sock = opts[:gqrx_sock]
        freq = PWN::SDR.hz_to_i(freq: opts[:freq])
        freq = PWN::SDR.hz_to_s(freq: freq)
        precision = opts[:precision]

        strength_lock = opts[:strength_lock] ||= -70.0
        phase = opts[:phase] ||= :find_candidates

        attempts = 0
        strength_db = -99.9
        prev_strength_db = -99.9
        distance_between_unique_samples = 0.0
        samples = []
        unique_samples = []
        strength_measured = false

        # Calculate max attempts based on precision, so if precision is 6 max attempts == 600
        # This helps as precision decreases (i.e. we're measuring more frequencies) it doesn't
        # take too long to measure strength at each frequency
        case precision
        when 1..5
          max_attempts = precision * 10
        when 6..10
          max_attempts = precision * 100
        else
          max_attempts = 1000
        end

        loop do
          attempts += 1
          strength_db = cmd(gqrx_sock: gqrx_sock, cmd: 'l STRENGTH').to_f

          # Fast approach while still maintaining decent accuracy
          samples.push(strength_db)
          unique_samples = samples.uniq
          if unique_samples.length > 1
            prev_strength_db = unique_samples[-2]
            distance_between_unique_samples = (strength_db - prev_strength_db).abs.round(2)
            strength_measured = true if distance_between_unique_samples.positive? && strength_lock > strength_db
          end
          strength_measured = true if (distance_between_unique_samples.positive? && distance_between_unique_samples < 5) || attempts >= max_attempts

          break if strength_measured

          # Sleep a tiny bit to allow strength_db values to fluctuate
          sleep 0.0001
        end
        # Uncomment for debugging strength measurement attempts
        # which translates to speed and accuracy refinement
        puts "\tStrength Measurement Attempts: #{attempts} | Freq: #{freq} | Phase: #{phase}"
        puts "\tUnique Samples: #{unique_samples} | dbFS Distance Unique Samples: #{distance_between_unique_samples}"

        strength_db.round(1)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # tune_resp = PWN::SDR::GQRX.tune_to(
      #   gqrx_sock: 'required - GQRX socket object returned from #connect method',
      #   hz: 'required - Frequency to tune to'
      # )
      private_class_method def self.tune_to(opts = {})
        gqrx_sock = opts[:gqrx_sock]
        hz = PWN::SDR.hz_to_i(freq: opts[:hz])

        current_freq = 0
        attempts = 0
        loop do
          attempts += 1
          cmd(
            gqrx_sock: gqrx_sock,
            cmd: "F #{hz}",
            resp_ok: 'RPRT 0'
          )

          current_freq = cmd(
            gqrx_sock: gqrx_sock,
            cmd: 'f'
          )

          break if PWN::SDR.hz_to_i(freq: current_freq) == hz
        end
        # puts "Tuned to #{current_freq} in #{attempts} attempt(s)."
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # candidate_signals = PWN::SDR::GQRX.edge_detection(
      #   gqrx_sock: 'required - GQRX socket object returned from #connect method',
      #   hz: 'required - Frequency to start edge detection from',
      #   precision: 'required - Frequency step precision',
      #   step_hz: 'required - Frequency step in Hz for edge detection',
      #   strength_lock: 'required - Strength lock in dBFS to determine signal edges'
      # )
      private_class_method def self.edge_detection(opts = {})
        gqrx_sock = opts[:gqrx_sock]
        hz = opts[:hz]
        precision = opts[:precision]
        step_hz = opts[:step_hz]
        strength_lock = opts[:strength_lock]
        left_candidate_signals = []
        right_candidate_signals = []
        candidate_signals = []

        original_hz = hz
        strength_db = 99.9
        puts '*** Edge Detection: Locating Beginning of Signal...'
        while strength_db >= strength_lock
          tune_to(gqrx_sock: gqrx_sock, hz: hz)
          strength_db = measure_signal_strength(
            gqrx_sock: gqrx_sock,
            freq: hz,
            precision: precision,
            strength_lock: strength_lock,
            phase: :edge_left
          )
          candidate = {
            hz: PWN::SDR.hz_to_i(freq: hz),
            freq: PWN::SDR.hz_to_s(freq: hz),
            strength: strength_db,
            edge: :left
          }
          left_candidate_signals.push(candidate)
          hz -= step_hz
        end
        left_candidate_signals.uniq! { |s| s[:hz] }
        left_candidate_signals.sort_by! { |s| s[:hz] }

        # Now scan forwards to find the end of the signal
        # The end of the signal is where the strength drops below strength_lock
        hz = original_hz

        strength_db = 99.9
        puts '*** Edge Detection: Locating End of Signal...'
        while strength_db >= strength_lock
          tune_to(gqrx_sock: gqrx_sock, hz: hz)
          strength_db = measure_signal_strength(
            gqrx_sock: gqrx_sock,
            freq: hz,
            precision: precision,
            strength_lock: strength_lock,
            phase: :edge_right
          )
          candidate = {
            hz: PWN::SDR.hz_to_i(freq: hz),
            freq: PWN::SDR.hz_to_s(freq: hz),
            strength: strength_db,
            edge: :right
          }
          right_candidate_signals.push(candidate)
          hz += step_hz
        end
        # Update candidate signals to remove duplicates and sort by hz
        right_candidate_signals.uniq! { |s| s[:hz] }
        right_candidate_signals.sort_by! { |s| s[:hz] }

        candidate_signals = left_candidate_signals + right_candidate_signals
        candidate_signals.uniq! { |s| s[:hz] }
        candidate_signals.sort_by! { |s| s[:hz] }
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # duration = PWN::SDR::GQRX.duration_between(
      #   timestamp_start: 'required - Start timestamp',
      #   timestamp_end: 'required - End timestamp'
      # )
      private_class_method def self.duration_between(opts = {})
        timestamp_start = opts[:timestamp_start]
        timestamp_end = opts[:timestamp_end]
        raise 'ERROR: timestamp_start && timestamp_end must are required parameters.' if timestamp_start.nil? || timestamp_end.nil?

        duration_secs = Time.parse(timestamp_end).to_f - Time.parse(timestamp_start).to_f

        # Convert duration seconds to hours minutes seconds
        hours = (duration_secs / 3600).to_i
        minutes = ((duration_secs % 3600) / 60).to_i
        seconds = (duration_secs % 60).to_i
        format('%<hrs>02d:%<mins>02d:%<secs>02d', hrs: hours, mins: minutes, secs: seconds)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # scan_resp = PWN::SDR::GQRX.log_signals(
      #   signals_detected: 'required - Array of detected signals',
      #   timestamp_start: 'required - Scan start timestamp',
      #   scan_log: 'required - Path to save detected signals log',
      #   iteration_metrics: 'optional - Hash of iteration metrics per range iteration'
      # )
      private_class_method def self.log_signals(opts = {})
        signals_detected = opts[:signals_detected]
        timestamp_start = opts[:timestamp_start]
        scan_log = opts[:scan_log]

        existing_scan_resp = JSON.parse(File.read(scan_log), symbolize_names: true) if File.exist?(scan_log)

        # BUG: iteration_metrics not being properly initialized from existing log
        iteration_metrics = opts[:iteration_metrics]
        iteration_metrics ||= existing_scan_resp[:iteration_metrics] if existing_scan_resp.is_a?(Hash) && existing_scan_resp.key?(:iteration_metrics) && existing_scan_resp[:iteration_metrics].is_a?(Array) && !existing_scan_resp[:iteration_metrics].empty?
        iteration_metrics ||= []

        signals = signals_detected.sort_by { |s| PWN::SDR.hz_to_i(freq: s[:freq]) }
        # Unique signals by frequency
        signals.uniq! { |s| PWN::SDR.hz_to_i(freq: s[:freq]) }

        timestamp_end = Time.now.strftime('%Y-%m-%d %H:%M:%S%z')
        duration = duration_between(timestamp_start: timestamp_start, timestamp_end: timestamp_end)

        # TODO: Implement iteration_metrics logging per range iteration
        scan_resp = {
          signals: signals,
          total: signals.length,
          timestamp_start: timestamp_start,
          timestamp_end: timestamp_end,
          duration: duration,
          iteration_metrics: iteration_metrics
        }

        File.write(
          scan_log,
          JSON.pretty_generate(scan_resp)
        )

        # Append a new line at end of file to avoid readline
        # issues requiring tput reset in terminal
        File.write(scan_log, "\n", mode: 'a')

        scan_resp
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # best_peak = PWN::SDR::GQRX.find_best_peak(
      #   gqrx_sock: 'required - GQRX socket object returned from #connect method',
      #   candidate_signals: 'required - Array of candidate signals from edge_detection',
      #   step_hz: 'required - Frequency step in Hz for peak finding',
      #   strength_lock: 'required - Strength lock in dBFS to determine signal edges'
      # )
      private_class_method def self.find_best_peak(opts = {})
        gqrx_sock = opts[:gqrx_sock]
        candidate_signals = opts[:candidate_signals]
        precision = opts[:precision]
        step_hz = opts[:step_hz]
        strength_lock = opts[:strength_lock]

        beg_of_signal_hz = PWN::SDR.hz_to_i(freq: candidate_signals.first[:hz])
        end_of_signal_hz = PWN::SDR.hz_to_i(freq: candidate_signals.last[:hz])

        puts "*** Analyzing Best Peak in Frequency Range: #{PWN::SDR.hz_to_s(freq: beg_of_signal_hz)} Hz - #{PWN::SDR.hz_to_s(freq: end_of_signal_hz)} Hz"
        # puts JSON.pretty_generate(candidate_signals)

        samples = []
        prev_best_sample = {}
        consecutive_best = 0
        direction_up = true

        pass_count = 0
        infinite_loop_safeguard = false
        # loop do
        # Why doesn't this work with loop do ???
        while true
          pass_count += 1

          # Safeguard against infinite loop
          # infinite_loop_safeguard = true if pass_count >= 100
          # infinite_loop_safeguard = true if pass_count >= 10
          # puts 'WARNING: Infinite loop safeguard triggered in find_best_peak!' if infinite_loop_safeguard
          # break if infinite_loop_safeguard

          direction_up = !direction_up
          start_hz_direction = direction_up ? beg_of_signal_hz : end_of_signal_hz
          end_hz_direction = direction_up ? end_of_signal_hz : beg_of_signal_hz
          step_hz_direction = direction_up ? step_hz : -step_hz

          start_hz_direction.step(by: step_hz_direction, to: end_hz_direction) do |hz|
            print '>' if direction_up
            print '<' unless direction_up
            tune_to(gqrx_sock: gqrx_sock, hz: hz)
            strength_db = measure_signal_strength(
              gqrx_sock: gqrx_sock,
              freq: hz,
              precision: precision,
              strength_lock: strength_lock,
              phase: :find_best_peak
            )
            samples.push({ hz: hz, strength_db: strength_db })
          end

          # Compute fresh averaged_samples from all cumulative samples
          averaged_samples = []
          samples.group_by { |s| s[:hz] }.each do |hz, grouped_samples|
            avg_strength = (grouped_samples.map { |s| s[:strength_db] }.sum / grouped_samples.size)
            averaged_samples.push({ hz: hz, strength_db: avg_strength })
          end

          # Sort by hz for trimming
          averaged_samples.sort_by! { |s| s[:hz] }

          # Find current best for trimming threshold
          best_sample = averaged_samples.max_by { |s| s[:strength_db] }
          max_strength = best_sample[:strength_db].round(1)

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
          next unless best_sample.is_a?(Hash)

          # Check for improvement
          if best_sample[:hz] == prev_best_sample[:hz]
            consecutive_best += 1
          else
            consecutive_best = 0
          end

          # Dup to avoid reference issues
          prev_best_sample = best_sample.dup

          puts "Pass #{pass_count}: Best #{PWN::SDR.hz_to_s(freq: best_sample[:hz])} => #{best_sample[:strength_db]} dBFS, consecutive best count: #{consecutive_best}"

          # Break if we have a stable best sample or only one sample remains
          break if consecutive_best.positive? || averaged_samples.length == 1
        end

        best_sample
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
      # freq_obj = PWN::SDR::GQRX.init_freq(
      #   gqrx_sock: 'required - GQRX socket object returned from #connect method',
      #   freq: 'required - Frequency to set',
      #   demodulator_mode: 'optional - Demodulator mode (defaults to WFM)',
      #   bandwidth: 'optional - Bandwidth (defaults to "200.000")',
      #   squelch: 'optional - Squelch level to set (Defaults to current value)',
      #   decoder: 'optional - Decoder key (e.g., :gsm) to start live decoding (starts recording if provided)',
      #   udp_ip: 'optional - UDP IP address for decoder module (defaults to 127.0.0.1)',
      #   udp_port: 'optional - UDP port for decoder module (defaults to 7355)',
      #   suppress_details: 'optional - Boolean to include extra frequency details in return hash (defaults to false)',
      #   keep_alive: 'optional - Boolean to keep GQRX connection alive after method completion (defaults to false)'
      # )
      public_class_method def self.init_freq(opts = {})
        gqrx_sock = opts[:gqrx_sock]
        freq = opts[:freq]
        precision = opts[:precision] ||= 6
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

        bandwidth = opts[:bandwidth] ||= '200.000'
        squelch = opts[:squelch]
        decoder = opts[:decoder]
        udp_ip = opts[:udp_ip]
        udp_port = opts[:udp_port]
        suppress_details = opts[:suppress_details] || false
        keep_alive = opts[:keep_alive] || false

        unless keep_alive
          squelch = cmd(gqrx_sock: gqrx_sock, cmd: 'l SQL').to_f if squelch.nil?
          change_squelch_resp = cmd(
            gqrx_sock: gqrx_sock,
            cmd: "L SQL #{squelch}",
            resp_ok: 'RPRT 0'
          )

          mode_str = demodulator_mode.to_s.upcase
          passband_hz = PWN::SDR.hz_to_i(freq: bandwidth)
          cmd(
            gqrx_sock: gqrx_sock,
            cmd: "M #{mode_str} #{passband_hz}",
            resp_ok: 'RPRT 0'
          )
        end

        tune_to(gqrx_sock: gqrx_sock, hz: freq)
        strength_db = measure_signal_strength(
          gqrx_sock: gqrx_sock,
          freq: freq,
          precision: precision,
          phase: :init_freq
        )

        freq_obj = {
          freq: freq,
          demodulator_mode: demodulator_mode,
          bandwidth: bandwidth,
          strength_db: strength_db,
          decoder: decoder,
          squelch: squelch
        }

        unless suppress_details
          demod_n_passband = cmd(
            gqrx_sock: gqrx_sock,
            cmd: 'm'
          )

          audio_gain_db = cmd(
            gqrx_sock: gqrx_sock,
            cmd: 'l AF'
          ).to_f

          squelch = cmd(
            gqrx_sock: gqrx_sock,
            cmd: 'l SQL'
          ).to_f

          rf_gain = cmd(
            gqrx_sock: gqrx_sock,
            cmd: 'l RF_GAIN'
          )

          if_gain = cmd(
            gqrx_sock: gqrx_sock,
            cmd: 'l IF_GAIN'
          )

          bb_gain = cmd(
            gqrx_sock: gqrx_sock,
            cmd: 'l BB_GAIN'
          )

          freq_obj[:audio_gain_db] = audio_gain_db
          freq_obj[:demod_mode_n_passband] = demod_n_passband
          freq_obj[:bb_gain] = bb_gain
          freq_obj[:if_gain] = if_gain
          freq_obj[:rf_gain] = rf_gain
          freq_obj[:squelch] = squelch

          # Start recording and decoding if decoder provided
          if decoder
            decoder = decoder.to_s.to_sym
            decoder_module = nil

            # Resolve decoder module via case statement for extensibility
            case decoder
            when :flex
              decoder_module = PWN::SDR::Decoder::Flex
            when :gsm
              decoder_module = PWN::SDR::Decoder::GSM
            when :pocsag
              decoder_module = PWN::SDR::Decoder::POCSAG
            when :rds
              decoder_module = PWN::SDR::Decoder::RDS
            else
              raise "ERROR: Unknown decoder key: #{decoder}. Supported: :gsm"
            end

            # Initialize and start decoder (module style: .start returns thread)
            freq_obj[:gqrx_sock] = gqrx_sock
            freq_obj[:udp_ip] = udp_ip
            freq_obj[:udp_port] = udp_port
            freq_obj[:decoder_module] = decoder_module
            decoder_module.decode(freq_obj: freq_obj)
          end
        end

        freq_obj
      rescue StandardError => e
        raise e
      ensure
        disconnect(gqrx_sock: gqrx_sock) if gqrx_sock.is_a?(TCPSocket) && !keep_alive
      end

      # Supported Method Parameters::
      # scan_resp = PWN::SDR::GQRX.scan_range(
      #   gqrx_sock: 'required - GQRX socket object returned from #connect method',
      #   ranges: 'required - Array of Hash objects with :start_freq and :target_freq keys defining scan ranges',
      #   demodulator_mode: 'optional - Demodulator mode (e.g. WFM, AM, FM, USB, LSB, RAW, CW, RTTY / defaults to WFM)',
      #   bandwidth: 'optional - Bandwidth in Hz (Defaults to "200.000")',
      #   precision: 'optional - Frequency step precision (number of digits; defaults to 1)',
      #   strength_lock: 'optional - Strength lock in dBFS (defaults to -70.0)',
      #   squelch: 'optional - Squelch level in dBFS (defaults to strength_lock - 3.0)',
      #   audio_gain_db: 'optional - Audio gain in dB (defaults to 0.0)',
      #   rf_gain: 'optional - RF gain (defaults to 0.0)',
      #   intermediate_gain: 'optional - Intermediate gain (defaults to 32.0)',
      #   baseband_gain: 'optional - Baseband gain (defaults to 10.0)',
      #   keep_looping: 'optional - Boolean to keep scanning indefinitely (defaults to false)',
      #   scan_log: 'optional - Path to save detected signals log (defaults to /tmp/pwn_sdr_gqrx_scan_<start_freq>-<target_freq>_<timestamp>_lN.json)',
      #   location: 'optional - Location string to include in AI analysis (e.g., "New York, NY", 90210, GPS coords, etc.)'
      # )

      public_class_method def self.scan_range(opts = {})
        timestamp_start = Time.now.strftime('%Y-%m-%d %H:%M:%S%z')
        range_timestamp_start = ''

        gqrx_sock = opts[:gqrx_sock]

        ranges = opts[:ranges]
        raise 'ERROR: ranges must be an Array of Hash objects with :start_freq and :target_freq keys.' unless ranges.is_a?(Array) && ranges.all? { |r| r.is_a?(Hash) && r.key?(:start_freq) && r.key?(:target_freq) }

        demodulator_mode = opts[:demodulator_mode]

        bandwidth = opts[:bandwidth] ||= '200.000'

        precision = opts[:precision] ||= 1
        raise 'ERROR: precision must be an Integer between 1 and 12.' unless precision.is_a?(Integer) && precision.between?(1, 12)

        step_hz = 10**(precision - 1)

        strength_lock = opts[:strength_lock] ||= -70.0
        squelch = opts[:squelch] ||= (strength_lock - 3.0)
        raise 'ERROR: squelch must always be less than strength_lock.' if squelch >= strength_lock

        decoder = opts[:decoder]
        keep_looping = opts[:keep_looping] || false
        log_timestamp = Time.now.strftime('%Y-%m-%d')

        location = opts[:location] ||= 'United States'

        # This is for looping through ranges indefinitely if keep_looping is true
        # Generate ranges strings for log filename
        range_str = ''
        ranges.each do |range|
          start_freq = range[:start_freq]
          hz_start = PWN::SDR.hz_to_i(freq: start_freq)
          hz_start_str = PWN::SDR.hz_to_s(freq: hz_start)

          target_freq = range[:target_freq]
          hz_target = PWN::SDR.hz_to_i(freq: target_freq)
          hz_target_str = PWN::SDR.hz_to_s(freq: hz_target)

          range_str = "#{range_str}_#{hz_start_str}-#{hz_target_str}"
        end
        scan_log = opts[:scan_log] ||= "/tmp/pwn_sdr_gqrx_scan#{range_str}_#{log_timestamp}.json"

        iteration_metrics = []
        candidate_signals = []
        signals_detected = []
        iteration_total = 1
        signals_detected_total = 0
        loop do
          signals_detected_delta = 0
          iter_metrics_hash = {}
          ranges.each do |range|
            range_timestamp_start = Time.now.strftime('%Y-%m-%d %H:%M:%S%z')
            iter_metrics_hash[:iteration] = iteration_total
            iter_metrics_hash[:range] = range
            iter_metrics_hash[:timestamp_start] = range_timestamp_start

            # Verify all frequencies are valid
            start_freq = range[:start_freq]
            hz_start = PWN::SDR.hz_to_i(freq: start_freq)
            raise "ERROR: Invalid start_freq '#{start_freq}' provided." if hz_start.zero?

            target_freq = range[:target_freq]
            hz_target = PWN::SDR.hz_to_i(freq: target_freq)
            hz_target_str = PWN::SDR.hz_to_s(freq: hz_target)
            raise "ERROR: Invalid target_freq '#{target_freq}' provided." if hz_target.zero?

            step_hz_direction = hz_start > hz_target ? -step_hz : step_hz
            noise_floor = measure_noise_floor(
              gqrx_sock: gqrx_sock,
              freq: start_freq,
              precision: precision,
              step_hz_direction: step_hz_direction
            )
            if squelch < noise_floor
              squelch = noise_floor.round + 7
              strength_lock = squelch + 3.0
              puts "Adjusted strength_lock to #{strength_lock} dBFS and squelch to #{squelch} dBFS based on measured noise floor.  This ensures proper signal detection..."
            end

            # Begin scanning range
            puts "\n"
            puts '-' * 86
            puts 'SESSION PARAMS >> Scan Range(s):'
            puts ranges
            puts "SESSION PARAMS >> Step Increment: #{PWN::SDR.hz_to_s(freq: step_hz_direction.abs)} Hz."
            puts "SESSION PARAMS >> Continuously Loop through Scan Range(s): #{keep_looping}"
            puts "\nIf scans are slow and/or you're experiencing false positives/negatives,"
            puts 'consider adjusting the following:'
            puts "1. The SDR's sample rate in GQRX"
            puts "\s\s- Click on `Configure I/O devices`."
            puts "\s\s- A lower `Input rate` value seems counter-intuitive but works well (e.g. ADALM PLUTO ~ 1000000)."
            puts '2. Adjust the :strength_lock parameter.'
            puts '3. Adjust the :precision parameter.'
            puts '4. Disable AI introspection in PWN::Env'
            puts 'Happy scanning!'
            puts '-' * 86
            # print 'Pressing ENTER to begin scan...'
            # gets
            puts "\n\n\n"

            # Set squelch once for each range
            change_squelch_resp = cmd(
              gqrx_sock: gqrx_sock,
              cmd: "L SQL #{squelch}",
              resp_ok: 'RPRT 0'
            )

            # We always disable RDS decoding during the scan
            # to prevent unnecessary processing overhead.
            # We return the rds boolean in the scan_resp object
            # so it will be picked up and used appropriately
            # when calling analyze_scan or analyze_log methods.
            rds_resp = cmd(
              gqrx_sock: gqrx_sock,
              cmd: 'U RDS 0',
              resp_ok: 'RPRT 0'
            )

            # Set demodulator mode & passband once for the scan
            mode_str = demodulator_mode.to_s.upcase
            passband_hz = PWN::SDR.hz_to_i(freq: bandwidth)
            cmd(
              gqrx_sock: gqrx_sock,
              cmd: "M #{mode_str} #{passband_hz}",
              resp_ok: 'RPRT 0'
            )

            audio_gain_db = opts[:audio_gain_db] ||= 0.0
            audio_gain_db = audio_gain_db.to_f
            audio_gain_db_resp = cmd(
              gqrx_sock: gqrx_sock,
              cmd: "L AF #{audio_gain_db}",
              resp_ok: 'RPRT 0'
            )

            rf_gain = opts[:rf_gain] ||= 0.0
            rf_gain = rf_gain.to_f
            rf_gain_resp = cmd(
              gqrx_sock: gqrx_sock,
              cmd: "L RF_GAIN #{rf_gain}",
              resp_ok: 'RPRT 0'
            )

            intermediate_gain = opts[:intermediate_gain] ||= 32.0
            intermediate_gain = intermediate_gain.to_f
            intermediate_resp = cmd(
              gqrx_sock: gqrx_sock,
              cmd: "L IF_GAIN #{intermediate_gain}",
              resp_ok: 'RPRT 0'
            )

            baseband_gain = opts[:baseband_gain] ||= 10.0
            baseband_gain = baseband_gain.to_f
            baseband_resp = cmd(
              gqrx_sock: gqrx_sock,
              cmd: "L BB_GAIN #{baseband_gain}",
              resp_ok: 'RPRT 0'
            )

            prev_freq_obj = init_freq(
              gqrx_sock: gqrx_sock,
              freq: hz_start,
              precision: precision,
              demodulator_mode: demodulator_mode,
              bandwidth: bandwidth,
              squelch: squelch,
              decoder: decoder,
              suppress_details: true,
              keep_alive: true
            )

            start_freq = range[:start_freq]
            hz_start = PWN::SDR.hz_to_i(freq: start_freq)
            hz = hz_start

            target_freq = range[:target_freq]
            hz_target = PWN::SDR.hz_to_i(freq: target_freq)

            # puts "#{range} #{start_freq} (#{hz_start})to #{target_freq} (#{hz_target})"
            # gets
            # while step_hz_direction.positive? ? hz <= hz_target : hz >= hz_target
            while (step_hz_direction.positive? && hz <= hz_target) || (step_hz_direction.negative? && hz >= hz_target)
              tune_to(gqrx_sock: gqrx_sock, hz: hz)
              strength_db = measure_signal_strength(
                gqrx_sock: gqrx_sock,
                freq: hz,
                precision: precision,
                strength_lock: strength_lock,
                phase: :find_candidates
              )

              if strength_db >= strength_lock
                puts '-' * 86
                # Find left and right edges of the signal
                candidate_signals = edge_detection(
                  gqrx_sock: gqrx_sock,
                  hz: hz,
                  step_hz: step_hz,
                  precision: precision,
                  strength_lock: strength_lock
                )
              elsif candidate_signals.length.positive?
                best_peak = find_best_peak(
                  gqrx_sock: gqrx_sock,
                  candidate_signals: candidate_signals,
                  precision: precision,
                  step_hz: step_hz,
                  strength_lock: strength_lock
                )

                if best_peak[:hz] && best_peak[:strength_db] > strength_lock
                  puts "\n**** Detected Signal ****"
                  best_freq = PWN::SDR.hz_to_s(freq: best_peak[:hz])
                  best_strength_db = best_peak[:strength_db]
                  prev_freq_obj = init_freq(
                    gqrx_sock: gqrx_sock,
                    freq: best_freq,
                    precision: precision,
                    demodulator_mode: demodulator_mode,
                    bandwidth: bandwidth,
                    squelch: squelch,
                    decoder: decoder,
                    suppress_details: true,
                    keep_alive: true
                  )
                  prev_freq_obj[:strength_lock] = strength_lock
                  prev_freq_obj[:strength_db] = best_strength_db.round(1)
                  prev_freq_obj[:iteration] = iteration_total

                  ai_analysis = PWN::AI::Agent::GQRX.analyze(
                    request: prev_freq_obj.to_json,
                    location: location
                  )

                  prev_freq_obj[:ai_analysis] = ai_analysis unless ai_analysis.nil?
                  puts JSON.pretty_generate(prev_freq_obj)
                  puts '-' * 86
                  puts "\n\n\n"
                  signals_detected.push(prev_freq_obj)
                  log_signals(
                    signals_detected: signals_detected,
                    timestamp_start: timestamp_start,
                    scan_log: scan_log
                  )
                  hz = candidate_signals.last[:hz]
                  # gets
                end
                candidate_signals.clear
              end
              hz += step_hz_direction
            end

            log_signals(
              signals_detected: signals_detected,
              timestamp_start: timestamp_start,
              scan_log: scan_log
            )
          end
          break unless keep_looping

          # Determine how many new signals were detected this iteration
          # Reduces signals_detected to an array of unique frequencies only
          signals_detected.uniq! { |s| PWN::SDR.hz_to_i(freq: s[:freq]) }
          signals_detected_total = signals_detected.select { |s| s[:iteration] == iteration_total }.length
          signals_detected_delta = signals_detected_total - signals_detected_delta
          start_next_iteration = case signals_detected_delta
                                 when 0
                                   30
                                 when 1..5
                                   10
                                 else
                                   5
                                 end

          range_timestamp_end = Time.now.strftime('%Y-%m-%d %H:%M:%S%z')
          iter_metrics_hash[:timestamp_end] = range_timestamp_end

          duration = duration_between(timestamp_start: range_timestamp_start, timestamp_end: range_timestamp_end)
          iter_metrics_hash[:duration] = duration
          iter_metrics_hash[:signals_detected] = signals_detected_delta

          iteration_metrics.push(iter_metrics_hash)
          puts "\nScan iteration(s) ##{iteration_total} complete."
          puts JSON.pretty_generate(iter_metrics_hash)

          puts "Resuming next scan iteration in #{start_next_iteration} seconds.  Press CTRL+C to exit"
          start_next_iteration.times do
            print '.'
            sleep 1
          end
          puts "\n"

          # Log current signals one last time just to capture scan iterations accurately
          iteration_total += 1
          log_signals(
            signals_detected: signals_detected,
            timestamp_start: timestamp_start,
            scan_log: scan_log,
            iteration_metrics: iteration_metrics
          )
        end
      rescue Interrupt
        puts "\nCTRL+C detected - goodbye."
      rescue StandardError => e
        raise e
      ensure
        disconnect(gqrx_sock: gqrx_sock) if defined?(gqrx_sock) && gqrx_sock.is_a?(TCPSocket)
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
          # puts JSON.pretty_generate(signal)
          signal[:gqrx_sock] = gqrx_sock

          # This is required to keep connection alive during analysis
          signal[:keep_alive] = true

          # We do this because we need keep_alive true for init_freq calls below
          squelch = signal[:squelch]
          squelch = cmd(gqrx_sock: gqrx_sock, cmd: 'l SQL').to_f if squelch.nil?
          change_squelch_resp = cmd(
            gqrx_sock: gqrx_sock,
            cmd: "L SQL #{squelch}",
            resp_ok: 'RPRT 0'
          )

          audio_gain_db = signal[:audio_gain_db] ||= 0.0
          audio_gain_db = audio_gain_db.to_f
          audio_gain_db_resp = cmd(
            gqrx_sock: gqrx_sock,
            cmd: "L AF #{audio_gain_db}",
            resp_ok: 'RPRT 0'
          )

          demodulator_mode = signal[:demodulator_mode] || :WFM
          mode_str = demodulator_mode.to_s.upcase

          bandwidth = signal[:bandwidth] ||= '200.000'
          passband_hz = PWN::SDR.hz_to_i(freq: bandwidth)
          cmd(
            gqrx_sock: gqrx_sock,
            cmd: "M #{mode_str} #{passband_hz}",
            resp_ok: 'RPRT 0'
          )

          freq_obj = init_freq(signal)
          freq_obj = signal.merge(freq_obj)
          # Redact gqrx_sock from output
          freq_obj.delete(:gqrx_sock)
          unless freq_obj[:decoder]
            puts JSON.pretty_generate(freq_obj)
            print 'Press [ENTER] to continue...'
            gets
          end
          puts "\n" * 3
        end
      rescue Interrupt
        puts "\nCTRL+C detected - goodbye."
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
      # udp_listener = PWN::SDR::GQRX.listen_udp(
      #   udp_ip: 'optional - IP address to bind UDP listener (defaults to 127.0.0.1)',
      #   upd_port: 'optional - Port to bind UDP listener (defaults to 7355)'
      # )

      public_class_method def self.listen_udp(opts = {})
        udp_ip = opts[:udp_ip] ||= '127.0.0.1'
        udp_port = opts[:udp_port] ||= 7355

        PWN::Plugins::Sock.listen(
          server_ip: udp_ip,
          port: udp_port,
          protocol: :udp,
          detach: true
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::SDR::GQRX.disconnect_udp(
      #   udp_listener: 'required - UDP socket object returned from #listen_udp method'
      # )

      public_class_method def self.disconnect_udp(opts = {})
        udp_listener = opts[:udp_listener]
        raise 'ERROR: udp_sock is required!' if udp_listener.nil?

        PWN::Plugins::Sock.disconnect(sock_obj: udp_listener) unless udp_listener.closed?
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # iq_raw_file = PWN::SDR::GQRX.record(
      #   gqrx_sock: 'required - GQRX socket object returned from #connect method'
      # )

      public_class_method def self.record(opts = {})
        gqrx_sock = opts[:gqrx_sock]
        raise 'ERROR: gqrx_sock is required!' if gqrx_sock.nil?

        # Toggle I/Q RECORD on in GQRX for brevity
        cmd(
          gqrx_sock: gqrx_sock,
          cmd: 'U IQRECORD 0',
          resp_ok: 'RPRT 0'
        )

        cmd(
          gqrx_sock: gqrx_sock,
          cmd: 'U IQRECORD 1',
          resp_ok: 'RPRT 0'
        )

        record_dir = Dir.home
        iq_raw_file = Dir.glob("#{record_dir}/gqrx_*.raw").max_by { |f| File.mtime(f) }
        raise 'ERROR: No GQRX .raw I/Q data file found!' unless iq_raw_file

        iq_raw_file
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::SDR::GQRX.stop_recording(
      #   gqrx_sock: 'required - GQRX socket object returned from #connect method',
      #   iq_raw_file: 'required - iq_raw_file returned from #connect method'
      # )

      public_class_method def self.stop_recording(opts = {})
        gqrx_sock = opts[:gqrx_sock]
        raise 'ERROR: gqrx_sock is required!' if gqrx_sock.nil?

        iq_raw_file = opts[:iq_raw_file]
        raise 'ERROR: iq_raw_file is required!' if iq_raw_file.nil?

        # Toggle IQRECORD off
        cmd(
          gqrx_sock: gqrx_sock,
          cmd: 'U IQRECORD 0',
          resp_ok: 'RPRT 0'
        )

        FileUtils.rm_f(iq_raw_file)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::SDR::GQRX.disconnect(
      #   gqrx_sock: 'required - GQRX socket object returned from #connect method'
      # )
      public_class_method def self.disconnect(opts = {})
        gqrx_sock = opts[:gqrx_sock]

        PWN::Plugins::Sock.disconnect(sock_obj: gqrx_sock) unless gqrx_sock.closed?
      rescue StandardError => e
        raise e
      end

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.get_spectrum_snapshot(opts = {})
        gqrx_sock = opts[:gqrx_sock]
        raise 'ERROR: gqrx_sock is required!' if gqrx_sock.nil?

        center_freq = opts[:center_freq]
        center_freq ||= cmd(gqrx_sock: gqrx_sock, cmd: 'f')
        center_hz = PWN::SDR.hz_to_i(freq: center_freq)

        sample_rate = (opts[:sample_rate] || 1_000_000).to_i
        nfft = (opts[:nfft] || 2048).to_i
        avg = (opts[:avg] || 4).to_i
        capture_secs = (opts[:capture_secs] || 0.05).to_f
        strength_offset_db = (opts[:strength_offset_db] || 0.0).to_f

        num_samples = (sample_rate * capture_secs).to_i
        num_samples = [num_samples, nfft].max
        num_samples = ((num_samples.to_f / nfft).ceil * nfft).to_i

        puts "[*] Capturing ~#{format('%.3f', capture_secs)}s I/Q (#{num_samples} samples @ #{sample_rate} SPS) => #{sample_rate / 1_000_000.0} MHz instantaneous span"

        # Start a fresh short IQ recording for snapshot (entire visible band at once)
        begin
          cmd(gqrx_sock: gqrx_sock, cmd: 'U IQRECORD 0', resp_ok: 'RPRT 0')
        rescue StandardError
          nil
        end
        sleep 0.02
        cmd(gqrx_sock: gqrx_sock, cmd: 'U IQRECORD 1', resp_ok: 'RPRT 0')
        sleep(capture_secs + 0.12)
        cmd(gqrx_sock: gqrx_sock, cmd: 'U IQRECORD 0', resp_ok: 'RPRT 0')

        # Newest raw I/Q produced by GQRX (usually ~/gqrx_*.raw , float32 I/Q interleaved @ sample_rate)
        home = Dir.home
        iq_raw_file = Dir.glob("#{home}/gqrx_*.raw").max_by { |f| File.mtime(f) }
        raise "ERROR: No GQRX .raw file found after capture (looked in #{home})" unless iq_raw_file && File.exist?(iq_raw_file)

        # Read tail of most recent bytes
        total_bytes = num_samples * 8 # float32 * 2 channels
        fsize = File.size(iq_raw_file)
        start_pos = [0, fsize - total_bytes].max
        raw_bytes = File.binread(iq_raw_file, total_bytes, start_pos)

        # ---- Pure-Ruby FFT + SDRangel-style peak detection (no external interpreters) ----
        raise 'ERROR: I/Q read empty or short' if raw_bytes.nil? || raw_bytes.bytesize < 8

        # GQRX raw I/Q: little-endian float32 interleaved I,Q,I,Q,...
        floats = raw_bytes.unpack('e*')
        n_iq = [floats.length / 2, num_samples].min
        iq = Array.new(n_iq) { |i| Complex(floats[2 * i], floats[(2 * i) + 1]) }

        # Hann window
        two_pi = 2.0 * Math::PI
        hann = Array.new(nfft) { |k| 0.5 * (1.0 - Math.cos(two_pi * k / (nfft - 1))) }

        # Iterative in-place radix-2 Cooley-Tukey FFT (nfft must be a power of two)
        raise "ERROR: nfft (#{nfft}) must be a power of two" unless nfft.nobits?(nfft - 1)

        log2n = Math.log2(nfft).to_i
        fft_proc = lambda do |x|
          n = x.length
          # bit-reversal permutation
          j = 0
          (0...(n - 1)).each do |i|
            x[i], x[j] = x[j], x[i] if i < j
            k = n >> 1
            while k <= j
              j -= k
              k >>= 1
            end
            j += k
          end
          # butterflies
          (1..log2n).each do |stage|
            m = 1 << stage
            half = m >> 1
            wm = Complex.polar(1.0, -two_pi / m)
            (0...n).step(m) do |kk|
              w = Complex(1.0, 0.0)
              (0...half).each do |jj|
                t = w * x[kk + jj + half]
                u = x[kk + jj]
                x[kk + jj] = u + t
                x[kk + jj + half] = u - t
                w *= wm
              end
            end
          end
          x
        end

        # Overlapping (50%) windowed FFTs, power-averaged (Welch-style)
        hop = [nfft / 2, 1].max
        specs = []
        pos = 0
        while pos + nfft <= iq.length && specs.length < avg
          blk = Array.new(nfft) { |k| iq[pos + k] * hann[k] }
          sp = fft_proc.call(blk)
          half = nfft / 2
          shifted = sp[half, nfft - half] + sp[0, half]
          specs << shifted.map(&:abs2)
          pos += hop
        end
        if specs.empty?
          blk = Array.new(nfft) do |k|
            (k < iq.length ? iq[k] : Complex(0.0, 0.0)) * hann[k]
          end
          sp = fft_proc.call(blk)
          half = nfft / 2
          shifted = sp[half, nfft - half] + sp[0, half]
          specs << shifted.map(&:abs2)
        end

        avg_pwr = Array.new(nfft, 0.0)
        specs.each { |ps| ps.each_with_index { |v, i| avg_pwr[i] += v } }
        cnt = specs.length.to_f
        avg_pwr.map! { |v| v / cnt }

        db = avg_pwr.map { |v| (10.0 * Math.log10(v + 1e-12)) + strength_offset_db }

        # fftshift(fftfreq(nfft, 1/sr)) => bins from -sr/2 .. +sr/2 (exclusive), step sr/nfft
        res_hz = sample_rate / nfft.to_f
        freq_off = Array.new(nfft) { |i| (i - (nfft / 2)) * res_hz }

        bins_out = Array.new(nfft) do |ii|
          fh = (center_hz + freq_off[ii]).to_i
          {
            bin: ii,
            freq_hz: fh,
            freq: PWN::SDR.hz_to_s(freq: fh),
            power_db: db[ii].round(2)
          }
        end

        # Noise floor: 12th percentile of dB
        sorted_db = db.sort
        pct_idx = ((sorted_db.length - 1) * 0.12).floor
        noise_floor = sorted_db[pct_idx].to_f

        # SDRangel-style peak detection: local maxima above noise_floor+6dB with
        # min bin separation and >= 4 dB prominence.
        height_thr = noise_floor + 6.0
        min_dist = [3, (6000.0 / res_hz).to_i].max
        prom_thr = 4.0

        candidates = []
        (1...(nfft - 1)).each do |i|
          next unless db[i] >= height_thr
          next unless db[i] > db[i - 1] && db[i] >= db[i + 1]

          # prominence: peak - highest of the two side-valley minima toward the
          # nearest higher-or-equal neighbour (scipy.signal.peak_prominences algorithm)
          left_min = db[i]
          li = i - 1
          while li >= 0 && db[li] <= db[i]
            left_min = db[li] if db[li] < left_min
            li -= 1
          end
          right_min = db[i]
          ri = i + 1
          while ri < nfft && db[ri] <= db[i]
            right_min = db[ri] if db[ri] < right_min
            ri += 1
          end
          prom = db[i] - [left_min, right_min].max
          next if prom < prom_thr

          candidates << { idx: i, pwr: db[i], prom: prom }
        end

        # Enforce minimum distance between peaks (keep strongest first)
        candidates.sort_by! { |c| -c[:pwr] }
        selected = []
        candidates.each do |c|
          selected << c unless selected.any? { |s2| (s2[:idx] - c[:idx]).abs < min_dist }
        end
        selected.sort_by! { |c| c[:idx] }

        edge_thr = noise_floor + 3.5
        signals = selected.map do |c|
          p = c[:idx]
          l = p
          l -= 1 while l.positive? && db[l] >= edge_thr
          r = p
          r += 1 while r < (nfft - 1) && db[r] >= edge_thr
          bw_hz = ([r - l, 1].max * res_hz).to_i
          center = (center_hz + freq_off[p]).to_i
          {
            hz: center,
            freq: PWN::SDR.hz_to_s(freq: center),
            power_db: c[:pwr].round(2),
            noise_floor_db: noise_floor.round(2),
            bw_hz: bw_hz,
            snr_db: (c[:pwr] - noise_floor).round(2),
            peak_bin: p,
            prominence_db: c[:prom].round(2)
          }
        end

        # Fallback: simple threshold if prominence-based detection found nothing
        if signals.empty?
          bins_out.each do |b|
            next unless b[:power_db] > (noise_floor + 7.0)

            signals << b.merge(
              hz: b[:freq_hz],
              noise_floor_db: noise_floor.round(2),
              bw_hz: (res_hz * 2).to_i,
              snr_db: (b[:power_db] - noise_floor).round(2)
            )
          end
        end

        {
          center_freq_hz: center_hz,
          center_freq: PWN::SDR.hz_to_s(freq: center_hz),
          sample_rate: sample_rate,
          visible_span_hz: sample_rate,
          nfft: nfft,
          avg: avg,
          resolution_hz: res_hz.round(2),
          samples: iq.length,
          capture_secs: capture_secs,
          spectrum: bins_out,
          signals: signals,
          noise_floor_db: noise_floor.round(2),
          timestamp: Time.now.strftime('%Y-%m-%d %H:%M:%S%z')
        }
      rescue StandardError => e
        begin
          cmd(gqrx_sock: gqrx_sock, cmd: 'U IQRECORD 0', resp_ok: 'RPRT 0')
        rescue StandardError
          nil
        end
        raise e
      end

      # Supported Method Parameters::
      # fast_resp = PWN::SDR::GQRX.fast_scan_range(
      #   gqrx_sock: 'required - GQRX socket object',
      #   ranges: 'required - Array<Hash> of {start_freq:, target_freq: }',
      #   sample_rate: 'optional - Set this to GQRX visible input sample rate (the span width)',
      #   nfft: 'optional - FFT size',
      #   avg: 'optional',
      #   capture_secs: 'optional',
      #   strength_lock: 'optional',
      #   keep_spectrum: 'optional - if true return raw spectrum arrays too (large)'
      # )
      #
      # Uses chunk-wise retuning where chunk = sample_rate so that the *entire visible band* (waterfall width)
      # is captured via a single FFT each time rather than point-by-point hops.
      # This yields near real-time panoramic coverage. Update rate is roughly (retune + capture + fft) per chunk.
      public_class_method def self.fast_scan_range(opts = {})
        gqrx_sock = opts[:gqrx_sock]
        raise 'gqrx_sock required' if gqrx_sock.nil?

        ranges = opts[:ranges]
        raise 'ranges required as array of hashes' unless ranges.is_a?(Array) && !ranges.empty?

        sr = (opts[:sample_rate] || 1_000_000).to_i
        nfft = opts[:nfft] || 2048
        avgs = opts[:avg] || 2
        cap = opts[:capture_secs] || 0.03
        strength_lock = opts[:strength_lock] || -70.0
        keep_spec = opts[:keep_spectrum] ? true : false
        scan_log = opts[:scan_log] || "/tmp/pwn_fastscan_#{Time.now.to_i}.json"

        ts_start = Time.now.strftime('%Y-%m-%d %H:%M:%S%z')
        detected = []
        all_specs = [] if keep_spec

        ranges.each do |r|
          s_hz = PWN::SDR.hz_to_i(freq: r[:start_freq])
          t_hz = PWN::SDR.hz_to_i(freq: r[:target_freq])
          dir = t_hz >= s_hz ? 1 : -1
          step = (sr * 0.85).to_i # chunk step - use 85% to have overlap / avoid edge artifacts
          step = sr if step < 100_000

          puts "[FAST-SCAN] Panoramic covering #{PWN::SDR.hz_to_s(freq: s_hz)}..#{PWN::SDR.hz_to_s(freq: t_hz)} using #{sr} SPS chunks (step #{PWN::SDR.hz_to_s(freq: step)})"

          h = s_hz
          while dir.positive? ? (h <= t_hz) : (h >= t_hz)
            # retune to put this chunk in the visible IF
            tune_to(gqrx_sock: gqrx_sock, hz: h)
            sleep 0.15 # allow GQRX / SDR to settle the IF filter & AGC etc.

            snap = get_spectrum_snapshot(
              gqrx_sock: gqrx_sock,
              center_freq: h,
              sample_rate: sr,
              nfft: nfft,
              avg: avgs,
              capture_secs: cap,
              strength_offset_db: opts[:strength_offset_db]
            )

            all_specs << snap if keep_spec

            sigs = snap[:signals] || []
            if sigs.any?
              # Prefer SDRangel-style identified signals (with BW / SNR / noise_floor)
              sigs.each do |sig|
                next if sig[:power_db] && sig[:power_db] < strength_lock

                detected << {
                  hz: sig[:hz] || sig[:freq_hz],
                  freq: sig[:freq],
                  strength: sig[:power_db],
                  bw_hz: sig[:bw_hz],
                  snr_db: sig[:snr_db],
                  noise_floor_db: sig[:noise_floor_db],
                  chunk_center: PWN::SDR.hz_to_s(freq: h),
                  method: :fast_spectrum_sdrangel_like
                }
              end
            else
              # legacy fallback on raw spectrum bins
              snap[:spectrum].each do |bin|
                next if bin[:power_db] < strength_lock

                detected << {
                  hz: bin[:freq_hz],
                  freq: bin[:freq],
                  strength: bin[:power_db],
                  chunk_center: PWN::SDR.hz_to_s(freq: h),
                  method: :fast_spectrum
                }
              end
            end
            h += step * dir
          end
        end

        detected.uniq! { |d| d[:hz] }
        detected.sort_by! { |d| d[:hz] }

        resp = {
          signals: detected,
          total: detected.length,
          spectrums: keep_spec ? all_specs : nil,
          timestamp_start: ts_start,
          timestamp_end: Time.now.strftime('%Y-%m-%d %H:%M:%S%z'),
          sample_rate_used: sr,
          nfft: nfft,
          method: :fast_scan_range
        }

        File.write(scan_log, JSON.pretty_generate(resp))
        begin
          log_signals(signals_detected: detected, timestamp_start: ts_start, scan_log: scan_log)
        rescue StandardError
          nil
        end
        resp
      rescue StandardError => e
        raise e
      end

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <support@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts <<~USAGE
          USAGE:
            gqrx_sock = #{self}.connect(
              target: 'optional - GQRX target IP address (defaults to 127.0.0.1)',
              port: 'optional - GQRX target port (defaults to 7356)'
            )

            gqrx_resp = #{self}.cmd(
              gqrx_sock: 'required - GQRX socket object returned from #connect method',
              cmd: 'required - GQRX command to send',
              resp_ok: 'optional - Expected OK response (defaults to nil / no check)'
            )

            freq_obj = #{self}.init_freq(
              gqrx_sock: 'required - GQRX socket object returned from #connect method',
              freq: 'required - Frequency to set',
              precision: 'optional - Frequency step precision (number of digits; defaults to 6)',
              demodulator_mode: 'optional - Demodulator mode (defaults to WFM)',
              bandwidth: 'optional - Bandwidth (defaults to "200.000")',
              decoder: 'optional - Decoder key (e.g., :gsm) to start live decoding (starts recording if provided)',
              suppress_details: 'optional - Boolean to include extra frequency details in return hash (defaults to false)',
              keep_alive: 'optional - Boolean to keep GQRX connection alive after method completion (defaults to false)'
            )

            scan_resp = #{self}.scan_range(
              gqrx_sock: 'required - GQRX socket object returned from #connect method',
              ranges: 'required - Array of Hash objects with :start_freq and :target_freq keys defining scan ranges',
              demodulator_mode: 'optional - Demodulator mode (e.g. WFM, AM, FM, USB, LSB, RAW, CW, RTTY / defaults to WFM)',
              bandwidth: 'optional - Bandwidth in Hz (Defaults to "200.000")',
              precision: 'optional - Precision (Defaults to 1)',
              strength_lock: 'optional - Strength lock (defaults to -70.0)',
              squelch: 'optional - Squelch level (defaults to strength_lock - 3.0)',
              audio_gain_db: 'optional - Audio gain in dB (defaults to 0.0)',
              rf_gain: 'optional - RF gain (defaults to 0.0)',
              intermediate_gain: 'optional - Intermediate gain (defaults to 32.0)',
              baseband_gain: 'optional - Baseband gain (defaults to 10.0)',
              keep_looping: 'optional - Boolean to keep scanning indefinitely (defaults to false)',
              scan_log: 'optional - Path to save detected signals log (defaults to /tmp/pwn_sdr_gqrx_scan_<start_freq>-<target_freq>_<timestamp>.json)',
              location: 'optional - Location string to include in AI analysis (e.g., "New York, NY", 90210, GPS coords, etc.)'
            )

            snapshot = #{self}.get_spectrum_snapshot(
              gqrx_sock: 'required - GQRX socket object returned from #connect method',
              center_freq: 'optional - Center frequency (Hz) for snapshot (defaults to current tuned freq)',
              sample_rate: 'optional - Instantaneous bandwidth / sample rate in Hz (defaults to 1_000_000)',
              nfft: 'optional - FFT bin size (defaults to 2048)',
              avg: 'optional - Number of FFT averages (defaults to 4)',
              capture_secs: 'optional - Duration of I/Q capture in seconds (defaults to 0.05)',
              strength_offset_db: 'optional - Add this many dB to all power levels (defaults to 0.0)'
            )

            fast_scan_resp = #{self}.fast_scan_range(
              gqrx_sock: 'required - GQRX socket object returned from #connect method',
              ranges: 'required - Array of Hash objects with :start_freq and :target_freq keys defining scan ranges',
              sample_rate: 'optional - Chunk size / visible span in Hz (defaults to 1_000_000)',
              nfft: 'optional - FFT size (defaults to 2048)',
              avg: 'optional - Number of averages (defaults to 2)',
              capture_secs: 'optional - Seconds of capture per chunk (defaults to 0.03)',
              strength_lock: 'optional - Minimum signal strength in dBFS to report (defaults to -70.0)',
              keep_spectrum: 'optional - If true, include full spectrum data in result (can be large, defaults to false)',
              strength_offset_db: 'optional - Add this many dB to all power levels (defaults to 0.0)',
              scan_log: 'optional - Path to save fast scan results (defaults to /tmp/pwn_fastscan_<timestamp>.json)'
            )

            #{self}.analyze_scan(
              scan_resp: 'required - Scan response object from #scan_range or #fast_scan_range method',
              target: 'optional - GQRX target IP address (defaults to 127.0.0.1)',
              port: 'optional - GQRX target port (defaults to 7356)'
            )

            #{self}.analyze_log(
              scan_log: 'required - Path to signals log file',
              target: 'optional - GQRX target IP address (defaults to 127.0.0.1)',
              port: 'optional - GQRX target port (defaults to 7356)'
            )

            udp_listener = #{self}.listen_udp(
              udp_ip: 'optional - IP address to bind UDP listener (defaults to 127.0.0.1)',
              udp_port: 'optional - Port to bind UDP listener (defaults to 7355)'
            )

            #{self}.disconnect_udp(
              udp_listener: 'required - UDP socket object returned from #listen_udp method'
            )

            iq_raw_file = #{self}.record(
              gqrx_sock: 'required - GQRX socket object returned from #connect method'
            )

            #{self}.stop_recording(
              gqrx_sock: 'required - GQRX socket object returned from #connect method',
              iq_raw_file: 'required - iq_raw_file returned from #record method'
            )

            #{self}.disconnect(
              gqrx_sock: 'required - GQRX socket object returned from #connect method'
            )

            #{self}.authors
        USAGE
      end
    end
  end
end
