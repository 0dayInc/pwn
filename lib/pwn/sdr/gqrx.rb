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
        # Debug strength measurement attempts only when explicitly requested
        # (PWN_GQRX_DEBUG=1). Always-on logging made scans unreadable and hid
        # the real detection summary under thousands of probe lines.
        if ENV['PWN_GQRX_DEBUG']
          puts "\tStrength Measurement Attempts: #{attempts} | Freq: #{freq} | Phase: #{phase}"
          puts "\tUnique Samples: #{unique_samples} | dbFS Distance Unique Samples: #{distance_between_unique_samples}"
        end

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
        # Optional hard bounds (used by refine_detections to keep the walk
        # inside the FFT-seeded window so we cannot bleed into a neighbour).
        min_hz = opts[:min_hz]
        max_hz = opts[:max_hz]
        left_candidate_signals = []
        right_candidate_signals = []
        candidate_signals = []

        original_hz = hz
        strength_db = 99.9
        puts '*** Edge Detection: Locating Beginning of Signal...'
        while strength_db >= strength_lock
          break if min_hz && hz < min_hz

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
          break if max_hz && hz > max_hz

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
        # Optional top-level metadata merged into the scan response so that
        # #scan_range and #fast_scan_range produce an identical JSON schema
        # (sample_rate_used / nfft / precision / plan_bw_hz / method / …).
        meta = opts[:meta] || {}
        meta = meta.transform_keys(&:to_sym) if meta.respond_to?(:transform_keys)

        existing_scan_resp = JSON.parse(File.read(scan_log), symbolize_names: true) if File.exist?(scan_log)

        # Prefer caller-supplied iteration_metrics; fall back to prior log.
        iteration_metrics = opts[:iteration_metrics]
        iteration_metrics ||= existing_scan_resp[:iteration_metrics] if existing_scan_resp.is_a?(Hash) && existing_scan_resp.key?(:iteration_metrics) && existing_scan_resp[:iteration_metrics].is_a?(Array) && !existing_scan_resp[:iteration_metrics].empty?
        iteration_metrics ||= []

        signals = signals_detected.sort_by { |s| PWN::SDR.hz_to_i(freq: s[:freq]) }
        # Unique signals by frequency
        signals.uniq! { |s| PWN::SDR.hz_to_i(freq: s[:freq]) }

        timestamp_end = Time.now.strftime('%Y-%m-%d %H:%M:%S%z')
        duration = duration_between(timestamp_start: timestamp_start, timestamp_end: timestamp_end)

        # Canonical top-level schema shared by iterative + FFT scan modes.
        # FFT-only keys (sample_rate_used / nfft) are nil for #scan_range;
        # callers override via :meta. Preserve any previously-logged meta
        # that the current call did not re-supply so mid-scan re-logs do
        # not strip provenance fields.
        prior_meta = {}
        if existing_scan_resp.is_a?(Hash)
          %i[sample_rate_used nfft precision plan_bw_hz demodulator_mode bandwidth squelch strength_lock audio_gain_db rf_gain intermediate_gain baseband_gain decoder method spectrums].each do |k|
            prior_meta[k] = existing_scan_resp[k] if existing_scan_resp.key?(k)
          end
        end

        scan_resp = {
          signals: signals,
          total: signals.length,
          timestamp_start: timestamp_start,
          timestamp_end: timestamp_end,
          duration: duration,
          iteration_metrics: iteration_metrics,
          sample_rate_used: nil,
          nfft: nil,
          precision: nil,
          plan_bw_hz: nil,
          method: nil
        }
        scan_resp.merge!(prior_meta)
        scan_resp.merge!(meta)

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
      # refined = PWN::SDR::GQRX.refine_detections(
      #   gqrx_sock: 'required - GQRX socket object returned from #connect method',
      #   detections: 'required - Array of preliminary signal hashes (from FFT or prior scan)',
      #   precision: 'required - Frequency step precision (raster digits)',
      #   step_hz: 'required - Frequency step in Hz for edge / peak walking',
      #   strength_lock: 'required - Strength lock in dBFS used as the edge gate',
      #   plan_bw_hz: 'optional - Expected occupied bandwidth (Hz); bounds the search window',
      #   demodulator_mode: 'optional - Mode attributed to detections (defaults to existing / :WFM)',
      #   bandwidth: 'optional - Passband attributed to detections',
      #   squelch: 'optional - Squelch attributed to detections'
      # )
      #
      # Post-process a *preliminary* detection list by re-walking each candidate with
      # the traditional S-meter edge_detection + find_best_peak pipeline, restricted
      # to a tight window around the candidate. Purpose: turn an FFT bin estimate
      # into the exact channel frequency so decoding (and analyze_scan retunes) land
      # dead-center. Failures fall back to the original detection (best-effort).

      # Supported Method Parameters::
      # geo = PWN::SDR::GQRX.fft_plan_geometry(
      #   plan_bw_hz: 'required - expected channel / plan bandwidth (Hz)',
      #   step_hz: 'required - band-plan raster 10**(precision-1) (Hz)',
      #   res_hz: 'optional - FFT bin width sample_rate/nfft (Hz); used for bin counts',
      #   measured_bw_hz: 'optional - measured occupied BW for merge tolerance'
      # )
      #
      # Pure geometry for --fft-scan derived from the two band-plan invariants
      # (plan_bw_hz, step_hz) plus optional spectrum resolution. Every residual
      # clamp that previously hard-coded FLEX/NBFM-scale kHz values is a pure
      # function of those three inputs so the same detector works for all 84
      # band plans (CW 150 Hz → Wi-Fi MHz).
      private_class_method def self.fft_plan_geometry(opts = {})
        plan_bw_hz = opts[:plan_bw_hz].to_f
        step_hz = opts[:step_hz].to_f
        res_hz = opts[:res_hz].to_f
        measured_bw_hz = opts[:measured_bw_hz].to_f

        plan_bw_hz = 0.0 if plan_bw_hz.negative?
        step_hz = 1.0 if step_hz <= 0.0
        res_hz = 0.0 if res_hz.negative?
        measured_bw_hz = 0.0 if measured_bw_hz.negative?

        # Peak min-distance in Hz: half-channel, raster, or a small safety floor
        # so wide carriers (fm_radio 200 kHz) don't emit N peaks, and dense
        # narrow ones (FLEX 1 kHz / CW 100 Hz) still separate. Floor is
        # step-aware so CW/RTTY aren't forced to 3 kHz.
        # Floor for peak min-distance. Wide plans must NOT floor at step_hz
        # itself — for fm_radio step=100 kHz that made min_dist ~100 kHz and
        # let strong carriers dominate weaker neighbours within one channel.
        # Prefer a modest absolute floor scaled by plan family.
        if plan_bw_hz.positive? && plan_bw_hz >= 50_000.0
          floor_sep = [step_hz * 0.45, plan_bw_hz * 0.25, 25_000.0].max
        elsif plan_bw_hz.positive? && plan_bw_hz < 1_000.0
          floor_sep = [plan_bw_hz, step_hz, 100.0].max
        elsif plan_bw_hz.positive? && plan_bw_hz < 10_000.0
          floor_sep = [plan_bw_hz * 0.5, step_hz, 500.0].max
        else
          floor_sep = [step_hz, 3_000.0].max
          floor_sep = [floor_sep, 3_000.0].min if plan_bw_hz.positive? && plan_bw_hz < 3_000.0
        end

        # Wide broadcast: keep sep slightly under one channel so adjacent
        # stations (US FM every 200 kHz) always survive, while pilot/RDS
        # (~19/57 kHz offsets) still get merged under the main carrier.
        sep_hz = if plan_bw_hz.positive? && plan_bw_hz >= 50_000.0
                   [step_hz * 0.55, plan_bw_hz * 0.30, floor_sep].max
                 elsif plan_bw_hz.positive?
                   [plan_bw_hz * 0.5, step_hz, floor_sep].max
                 else
                   [step_hz, 6_000.0].max
                 end

        min_dist_bins = if res_hz.positive?
                          [3, (sep_hz / res_hz).ceil].max
                        else
                          3
                        end

        max_half_bins = if res_hz.positive?
                          cap_hz = plan_bw_hz.positive? ? plan_bw_hz : 50_000.0
                          [(cap_hz / res_hz).ceil, 2].max
                        else
                          2
                        end

        # Refine local window half-width.
        # Goal: cover the channel footprint of the *seed* without enclosing the
        # next co-channel neighbour. Using 2*step blew up on fm_radio
        # (step=100 kHz → ±200 kHz, neighbour spacing = 200 kHz). Rule:
        #   half ≈ max(0.6·plan, min(2·step, plan), floor)
        # so FLEX stays ~12 kHz and FM stays ~120 kHz (next station at ±200).
        if plan_bw_hz <= 0.0
          base_half = 5_000.0
          lo_clamp = 5_000.0
          hi_clamp = 15_000.0
        elsif plan_bw_hz < 1_000.0
          # CW / RTTY — keep tiny
          base_half = [plan_bw_hz * 4.0, 2.0 * step_hz, 500.0].max
          lo_clamp = [2.0 * step_hz, 200.0].max
          hi_clamp = [plan_bw_hz * 20.0, 5_000.0].max
        else
          # Prefer ~0.6 plan_bw (main-lobe FO) and never use 2*step when
          # step itself is already a significant fraction of plan_bw
          # (fm_radio: step=100k, plan=200k → 2*step == plan → neighbour steal).
          step_term = [step_hz, 0.5 * plan_bw_hz].min
          base_half = [0.6 * plan_bw_hz, step_term, 2_000.0].max
          lo_clamp = [[step_hz * 0.5, 1_000.0].max, 1_000.0].max
          # Cap at 0.75 plan so the next neighbour (typically ≥ plan apart)
          # stays outside the refine window.
          hi_clamp = [0.75 * plan_bw_hz, step_term, 50_000.0].max
        end
        refine_half_hz = base_half.clamp(lo_clamp, hi_clamp).to_i
        refine_half_hz = 1 if refine_half_hz < 1

        # Narrow fallback bin search around seed when no local FFT peaks clear
        # the SNR gate — half plan or step (capped by refine window).
        narrow_half_hz = if plan_bw_hz.positive?
                           [(plan_bw_hz / 2.0), step_hz, [step_hz, 500.0].max].max
                         else
                           [step_hz, 2_000.0].max
                         end
        narrow_half_hz = [narrow_half_hz, refine_half_hz.to_f].min.to_i
        narrow_half_hz = 1 if narrow_half_hz < 1

        # Snap reject: max walk from the panoramic seed we still accept as
        # "the same channel". Half-plan (or one raster) — for FLEX ~10 kHz,
        # for FM ~100 kHz. Never open the door to the next neighbour.
        if plan_bw_hz.positive?
          max_snap_delta_hz = [
            plan_bw_hz * 0.5,
            step_hz,
            [plan_bw_hz * 0.25, 1_000.0].max
          ].max
        else
          max_snap_delta_hz = [step_hz, 10_000.0].max
        end
        max_snap_delta_hz = max_snap_delta_hz.to_i
        max_snap_delta_hz = step_hz.to_i if max_snap_delta_hz < 1

        # Cross-chunk / post-refine merge tolerance.
        # Wide broadcast carriers (fm_radio): half-plan (100 kHz) would collapse
        # two legitimate adjacent stations. Prefer a fraction of the *raster*
        # so two seeds on neighbouring 100 kHz channels survive, while
        # subcarrier/pilot debris around a single station still merges.
        if plan_bw_hz >= 50_000.0
          merge_tol_hz = [
            step_hz * 0.55,
            (measured_bw_hz / 2.0),
            (res_hz.positive? ? (2.0 * res_hz).ceil : 0.0),
            1_000.0
          ].max.to_i
        else
          merge_tol_hz = [
            (plan_bw_hz / 2.0),
            step_hz,
            (measured_bw_hz / 2.0),
            (res_hz.positive? ? (2.0 * res_hz).ceil : 0.0)
          ].max.to_i
        end
        merge_tol_hz = step_hz.to_i if merge_tol_hz < 1 && plan_bw_hz < 50_000.0
        merge_tol_hz = 1 if merge_tol_hz < 1

        # Local high-res FFT zoom sample rate for refine: ~4–8× plan BW with
        # bounds that still resolve narrow plans and don't waste time on wide
        # ones. Min bound scales with plan so CW isn't forced to 200 kHz SR
        # (though 200 kHz still fine if caller wants speed consistency).
        local_sr = if plan_bw_hz.positive?
                     raw = [plan_bw_hz * 8.0, plan_bw_hz * 4.0, 4.0 * step_hz * 64].max
                     # Keep a practical floor for GQRX IQRECORD usefulness.
                     lo_sr = if plan_bw_hz < 1_000.0
                               50_000
                             elsif plan_bw_hz < 50_000.0
                               200_000
                             else
                               500_000
                             end
                     hi_sr = if plan_bw_hz >= 200_000.0
                               2_000_000
                             else
                               1_000_000
                             end
                     raw.clamp(lo_sr, hi_sr).to_i
                   else
                     200_000
                   end

        # Window must fit inside the local FFT span (± local_sr/2), else snap
        # validation accepts peaks the zoom never actually captured.
        max_win = [(local_sr * 0.45).to_i, step_hz.to_i, 1].max
        refine_half_hz = [refine_half_hz, max_win].min
        narrow_half_hz = [narrow_half_hz, refine_half_hz].min

        {
          plan_bw_hz: plan_bw_hz.to_i,
          step_hz: step_hz.to_i,
          res_hz: res_hz,
          sep_hz: sep_hz,
          min_dist_bins: min_dist_bins,
          max_half_bins: max_half_bins,
          refine_half_hz: refine_half_hz,
          narrow_half_hz: narrow_half_hz,
          max_snap_delta_hz: max_snap_delta_hz,
          merge_tol_hz: merge_tol_hz,
          local_sr: local_sr
        }
      rescue StandardError => e
        raise e
      end

      private_class_method def self.refine_detections(opts = {})
        gqrx_sock = opts[:gqrx_sock]
        detections = opts[:detections] || []
        precision = opts[:precision].to_i
        step_hz = opts[:step_hz].to_i
        strength_lock = opts[:strength_lock].to_f
        plan_bw_hz = (opts[:plan_bw_hz] || step_hz).to_i
        plan_bw_hz = step_hz if plan_bw_hz <= 0
        step_hz = 1 if step_hz <= 0
        mode = opts[:refine_mode].to_s.downcase
        mode = 'lock' if mode.empty? || mode == 'true' || mode == 'default'

        return detections if detections.empty?

        # Plan-parametric geometry (half_win / local_sr / snap reject / merge)
        # derived once from (plan_bw_hz, step_hz) so every band plan shares
        # the same formulas — residual FLEX-tuned 5–15 kHz clamps are gone.
        geo = fft_plan_geometry(plan_bw_hz: plan_bw_hz, step_hz: step_hz)
        half_win = geo[:refine_half_hz]
        local_sr = geo[:local_sr]
        narrow_half = geo[:narrow_half_hz]
        max_delta = geo[:max_snap_delta_hz]
        local_nfft = 2048
        local_res = local_sr / local_nfft.to_f
        # How many raster bins either side of the seed to lock-hunt.
        # Wide FM (step 100 kHz): ±1 is enough to fix a bad snap; narrow plans
        # hunt ±2 so bursty carriers still find a strong center.
        hunt_steps = plan_bw_hz >= 50_000.0 ? 1 : 2

        puts '-' * 86
        puts "[REFINE] #{mode}-mode channel lock of #{detections.length} preliminary detection(s)"
        puts "         raster=#{PWN::SDR.hz_to_s(freq: step_hz)} Hz  plan_bw=#{PWN::SDR.hz_to_s(freq: plan_bw_hz)} Hz  strength_lock=#{strength_lock} dBFS"
        puts "         geo: half_win=#{PWN::SDR.hz_to_s(freq: half_win)}  local_sr=#{local_sr}  narrow_half=#{PWN::SDR.hz_to_s(freq: narrow_half)}  max_snap_Δ=#{PWN::SDR.hz_to_s(freq: max_delta)}  hunt=±#{hunt_steps}"
        puts '-' * 86

        mode_str = (opts[:demodulator_mode] || :FM).to_s.upcase
        passband_hz = plan_bw_hz.positive? ? plan_bw_hz : 20_000

        # Band-plan IF once up-front for S-meter/lock-hunt (meaningful STRENGTH).
        begin
          cmd(gqrx_sock: gqrx_sock, cmd: "M #{mode_str} #{passband_hz}", resp_ok: 'RPRT 0')
          cmd(gqrx_sock: gqrx_sock, cmd: 'L SQL -150.0', resp_ok: 'RPRT 0')
          sleep 0.08
        rescue StandardError => e
          puts "[REFINE] WARNING: could not apply band-plan IF (#{e.class}: #{e.message})"
        end

        # Fast S-meter sample helper (median of N reads after a short settle).
        sample_smeter = lambda do |hz, n: 4, settle: 0.04|
          tune_to(gqrx_sock: gqrx_sock, hz: hz)
          sleep settle
          samples = n.times.map do
            s = cmd(gqrx_sock: gqrx_sock, cmd: 'l STRENGTH').to_f
            sleep 0.008
            s
          end
          samples.sort!
          samples[samples.length / 2]
        end

        refined = []
        detections.each_with_index do |det, idx|
          seed_hz = (det[:raw_peak_hz] || det[:hz] || PWN::SDR.hz_to_i(freq: det[:freq])).to_i
          if seed_hz.zero?
            puts "  [REFINE] detection ##{idx + 1} has no usable seed frequency — keeping as-is"
            refined << det
            next
          end

          seed_snap = ((seed_hz.to_f / step_hz).round * step_hz).to_i
          win_lo = seed_hz - half_win
          win_hi = seed_hz + half_win
          puts "\n[REFINE #{idx + 1}/#{detections.length}] seed=#{PWN::SDR.hz_to_s(freq: seed_hz)} snap=#{PWN::SDR.hz_to_s(freq: seed_snap)}  window=#{PWN::SDR.hz_to_s(freq: win_lo)}..#{PWN::SDR.hz_to_s(freq: win_hi)} mode=#{mode}"

          peak_hz = nil
          peak_pwr = nil
          peak_bw = det[:bw_hz].to_i
          peak_snr = det[:snr_db]
          peak_nf = det[:noise_floor_db]
          smeter = nil

          if mode == 'fft'
            # Legacy path: local high-res FFT zoom (slow — one IQRECORD + FFT per hit).
            begin
              cmd(gqrx_sock: gqrx_sock, cmd: "M RAW #{local_sr}", resp_ok: 'RPRT 0')
              tune_to(gqrx_sock: gqrx_sock, hz: seed_hz)
              sleep 0.08
              snap = get_spectrum_snapshot(
                gqrx_sock: gqrx_sock,
                center_freq: seed_hz,
                sample_rate: local_sr,
                nfft: local_nfft,
                avg: 4,
                capture_secs: 0.08,
                channel_bw_hz: plan_bw_hz,
                step_hz: step_hz
              )
              local_sigs = (snap[:signals] || []).select do |s|
                h = s[:hz].to_i
                h.between?(win_lo, win_hi) && s[:snr_db].to_f >= 8.0
              end
              if local_sigs.empty?
                bins = snap[:spectrum] || []
                narrow_lo = seed_hz - narrow_half
                narrow_hi = seed_hz + narrow_half
                in_win = bins.select { |b| b[:freq_hz].to_i.between?(narrow_lo, narrow_hi) }
                unless in_win.empty?
                  best_bin = in_win.max_by { |b| b[:power_db].to_f }
                  nf = snap[:noise_floor_db].to_f
                  if best_bin[:power_db].to_f >= (nf + 8.0)
                    peak_hz = best_bin[:freq_hz].to_i
                    peak_pwr = best_bin[:power_db].to_f
                    peak_bw = plan_bw_hz
                    peak_snr = (peak_pwr - nf).round(2)
                    peak_nf = nf
                  end
                end
              else
                near = local_sigs.select { |s| (s[:hz].to_i - seed_hz).abs <= max_delta }
                pool = near.empty? ? local_sigs : near
                best_snr = pool.map { |s| s[:snr_db].to_f }.max
                contenders = pool.select { |s| s[:snr_db].to_f >= (best_snr - 3.0) }
                best = contenders.min_by { |s| (s[:hz].to_i - seed_hz).abs }
                peak_hz = best[:hz].to_i
                peak_pwr = best[:power_db].to_f
                peak_bw = best[:bw_hz].to_i
                peak_bw = plan_bw_hz if peak_bw <= 0 || peak_bw > (plan_bw_hz * 2)
                peak_snr = best[:snr_db]
                peak_nf = best[:noise_floor_db]
              end
              # restore band-plan IF for any subsequent S-meter confirm
              cmd(gqrx_sock: gqrx_sock, cmd: "M #{mode_str} #{passband_hz}", resp_ok: 'RPRT 0')
            rescue StandardError => e
              puts "  [REFINE] local FFT failed (#{e.class}: #{e.message}) — falling back to lock-hunt"
              peak_hz = nil
              begin
                cmd(gqrx_sock: gqrx_sock, cmd: "M #{mode_str} #{passband_hz}", resp_ok: 'RPRT 0')
              rescue StandardError
                nil
              end
            end
          end

          # Lock-hunt (default AND fft-fallback): probe seed_snap ± N * step_hz
          # under the band-plan demod and keep the strongest above (lock - 6 dB).
          # This is the accuracy fix for FM: panoramic centroids often snap one
          # channel off (89.2 vs 89.1); a single S-meter probe per neighbour
          # corrects it in ~150 ms vs multi-second local FFT zoom.
          if peak_hz.nil? || mode == 'lock' || mode == 'hybrid'
            candidates = (-hunt_steps..hunt_steps).map { |k| seed_snap + (k * step_hz) }
            # Also include the raw panoramic snap if it differs from seed_snap.
            candidates << ((seed_hz.to_f / step_hz).round * step_hz).to_i
            candidates = candidates.uniq.select { |h| h.positive? && h.between?(win_lo - step_hz, win_hi + step_hz) }
            best_h = nil
            best_s = -1.0 / 0.0
            scores = []
            candidates.each do |h|
              s = sample_smeter.call(h, n: 3, settle: 0.035)
              scores << [h, s]
              if s > best_s
                best_s = s
                best_h = h
              end
            end
            # Accept if strong enough relative to strength_lock (S-meter domain).
            # strength_lock ≈ nf+8; require at least lock-6 (≈ nf+2) so weak-but-
            # real stations still lock while pure noise floor rejects.
            min_accept = strength_lock - 6.0
            if best_h && best_s >= min_accept
              peak_hz = best_h
              smeter = best_s.round(1)
              peak_pwr = smeter if peak_pwr.nil?
              # Optional: if two neighbours both very strong (within 3 dB) and
              # both above lock, keep BOTH as separate detections later by
              # returning the nearest-to-seed; dual-split happens only when
              # the secondary is itself a distinct seed from panorama.
              near_seed = scores.select { |_h, s| s >= (best_s - 3.0) && s >= min_accept }
                                .min_by { |h, _s| (h - seed_hz).abs }
              if near_seed && (near_seed[0] - seed_hz).abs <= max_delta
                peak_hz = near_seed[0]
                smeter = near_seed[1].round(1)
              end
              puts "  [REFINE] lock-hunt scores: #{scores.map { |h, s| "#{PWN::SDR.hz_to_s(freq: h)}=#{s.round(1)}" }.join('  ')}"
            else
              puts "  [REFINE] lock-hunt no candidate ≥ #{min_accept.round(1)} dBFS (best=#{best_s.round(1)}) — keeping FFT estimate"
            end
          end

          unless peak_hz
            refined << det
            next
          end

          snapped_hz = ((peak_hz.to_f / step_hz).round * step_hz).to_i
          if (snapped_hz - seed_hz).abs > [max_delta, step_hz * hunt_steps].max
            puts "  [REFINE] snap moved Δ=#{(snapped_hz - seed_hz).abs} Hz (>#{[max_delta, step_hz * hunt_steps].max}) — keeping FFT estimate"
            refined << det
            next
          end

          # Single S-meter confirm if we only have FFT peak so far.
          if smeter.nil?
            begin
              smeter = sample_smeter.call(snapped_hz, n: 4, settle: 0.04).round(1)
            rescue StandardError
              smeter = nil
            end
          end

          out = det.dup
          out[:raw_fft_peak_hz] = det[:raw_peak_hz] || det[:hz]
          out[:raw_fft_freq] = det[:freq]
          out[:raw_peak_hz] = peak_hz
          out[:hz] = snapped_hz
          out[:freq] = PWN::SDR.hz_to_s(freq: snapped_hz)
          out[:bw_hz] = peak_bw.positive? ? peak_bw : plan_bw_hz
          out[:noise_floor_db] = peak_nf if peak_nf
          out[:snr_db] = peak_snr if peak_snr
          out[:strength_db] = smeter || peak_pwr.to_f.round(2)
          out[:method] = mode == 'fft' ? :fast_spectrum_refined_fft_peak : :fast_spectrum_refined_lock_hunt
          out[:refined] = true
          delta_hz = (snapped_hz - seed_hz).abs
          sm_s = smeter ? "#{smeter} dBFS" : 'n/a'
          puts "  [REFINE] #{PWN::SDR.hz_to_s(freq: seed_hz)} → #{out[:freq]}  (Δ=#{delta_hz} Hz)  strength=#{out[:strength_db]}  smeter=#{sm_s}  bw=#{PWN::SDR.hz_to_s(freq: out[:bw_hz])}  snr=#{out[:snr_db]}"
          refined << out
        rescue StandardError => e
          puts "  [REFINE] error on detection ##{idx + 1}: #{e.class}: #{e.message} — keeping FFT estimate"
          refined << det
        end

        # De-dupe after refine — keep strongest when two seeds collapse onto one channel.
        refined.sort_by! { |d| d[:hz].to_i }
        deduped = []
        refined.each do |d|
          prev = deduped.last
          tol = fft_plan_geometry(
            plan_bw_hz: plan_bw_hz,
            step_hz: step_hz,
            measured_bw_hz: d[:bw_hz].to_i,
            res_hz: local_res
          )[:merge_tol_hz]
          # For wide plans, merge_tol of half-plan (100 kHz for FM) would
          # collapse adjacent legitimate stations. Cap at 0.6*step when step
          # is already half a channel or more.
          if plan_bw_hz >= 50_000.0
            tol = [tol, (step_hz * 0.6).to_i].min
            tol = [tol, 1].max
          end
          if prev && (d[:hz].to_i - prev[:hz].to_i).abs <= tol
            # Prefer stronger S-meter when both refined; fall back to SNR.
            prev_score = prev[:strength_db].to_f
            this_score = d[:strength_db].to_f
            if this_score == prev_score
              prev_score = prev[:snr_db].to_f
              this_score = d[:snr_db].to_f
            end
            deduped[-1] = d if this_score >= prev_score
          else
            deduped << d
          end
        end

        puts "[REFINE] done — #{detections.length} preliminary → #{deduped.length} refined"
        deduped
      rescue StandardError => e
        raise e
      end

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
      #   decoder: 'optional - Decoder key (e.g., :gsm / :rds) to start live decoding (starts recording if provided)',
      #   interactive: 'optional - Boolean; when false AND decoder responds to .sample, call sample (non-interactive Hash) instead of decode (TTY). Defaults to true.',
      #   settle_secs: 'optional - Seconds for decoder.sample (e.g. RDS; default 8)',
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
        # interactive: false → prefer decoder.sample (structured Hash) over
        # decoder.decode (TTY spinner). Used by agents / Extrospection / cron.
        interactive = opts.key?(:interactive) ? !opts[:interactive].nil? && opts[:interactive] != false : true
        settle_secs = opts[:settle_secs]
        udp_ip = opts[:udp_ip] ||= '127.0.0.1'
        udp_port = opts[:udp_port] ||= 7355
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
            # Resolve decoder module via central registry (see
            # PWN::SDR::Decoder::REGISTRY) so new protocols only need an
            # autoload + REGISTRY entry — no edit here.
            decoder_module = PWN::SDR::Decoder.resolve(decoder: decoder)

            # Initialize and start decoder (uniform .decode(freq_obj:) API).
            # When interactive:false and the module exposes .sample (e.g.
            # Decoder::RDS), return a structured Hash instead of the TTY loop.
            freq_obj[:gqrx_sock] = gqrx_sock
            freq_obj[:udp_ip] = udp_ip
            freq_obj[:udp_port] = udp_port
            freq_obj[:decoder_module] = decoder_module
            if !interactive && decoder_module.respond_to?(:sample)
              sample_opts = {
                freq_obj: freq_obj,
                gqrx_sock: gqrx_sock
              }
              sample_opts[:settle_secs] = settle_secs unless settle_secs.nil?
              freq_obj[:sample] = decoder_module.sample(sample_opts)
            else
              decoder_module.decode(freq_obj: freq_obj)
            end
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

        # Honour explicit CLI/API -S / -Q. Default strength_lock = -70.0 is only
        # a starting guess and is re-calibrated against the live S-meter noise
        # floor below unless the user provided -S. Stored squelch is always a
        # few dB under strength_lock for later decoder re-tunes; during the
        # candidate / edge walk itself we open GQRX SQL fully so I/Q + S-meter
        # are never muted.
        user_strength_lock = !opts[:strength_lock].nil?
        user_squelch = !opts[:squelch].nil?
        strength_lock = (opts[:strength_lock] || -70.0).to_f
        squelch = (opts[:squelch] || (strength_lock - 3.0)).to_f
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
            # Auto-calibrate strength_lock from live S-meter noise floor unless
            # the user passed an explicit -S. The historical rule
            #   squelch = nf.round + 7; strength_lock = squelch + 3
            # RAISED the gate into the signal cloud on dense bands (fm_radio
            # stations sit only ~10–20 dB above the quiet floor) which made
            # edge_detection refuse to drop and paint multi-MHz occupied-BW
            # blobs. Mirror #fast_scan_range: lock = nf + 8, squelch = lock - 3.
            if user_strength_lock
              if !user_squelch && squelch < noise_floor
                # Explicit -S but no -Q: keep lock, just park squelch under the
                # quieter of (lock-3, nf+1) so decoder SQL is sane later.
                squelch = [strength_lock - 3.0, noise_floor.to_f + 1.0].min.round(1)
                puts "[SCAN] derived squelch=#{squelch} dBFS under strength_lock=#{strength_lock} (nf≈#{noise_floor})"
              end
            else
              # nf + 12 dB: high enough that quiet interstitial spectrum
              # (side-lobes, distant carriers) stays under the gate, low
              # enough that real FM main lobes (~15–30 dB above nf) still
              # trip. The historical nf.round+7 formula sat *inside* the
              # carrier cloud and refused to drop on edges.
              auto_lock = (noise_floor.to_f + 12.0).round(1)
              puts "[SCAN] auto strength_lock: live S-meter nf≈#{noise_floor} dBFS → lock=#{auto_lock} dBFS (was #{strength_lock})"
              strength_lock = auto_lock
              squelch = (strength_lock - 3.0).round(1) unless user_squelch
            end
            if squelch >= strength_lock
              squelch = (strength_lock - 3.0).round(1)
              puts "[SCAN] clamped squelch to #{squelch} dBFS (< strength_lock #{strength_lock})"
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
            puts "1. The SDR's sample rate in GQRX (device Input rate — NOT remote-control)"
            puts "\s\s- Prefer: PWN::SDR::GQRX.apply_band_plan_input_rate(band_plan: :fm_radio, restart: true)"
            puts "\s\s- Or: click Configure I/O devices and set Input rate to the band-plan input_rate."
            puts "\s\s- Lower Input rate can improve regular-scan responsiveness (e.g. Pluto/HackRF ~ 1e6 for FM)."
            puts '2. Adjust the :strength_lock parameter.'
            puts '3. Adjust the :precision parameter.'
            puts '4. Disable AI module_reflection in PWN::Env'
            puts 'Happy scanning!'
            puts '-' * 86
            # print 'Pressing ENTER to begin scan...'
            # gets
            puts "\n\n\n"

            # Floor GQRX SQL during the candidate / edge / peak walk so the
            # S-meter is never muted. The calibrated :squelch is stored on
            # each detection for later decoder re-tunes (analyze_scan).
            change_squelch_resp = cmd(
              gqrx_sock: gqrx_sock,
              cmd: 'L SQL -150.0',
              resp_ok: 'RPRT 0'
            )
            puts "[SCAN] GQRX SQL floored to -150.0 for S-meter walks (stored squelch=#{squelch} dBFS, strength_lock=#{strength_lock} dBFS)"

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
                # Bound the edge walk to ~± plan_bw (or a few raster steps) so
                # adjacent co-channel carriers (fm_radio 200 kHz spacing) cannot
                # merge into a multi-MHz "occupied" lobe when strength_lock is
                # a hair too low. Hard bounds reuse the optional min_hz/max_hz
                # already supported by #edge_detection for #refine_detections.
                plan_bw_for_edge = PWN::SDR.hz_to_i(freq: bandwidth)
                plan_bw_for_edge = step_hz if plan_bw_for_edge.zero?
                # Keep the next co-channel neighbour outside the window:
                # half ≈ 0.6·plan (capped at plan itself), floored by the raster.
                half_edge = [
                  (plan_bw_for_edge * 0.6).to_i,
                  step_hz
                ].max
                half_edge = [half_edge, plan_bw_for_edge].min
                half_edge = step_hz if half_edge < 1
                candidate_signals = edge_detection(
                  gqrx_sock: gqrx_sock,
                  hz: hz,
                  step_hz: step_hz,
                  precision: precision,
                  strength_lock: strength_lock,
                  min_hz: hz - half_edge,
                  max_hz: hz + half_edge
                )
              elsif candidate_signals.length.positive?
                best_peak = find_best_peak(
                  gqrx_sock: gqrx_sock,
                  candidate_signals: candidate_signals,
                  precision: precision,
                  step_hz: step_hz,
                  strength_lock: strength_lock
                )

                # Accept peaks a few dB under strength_lock: the candidate
                # gate already verified something in this window was hot,
                # and find_best_peak averages multi-pass samples so a peaky
                # FM main lobe can report slightly under the trip level.
                if best_peak[:hz] && best_peak[:strength_db] > (strength_lock - 3.0)
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
                  prev_freq_obj[:strength_db] = best_strength_db.round(2)
                  prev_freq_obj[:iteration] = iteration_total

                  # Schema parity with #fast_scan_range signals so both
                  # modes emit the same key set (see log_signals / example
                  # scan JSON). Values are derived from edge detection +
                  # the measured noise floor rather than an FFT bin map.
                  best_hz = PWN::SDR.hz_to_i(freq: best_peak[:hz])
                  edge_hzs = candidate_signals.map { |s| PWN::SDR.hz_to_i(freq: s[:hz]) }
                  edge_lo = edge_hzs.min
                  edge_hi = edge_hzs.max
                  occupied_bw_hz = ((edge_hi - edge_lo).abs + step_hz).to_i
                  plan_bw_for_sig = PWN::SDR.hz_to_i(freq: bandwidth)
                  plan_bw_for_sig = step_hz if plan_bw_for_sig.zero?
                  # Prefer measured occupied BW when the edge walk resolved a
                  # plausible span (≤ 2× plan BW). Anything wider is almost
                  # always a multi-station merge from an under-shot lock —
                  # fall back to the band-plan channel width instead of
                  # advertising multi-MHz "signals".
                  max_plausible_bw = [plan_bw_for_sig * 2, step_hz * 4, plan_bw_for_sig].max
                  sig_bw_hz = if occupied_bw_hz.positive? && occupied_bw_hz <= max_plausible_bw
                                occupied_bw_hz
                              else
                                plan_bw_for_sig
                              end
                  nf_db = noise_floor.to_f
                  snr = (best_strength_db.to_f - nf_db).round(2)
                  prev_freq_obj[:hz] = best_hz
                  prev_freq_obj[:raw_peak_hz] = best_hz
                  prev_freq_obj[:bw_hz] = sig_bw_hz
                  prev_freq_obj[:snr_db] = snr
                  prev_freq_obj[:prominence_db] = snr
                  prev_freq_obj[:noise_floor_db] = nf_db.round(2)
                  prev_freq_obj[:chunk_center] = PWN::SDR.hz_to_s(freq: ((edge_lo + edge_hi) / 2.0).to_i)
                  prev_freq_obj[:method] = :iterative_edge_peak

                  # Soft-fail AI analysis so a missing PWN::Env[:ai] (or
                  # engine outage) never aborts an otherwise successful
                  # detection. module_reflection=false or bare `require
                  # 'pwn'` without Driver::Parser both leave Env[:ai] nil.
                  begin
                    ai_analysis = PWN::AI::Agent::GQRX.analyze(
                      request: prev_freq_obj.to_json,
                      location: location
                    )
                    prev_freq_obj[:ai_analysis] = ai_analysis unless ai_analysis.nil?
                  rescue StandardError => e
                    puts "[SCAN] AI analysis skipped: #{e.class}: #{e.message}"
                  end
                  puts JSON.pretty_generate(prev_freq_obj)
                  puts '-' * 86
                  puts "\n\n\n"
                  signals_detected.push(prev_freq_obj)
                  log_signals(
                    signals_detected: signals_detected,
                    timestamp_start: timestamp_start,
                    scan_log: scan_log,
                    meta: {
                      precision: precision,
                      plan_bw_hz: plan_bw_for_sig,
                      method: :scan_range
                    }
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
              scan_log: scan_log,
              meta: {
                precision: precision,
                plan_bw_hz: PWN::SDR.hz_to_i(freq: bandwidth),
                method: :scan_range
              }
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
            iteration_metrics: iteration_metrics,
            meta: {
              precision: precision,
              plan_bw_hz: PWN::SDR.hz_to_i(freq: bandwidth),
              method: :scan_range
            }
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

      # ------------------------------------------------------------------
      # GQRX *device* sample-rate configuration
      #
      # The remote-control protocol (see #cmd header / remote-control.txt)
      # exposes F/M/L/U/… but NOT input sample rate. GQRX's Input rate is a
      # hardware/device-dialog setting persisted under:
      #
      #   ~/.config/gqrx/<session>.conf  →  [input] sample_rate=<int>
      #
      # and only applied when GQRX (re)opens the SDR. Therefore the only
      # reliable way to configure sample rate for the *currently connected*
      # SDR is:
      #   1. resolve the active conf (+ optional SoapySDR probe for legal rates)
      #   2. rewrite [input] sample_rate=
      #   3. bounce GQRX (or prompt the operator to reopen I/O devices)
      #
      # Band-plan defaults live on
      # PWN::SDR::FrequencyAllocation.band_plans[<plan>][:input_rate]
      # (e.g. fm_radio → 1_000_000, ads_b* → 2_000_000). Prefer
      # #set_input_rate / #apply_band_plan_input_rate over hand edits.
      # ------------------------------------------------------------------

      # Supported Method Parameters::
      # path = PWN::SDR::GQRX.config_path(
      #   path: 'optional - absolute path to a GQRX .conf (defaults to ~/.config/gqrx/default.conf or recentconfig)'
      # )
      public_class_method def self.config_path(opts = {})
        return opts[:path].to_s if opts[:path] && !opts[:path].to_s.empty?

        conf_dir = File.join(Dir.home, '.config', 'gqrx')
        recent = File.join(conf_dir, 'recentconfig.cfg')
        if File.file?(recent)
          # recentconfig.cfg is usually a single path line
          candidate = File.read(recent).to_s.lines.map(&:strip).find { |l| !l.empty? && !l.start_with?('#') }
          return candidate if candidate && File.file?(candidate)
        end

        default = File.join(conf_dir, 'default.conf')
        return default if File.file?(default)

        # last resort: newest *.conf
        newest = Dir.glob(File.join(conf_dir, '*.conf')).max_by { |f| File.mtime(f) }
        return newest if newest

        default
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # info = PWN::SDR::GQRX.read_input_config(
      #   path: 'optional - GQRX conf path (defaults to #config_path)'
      # )
      # Returns Hash with :path, :device, :frequency, :input_rate, :raw
      public_class_method def self.read_input_config(opts = {})
        path = config_path(path: opts[:path])
        raise "ERROR: GQRX conf not found: #{path}" unless File.file?(path)

        text = File.read(path)
        # Restrict to the [input] section (until next [section] or EOF).
        input = text[/^\[input\][^\[]*/m].to_s
        raise "ERROR: no [input] section in #{path}" if input.empty?

        device = input[/^device=(.*)$/, 1].to_s.strip
        # strip surrounding quotes GQRX sometimes writes
        device = device.sub(/\A"(.*)"\z/, '\1')
        freq_s = input[/^frequency=(.*)$/, 1].to_s.strip
        rate_s = input[/^sample_rate=(.*)$/, 1].to_s.strip

        {
          path: path,
          device: device,
          frequency: (freq_s.empty? ? nil : freq_s.to_i),
          input_rate: (rate_s.empty? ? nil : rate_s.to_i),
          raw: input
        }
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # rates = PWN::SDR::GQRX.device_input_rates(
      #   device: 'optional - SoapySDR args string (defaults to [input] device= from conf)',
      #   path: 'optional - GQRX conf path used when :device omitted'
      # )
      # Returns Array<Integer> of legal sample rates (Hz). Empty when unprobeable.
      public_class_method def self.device_input_rates(opts = {})
        device = opts[:device].to_s
        if device.empty?
          conf = read_input_config(path: opts[:path])
          device = conf[:device].to_s
        end

        # Prefer SoapySDRUtil --probe (works for every Soapy driver GQRX uses).
        # device strings look like:
        #   "device=HackRF Pro,driver=hackrf,..."  or  "driver=plutosdr,..."
        # Conf may be stale (e.g. still names Pluto while a HackRF is what is
        # actually attached) — fall through a probe chain until rates resolve.
        candidates = []
        candidates << device unless device.empty?
        if (driver = device[/driver=([^,]+)/, 1])
          candidates << "driver=#{driver}"
        end
        begin
          find_out = `SoapySDRUtil --find 2>/dev/null`.to_s
          find_out.scan(/driver\s*=\s*(\S+)/i).flatten.uniq.each do |d|
            candidates << "driver=#{d}"
          end
        rescue StandardError
          nil
        end
        candidates.uniq!

        out = ''
        candidates.each do |probe_arg|
          next if probe_arg.to_s.empty?

          candidate_out = `SoapySDRUtil --probe="#{probe_arg.to_s.gsub('"', '\\"')}" 2>/dev/null`
          if candidate_out.to_s =~ /Sample rates:/i
            out = candidate_out
            break
          end
        end
        return [] if out.to_s.strip.empty?

        rates = []
        out.each_line do |line|
          next unless line =~ /Sample rates:\s*(.+)/i

          spec = Regexp.last_match(1).strip
          # Formats observed:
          #   "1, 2, 3, 4, 5, ..., 16, 17, 18, 19, 20 MSps"
          #   "0.25, 0.5, ..., 3.2 MSps"
          #   "250000, 1024000, 1800000, 2400000, 3200000 Hz"
          unit = :hz
          unit = :msps if spec =~ %r{MSps|MS/s|MHz}i
          unit = :ksps if spec =~ %r{kSps|kS/s|kHz}i

          nums = spec.scan(/(\d+(?:\.\d+)?)/).flatten.map(&:to_f)
          # When "...," range ellipsis is present with endpoints, expand integers.
          if spec.include?('...') && nums.length >= 2 && unit == :msps
            # HackRF style: 1,2,3,...,20 → integer Msps
            lo = nums.first
            hi = nums.last
            step = 1.0
            step = nums[1] - nums[0] if nums.length >= 3 && (nums[1] - nums[0]).positive?
            n = lo
            while n <= hi + 1e-9
              rates << (n * 1_000_000).round
              n += step
            end
          else
            nums.each do |n|
              hz = case unit
                   when :msps then (n * 1_000_000).round
                   when :ksps then (n * 1_000).round
                   else n.round
                   end
              rates << hz
            end
          end
        end
        rates.uniq.sort
      rescue StandardError
        []
      end

      # Supported Method Parameters::
      # hz = PWN::SDR::GQRX.nearest_input_rate(
      #   input_rate: 'required - desired input rate Hz',
      #   rates: 'optional - Array of legal rates (defaults to #device_input_rates)'
      # )
      # Snaps desired rate onto the closest legal device rate (>= preferred when
      # possible, else nearest). Returns desired unchanged when rates empty.
      public_class_method def self.nearest_input_rate(opts = {})
        desired = (opts[:input_rate] || opts[:sample_rate]).to_i
        raise 'ERROR: :input_rate required' unless desired.positive?

        rates = opts[:rates]
        rates = device_input_rates(device: opts[:device], path: opts[:path]) if rates.nil?
        return desired if rates.nil? || rates.empty?

        # Prefer the smallest legal rate that still covers the ask (Nyquist /
        # panoramic span), else the max the hardware can do.
        ge = rates.select { |r| r >= desired }
        return ge.min if ge.any?

        rates.max
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # result = PWN::SDR::GQRX.set_input_rate(
      #   input_rate: 'required - desired GQRX Input rate in Hz (Integer)',
      #   path: 'optional - GQRX conf path (defaults to #config_path)',
      #   clamp: 'optional - snap to nearest legal device rate (default true)',
      #   restart: 'optional - kill+respawn gqrx so the new rate is applied (default false)',
      #   gqrx_bin: 'optional - gqrx binary path when restart:true (default `which gqrx`)'
      # )
      # Rewrites [input] sample_rate= in the active GQRX conf. Does NOT use the
      # remote-control socket — input rate is not part of that protocol.
      # Returns { path:, previous:, input_rate:, clamped_from:, restarted:, device: }.
      public_class_method def self.set_input_rate(opts = {})
        desired = (opts[:input_rate] || opts[:sample_rate]).to_i
        raise 'ERROR: :input_rate required (positive Integer Hz)' unless desired.positive?

        path = config_path(path: opts[:path])
        conf = read_input_config(path: path)
        previous = conf[:input_rate]
        device = conf[:device]

        applied = desired
        clamped_from = nil
        clamp = opts.key?(:clamp) ? !opts[:clamp].nil? && opts[:clamp] != false : true
        if clamp
          snapped = nearest_input_rate(
            input_rate: desired,
            device: device,
            path: path
          )
          if snapped != desired
            clamped_from = desired
            applied = snapped
          end
        end

        text = File.read(path)
        if text.match?(/^\[input\][^\[]*sample_rate=/m)
          text = text.sub(/^(sample_rate=).*$/, "\\1#{applied}")
        else
          # Insert sample_rate under [input] if the key is somehow missing.
          text = text.sub(/^\[input\]\s*$/, "[input]\nsample_rate=#{applied}")
        end
        File.write(path, text)

        restarted = false
        if opts[:restart]
          restarted = restart_gqrx(
            gqrx_bin: opts[:gqrx_bin],
            conf_path: path
          )
        end

        {
          path: path,
          previous: previous,
          input_rate: applied,
          clamped_from: clamped_from,
          restarted: restarted,
          device: device,
          note: restarted ? 'GQRX restarted to apply input_rate' : 'Restart GQRX (or reopen I/O devices) to apply input_rate'
        }
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # result = PWN::SDR::GQRX.apply_band_plan_input_rate(
      #   band_plan: 'required - key from PWN::SDR::FrequencyAllocation.band_plans (e.g. :fm_radio, :ads_b1090)',
      #   path: 'optional - GQRX conf path',
      #   clamp: 'optional - snap to device-legal rate (default true)',
      #   restart: 'optional - bounce GQRX after write (default false)',
      #   input_rate: 'optional - override the band-plan recommended rate'
      # )
      # Looks up FrequencyAllocation[:input_rate], clamps to the currently
      # configured SDR's legal rates, and writes it into GQRX's conf.
      public_class_method def self.apply_band_plan_input_rate(opts = {})
        key = opts[:band_plan] || opts[:profile] || opts[:assume_band_plan]
        raise 'ERROR: :band_plan required' if key.nil?

        plans = PWN::SDR::FrequencyAllocation.band_plans
        plan_key = key.to_s.strip.downcase.tr('-', '_').to_sym
        plan = plans[plan_key]
        raise "ERROR: unknown band plan #{key.inspect}. Known: #{plans.keys.sort.join(', ')}" if plan.nil?

        desired = (opts[:input_rate] || opts[:sample_rate] || plan[:input_rate] || 1_000_000).to_i
        result = set_input_rate(
          input_rate: desired,
          path: opts[:path],
          clamp: opts.fetch(:clamp, true),
          restart: opts[:restart],
          gqrx_bin: opts[:gqrx_bin]
        )
        result.merge(
          band_plan: plan_key,
          band_plan_input_rate: plan[:input_rate],
          bandwidth: plan[:bandwidth],
          demodulator_mode: plan[:demodulator_mode]
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # ok = PWN::SDR::GQRX.restart_gqrx(
      #   gqrx_bin: 'optional - path to gqrx binary',
      #   conf_path: 'optional - pass -c <conf> on relaunch'
      # )
      # Best-effort: SIGTERM any running gqrx, then relaunch detached.
      # Returns true when a new process was spawned.
      public_class_method def self.restart_gqrx(opts = {})
        bin = opts[:gqrx_bin].to_s
        bin = `which gqrx 2>/dev/null`.to_s.strip if bin.empty?
        raise 'ERROR: gqrx binary not found' if bin.empty? || !File.executable?(bin)

        # Graceful stop so conf is flushed.
        pids = `pgrep -x gqrx 2>/dev/null`.to_s.split.map(&:to_i)
        pids.each do |pid|
          Process.kill('TERM', pid)
        rescue Errno::ESRCH
          nil
        end
        # Wait up to ~5s for exit
        50.times do
          break if `pgrep -x gqrx 2>/dev/null`.to_s.strip.empty?

          sleep 0.1
        end
        # Force if still up
        `pgrep -x gqrx 2>/dev/null`.to_s.split.map(&:to_i).each do |pid|
          Process.kill('KILL', pid)
        rescue Errno::ESRCH
          nil
        end

        conf = opts[:conf_path].to_s
        conf = config_path if conf.empty?
        cmd = if conf && File.file?(conf)
                [bin, '-c', conf]
              else
                [bin]
              end

        pid = spawn(
          *cmd,
          out: '/dev/null',
          err: '/dev/null',
          pgroup: true
        )
        Process.detach(pid)
        # Brief wait for remote control to come up (best effort).
        30.times do
          break if system('bash', '-c', 'exec 3<>/dev/tcp/127.0.0.1/7356', out: File::NULL, err: File::NULL)

          sleep 0.2
        end
        true
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
        avg = (opts[:avg] || 8).to_i
        capture_secs = (opts[:capture_secs] || 0.10).to_f
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
        sleep(capture_secs + 0.06)
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

        # ---- FFT (FFTW3 when available, pure-Ruby Cooley-Tukey fallback) ----
        raise 'ERROR: I/Q read empty or short' if raw_bytes.nil? || raw_bytes.bytesize < 8

        # GQRX raw I/Q: little-endian float32 interleaved I,Q,I,Q,...
        floats = raw_bytes.unpack('e*')
        n_iq = [floats.length / 2, num_samples].min
        # Keep flat interleaved I/Q for FFTW path; Complex array for Ruby path.
        raise "ERROR: nfft (#{nfft}) must be a power of two" unless nfft.nobits?(nfft - 1)

        two_pi = 2.0 * Math::PI
        hann = Array.new(nfft) { |k| 0.5 * (1.0 - Math.cos(two_pi * k / (nfft - 1))) }
        hop = [nfft / 2, 1].max
        use_fftw = begin
          defined?(PWN::FFI::FFTW) && PWN::FFI::FFTW.available?
        rescue StandardError
          false
        end

        specs = []
        if use_fftw
          # Native complex DFT via libfftw3f — orders of magnitude faster than
          # pure-Ruby butterflies at nfft>=2048 / avg>=4. Flat interleaved
          # windowed block is handed to cfft; we fftshift |X|^2 ourselves.
          pos = 0
          while (pos + nfft) <= n_iq && specs.length < avg
            blk = Array.new(2 * nfft)
            nfft.times do |k|
              base = 2 * (pos + k)
              w = hann[k]
              blk[2 * k] = floats[base].to_f * w
              blk[(2 * k) + 1] = floats[base + 1].to_f * w
            end
            begin
              pairs = PWN::FFI::FFTW.cfft(iq: blk, n: nfft)
              half = nfft / 2
              # fftshift: out[0:half]=in[half:n], out[half:n]=in[0:half]
              # → bins aligned -sr/2 .. +sr/2 matching pure-Ruby path.
              shifted_pwr = Array.new(nfft)
              (0...half).each do |i|
                re, im = pairs[i + half]
                shifted_pwr[i] = (re * re) + (im * im)
                re, im = pairs[i]
                shifted_pwr[i + half] = (re * re) + (im * im)
              end
              specs << shifted_pwr
            rescue StandardError
              use_fftw = false
              break
            end
            pos += hop
          end
        end

        unless use_fftw && !specs.empty?
          # Pure-Ruby complex FFT fallback (radix-2 Cooley-Tukey).
          iq = Array.new(n_iq) { |i| Complex(floats[2 * i], floats[(2 * i) + 1]) }
          log2n = Math.log2(nfft).to_i
          fft_proc = lambda do |x|
            n = x.length
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

        # Null DC / LO-leakage bin and band-edge guard bins BEFORE detection so
        # they neither skew the noise-floor estimate nor register as phantom
        # signals at the center of every retune step.
        guard = [(nfft * 0.02).to_i, 2].max
        dc = nfft / 2
        sorted_db = db.sort
        median_nf = sorted_db[sorted_db.length / 2].to_f
        db[dc] = median_nf
        (0...guard).each do |gi|
          db[gi] = median_nf
          db[nfft - 1 - gi] = median_nf
        end

        # Noise floor: median of dB (robust). Callers may supply expected
        # channel_bw_hz so min_dist tracks real channel spacing (pager_flex
        # 20 kHz / fm_radio 200 kHz) instead of a fixed 6 kHz heuristic that
        # over-fragments wide carriers and under-separates dense narrow ones.
        noise_floor = median_nf
        channel_bw_hz = (opts[:channel_bw_hz] || opts[:plan_bw_hz] || 0).to_f
        channel_bw_hz = 0.0 if channel_bw_hz.negative?

        # Peak picker (relative thresholds only — absolute S-meter dBFS is
        # meaningless on uncalibrated 10*log10(|FFT|^2)):
        #   height   : median_nf + height_db (default 12)
        #   prom     : >= prom_thr (default 8)
        #   min_dist : plan-parametric via #fft_plan_geometry — half channel /
        #              raster / step-aware floor, converted to bins by res_hz.
        # Callers may tighten with opts[:peak_height_db]/[:peak_prom_db]/
        # opts[:step_hz] (raster) for denser narrowband plans.
        height_db = (opts[:peak_height_db] || 12.0).to_f
        prom_thr = (opts[:peak_prom_db] || 8.0).to_f
        height_thr = noise_floor + height_db
        step_for_geo = (opts[:step_hz] || opts[:raster_hz] || 0).to_f
        geo = fft_plan_geometry(
          plan_bw_hz: channel_bw_hz,
          step_hz: step_for_geo,
          res_hz: res_hz
        )
        sep_hz = geo[:sep_hz]
        min_dist = geo[:min_dist_bins]

        candidates = []
        (1...(nfft - 1)).each do |i|
          next unless db[i] >= height_thr
          next unless db[i] > db[i - 1] && db[i] >= db[i + 1]

          # prominence: peak - highest of the two side-valley minima toward the
          # nearest higher-or-equal neighbour (scipy.signal.peak_prominences)
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

        # Occupied-BW edge walk is RELATIVE TO THE PEAK, never to the global
        # noise floor. Walking down to noise+3.5 dB on a dense paging band
        # (or any band with elevated continuum / many neighbours) floods the
        # whole lobe and reports hundreds of kHz of "occupied" bandwidth —
        # which then breaks min_bw_ratio filtering, merge tolerance, and the
        # refine window. Use a -6 dB from-peak contour (≈ half-power / 3 dB
        # each side) with a hard cap of ~2 * channel_bw when known.
        half_pwr_drop_db = 6.0
        # Cap occupied-BW walk to ~1 plan_bw each side of peak (plan-parametric).
        max_half_bins = geo[:max_half_bins]

        signals = selected.map do |c|
          p = c[:idx]
          edge_rel = c[:pwr] - half_pwr_drop_db
          l = p
          l -= 1 while l.positive? && (p - l) < max_half_bins && db[l - 1] >= edge_rel
          r = p
          r += 1 while r < (nfft - 1) && (r - p) < max_half_bins && db[r + 1] >= edge_rel
          bw_hz = ([r - l + 1, 1].max * res_hz).to_i

          # Power-weighted centroid over the -6 dB lobe → sub-bin center that
          # lands much closer to the true channel than the peak bin alone
          # (critical for precision-4 / 1 kHz FLEX raster snaps).
          lin_sum = 0.0
          mom_sum = 0.0
          (l..r).each do |bi|
            lin = 10.0**(db[bi] / 10.0)
            lin_sum += lin
            mom_sum += lin * bi
          end
          centroid_bin = lin_sum.positive? ? (mom_sum / lin_sum) : p.to_f
          center = (center_hz + ((centroid_bin - (nfft / 2)) * res_hz)).round
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

        # NOTE: no fallback. A quiet chunk correctly returns signals: [].

        {
          center_freq_hz: center_hz,
          center_freq: PWN::SDR.hz_to_s(freq: center_hz),
          sample_rate: sample_rate,
          visible_span_hz: sample_rate,
          nfft: nfft,
          avg: avg,
          resolution_hz: res_hz.round(2),
          samples: n_iq,
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
      #   min_snr_db: 'optional - Minimum SNR in dB above per-chunk noise floor to report (defaults to 12.0)',
      #   precision: 'optional - Band-plan channel raster; detections snapped to 10**(precision-1) Hz grid (defaults to 5)',
      #   min_bw_ratio: 'optional - Reject FFT peaks narrower than min_bw_ratio * plan bandwidth as spurs (defaults to 0.0 = off; half-power carrier BW is often << plan BW)',
      #   demodulator_mode: 'optional - Demodulator mode APPLIED to GQRX + attributed to detections (defaults to WFM)',
      #   bandwidth: 'optional - Passband bandwidth APPLIED to GQRX + attributed to detections (defaults to "200.000")',
      #   squelch: 'optional - Squelch level APPLIED to GQRX (defaults to strength_lock - 3.0)',
      #   audio_gain_db: 'optional - Audio gain in dB APPLIED to GQRX (defaults to 0.0)',
      #   rf_gain: 'optional - RF gain APPLIED to GQRX (defaults to 0.0)',
      #   intermediate_gain: 'optional - Intermediate gain APPLIED to GQRX (defaults to 32.0)',
      #   baseband_gain: 'optional - Baseband gain APPLIED to GQRX (defaults to 10.0)',
      #   decoder: 'optional - Decoder key (e.g. :gsm) to attribute to detections',
      #   location: 'optional - Location string for AI analysis',
      #   keep_spectrum: 'optional - if true return raw spectrum arrays too (large)',
      #   refine: 'optional - After panoramic FFT, re-walk each detection with traditional edge_detection + find_best_peak scoped around the candidate to lock the exact channel frequency (defaults to true)'
      # )
      #
      # Uses chunk-wise retuning where chunk = sample_rate so that the *entire visible band* (waterfall width)
      # is captured via a single FFT each time rather than point-by-point hops.
      # This yields near real-time panoramic coverage. Update rate is roughly (retune + capture + fft) per chunk.
      #
      # Per-signal output shape is INTENTIONALLY IDENTICAL to #scan_range /
      # #init_freq (:freq, :demodulator_mode, :bandwidth, :strength_db,
      # :decoder, :squelch, :strength_lock, :iteration, :ai_analysis) so that
      # #analyze_scan / #analyze_log and downstream decoders behave the same
      # regardless of which scan mode produced the log. FFT-specific extras
      # (:hz, :bw_hz, :snr_db, :prominence_db, :noise_floor_db, :chunk_center,
      # :method) are appended for provenance.
      public_class_method def self.fast_scan_range(opts = {})
        gqrx_sock = opts[:gqrx_sock]
        raise 'gqrx_sock required' if gqrx_sock.nil?

        ranges = opts[:ranges]
        raise 'ranges required as array of hashes' unless ranges.is_a?(Array) && !ranges.empty?

        sr = (opts[:sample_rate] || 1_000_000).to_i
        nfft = (opts[:nfft] || 2048).to_i
        # avg/capture defaults lean fast — lock-hunt refine recovers weak-edge hits.
        avgs = (opts[:avg] || 6).to_i
        cap = (opts[:capture_secs] || 0.08).to_f
        strength_lock = (opts[:strength_lock] || -70.0).to_f
        min_snr_db = (opts[:min_snr_db] || 18.0).to_f
        keep_spec = opts[:keep_spectrum] ? true : false
        res_hz = sr / nfft.to_f
        demodulator_mode = opts[:demodulator_mode] ||= :WFM
        bandwidth = opts[:bandwidth] ||= '200.000'
        squelch = (opts[:squelch] || (strength_lock - 3.0)).to_f
        decoder = opts[:decoder]
        location = opts[:location] ||= 'United States'
        log_timestamp = Time.now.strftime('%Y-%m-%d')

        # ---- Band-plan-aware candidate validation -------------------------
        # `:precision` and `:bandwidth` come straight from
        # PWN::SDR::FrequencyAllocation.band_plans. They encode two facts the
        # raw FFT peak detector cannot know:
        #   1. The channel *raster* (step_hz = 10**(precision-1)) that real
        #      emitters are aligned to. Detections are snapped to this grid so
        #      the same station seen in overlapping chunks lands on ONE hz.
        #   2. The expected *occupied bandwidth* of a single legitimate
        #      emitter. Any FFT peak narrower than min_bw_ratio * plan_bw_hz
        #      is a spur / pilot / IMD product, not a channel; any two peaks
        #      closer than ~half a plan_bw_hz are sub-components of the SAME
        #      emitter (e.g. WFM stereo pilot @19k, RDS @57k) and are merged.
        precision = (opts[:precision] || 5).to_i
        precision = precision.clamp(1, 12)
        step_hz = 10**(precision - 1)
        plan_bw_hz = PWN::SDR.hz_to_i(freq: bandwidth)
        plan_bw_hz = step_hz if plan_bw_hz.zero?
        # min_bw_ratio is OPTIONAL and OFF by default (0.0). Half-power occupied
        # width of a real FLEX/POCSAG/NBFM carrier is often << channel assignment
        # (e.g. ~1–5 kHz vs plan 20 kHz), so a 0.30*plan floor rejected the
        # actual strongest peaks. Floor is always ≥ 1 FFT bin; callers wanting
        # spur rejection by width can still pass --min-bw-ratio.
        min_bw_ratio = (opts[:min_bw_ratio] || 0.0).to_f
        min_bw_hz = [res_hz.ceil, 1].max
        min_bw_hz = [min_bw_hz, (plan_bw_hz * min_bw_ratio).to_i].max if min_bw_ratio.positive?

        range_str = ranges.map do |rr|
          a = PWN::SDR.hz_to_s(freq: PWN::SDR.hz_to_i(freq: rr[:start_freq]))
          b = PWN::SDR.hz_to_s(freq: PWN::SDR.hz_to_i(freq: rr[:target_freq]))
          "#{a}-#{b}"
        end.join('_')
        scan_log = opts[:scan_log] ||= "/tmp/pwn_sdr_gqrx_scan_#{range_str}_#{log_timestamp}.json"

        ts_start = Time.now.strftime('%Y-%m-%d %H:%M:%S%z')
        detected = []
        all_specs = [] if keep_spec

        # ---- Panoramic capture radio setup --------------------------------
        # CRITICAL: GQRX IQRECORD dumps the *demodulator IF* stream, not the
        # raw ADC. Forcing the band-plan demod/passband here (e.g. FM / 20 kHz
        # for pager_flex) collapsed the panoramic view to a 20 kHz keyhole and
        # destroyed edge/BW detection. Capture always uses RAW with a passband
        # equal to sample_rate so each chunk really spans `sr` Hz. Band-plan
        # demod/bandwidth/squelch are applied later (during refine / analyze)
        # and still attributed onto every detection hash for decoder re-tunes.
        mode_str = demodulator_mode.to_s.upcase
        passband_hz = plan_bw_hz # decoder IF — applied only in refine phase
        capture_mode = 'RAW'
        capture_passband_hz = sr
        audio_gain_db = (opts[:audio_gain_db] || 0.0).to_f
        rf_gain = (opts[:rf_gain] || 0.0).to_f
        intermediate_gain = (opts[:intermediate_gain] || 32.0).to_f
        baseband_gain = (opts[:baseband_gain] || 10.0).to_f
        user_strength_lock = !opts[:strength_lock].nil? # honour explicit -S (driver may pass key:nil)

        puts '-' * 86
        puts '[FAST-SCAN] SESSION PARAMS >> panoramic capture + deferred band-plan IF:'
        puts "  capture mode     : #{capture_mode} #{PWN::SDR.hz_to_s(freq: capture_passband_hz)} Hz  (full sample_rate span)"
        puts "  band-plan mode   : #{mode_str} #{PWN::SDR.hz_to_s(freq: passband_hz)} Hz  (applied at refine / decoder)"
        puts "  squelch (L SQL)  : #{squelch} dBFS"
        puts "  strength_lock    : #{strength_lock} dBFS  (S-meter edge gate; auto-calibrated unless -S given)"
        puts "  audio_gain (AF)  : #{audio_gain_db} dB"
        puts "  rf_gain          : #{rf_gain}"
        puts "  intermediate_gain: #{intermediate_gain}"
        puts "  baseband_gain    : #{baseband_gain}"
        puts "  decoder          : #{decoder.inspect}"
        puts "  raster/precision : #{PWN::SDR.hz_to_s(freq: step_hz)} Hz (precision #{precision})"
        puts "  plan_bw/min_bw   : #{PWN::SDR.hz_to_s(freq: plan_bw_hz)} Hz / min occupied >= #{PWN::SDR.hz_to_s(freq: min_bw_hz)} Hz (ratio #{min_bw_ratio})"
        puts "  min_snr          : #{min_snr_db} dB  (FFT scale, not S-meter)"
        puts "  sample_rate/nfft : #{sr} SPS / #{nfft}"
        puts '-' * 86

        # Floor squelch for capture so we never mute I/Q while sweeping.
        cmd(
          gqrx_sock: gqrx_sock,
          cmd: 'L SQL -150.0',
          resp_ok: 'RPRT 0'
        )

        # Disable RDS during the panoramic scan.
        begin
          cmd(gqrx_sock: gqrx_sock, cmd: 'U RDS 0', resp_ok: 'RPRT 0')
        rescue StandardError
          nil
        end

        # RAW + sample_rate passband = full panoramic IF for IQRECORD.
        cmd(
          gqrx_sock: gqrx_sock,
          cmd: "M #{capture_mode} #{capture_passband_hz}",
          resp_ok: 'RPRT 0'
        )

        cmd(
          gqrx_sock: gqrx_sock,
          cmd: "L AF #{audio_gain_db}",
          resp_ok: 'RPRT 0'
        )

        cmd(
          gqrx_sock: gqrx_sock,
          cmd: "L RF_GAIN #{rf_gain}",
          resp_ok: 'RPRT 0'
        )

        cmd(
          gqrx_sock: gqrx_sock,
          cmd: "L IF_GAIN #{intermediate_gain}",
          resp_ok: 'RPRT 0'
        )

        cmd(
          gqrx_sock: gqrx_sock,
          cmd: "L BB_GAIN #{baseband_gain}",
          resp_ok: 'RPRT 0'
        )

        # Brief settle so the backend reconfigures IF filter around RAW span.
        sleep 0.20

        begin
          applied_mode = cmd(gqrx_sock: gqrx_sock, cmd: 'm').to_s.strip
          puts "[FAST-SCAN] GQRX capture mode/passband='#{applied_mode}' (expect RAW #{capture_passband_hz})"
        rescue StandardError => e
          puts "[FAST-SCAN] WARNING: could not read back mode (#{e.class}: #{e.message})"
        end

        ranges.each do |r|
          s_hz = PWN::SDR.hz_to_i(freq: r[:start_freq])
          t_hz = PWN::SDR.hz_to_i(freq: r[:target_freq])
          dir = t_hz >= s_hz ? 1 : -1
          # Soft chunk-edge guard (also applied post-snapshot). Cap so a
          # wide plan (fm_radio 200 kHz) at modest sample_rate (1 Msps) does
          # not eat the entire usable span.
          edge_floor = [plan_bw_hz, 2 * step_hz, 1_000].max
          edge_floor = [edge_floor, (sr * 0.12).to_i].min # never >12% of span
          edge_guard_hz = [(sr * 0.05).to_i, edge_floor].max
          usable = sr - (2 * edge_guard_hz)
          usable = [usable, (sr * 0.50).to_i].max
          # Step so successive usable regions OVERLAP by ~15% (was fixed
          # 0.85*sr, which for FM left ~350 kHz holes per chunk at 1 Msps).
          step = (usable * 0.85).to_i
          step = [step, step_hz, 50_000].max
          step = sr if step > sr

          puts "[FAST-SCAN] Panoramic covering #{PWN::SDR.hz_to_s(freq: s_hz)}..#{PWN::SDR.hz_to_s(freq: t_hz)} using #{sr} SPS chunks (step #{PWN::SDR.hz_to_s(freq: step)}, edge_guard=#{PWN::SDR.hz_to_s(freq: edge_guard_hz)}, usable≈#{PWN::SDR.hz_to_s(freq: usable)})"

          h = s_hz
          while dir.positive? ? (h <= t_hz) : (h >= t_hz)
            # retune to put this chunk in the visible IF
            tune_to(gqrx_sock: gqrx_sock, hz: h)
            sleep 0.08 # allow GQRX / SDR to settle the IF filter & AGC etc.

            snap = get_spectrum_snapshot(
              gqrx_sock: gqrx_sock,
              center_freq: h,
              sample_rate: sr,
              nfft: nfft,
              avg: avgs,
              capture_secs: cap,
              strength_offset_db: opts[:strength_offset_db],
              channel_bw_hz: plan_bw_hz,
              step_hz: step_hz
            )

            all_specs << snap if keep_spec

            sigs = snap[:signals] || []
            # Gate on SNR (scale-independent) rather than absolute power_db,
            # because 10*log10(|FFT|^2) is uncalibrated and cannot be compared
            # against the -70 dBFS S-meter strength_lock without a
            # user-supplied strength_offset_db. NO fallback: a quiet chunk
            # correctly contributes zero detections.
            # Upper BW bound: half-power estimate should not exceed ~2× plan.
            # Stops continuum / multi-carrier blobs from surviving as one "signal".
            max_bw_hz = [(plan_bw_hz * 2), (step_hz * 8), min_bw_hz].max
            # edge_guard_hz / usable computed once per range above so the
            # step and post-snapshot acceptance region stay consistent.
            chunk_lo = h - (sr / 2) + edge_guard_hz
            chunk_hi = h + (sr / 2) - edge_guard_hz
            # Also clamp to the requested scan range.
            range_lo = [s_hz, t_hz].min
            range_hi = [s_hz, t_hz].max

            sigs.each do |sig|
              next if sig[:snr_db] && sig[:snr_db] < min_snr_db

              raw_candidate_hz = (sig[:hz] || sig[:freq_hz]).to_i
              next if raw_candidate_hz < range_lo || raw_candidate_hz > range_hi
              next if raw_candidate_hz < chunk_lo || raw_candidate_hz > chunk_hi
              # Require decent prominence when present (noise continuum has low prom).
              next if sig[:prominence_db] && sig[:prominence_db].to_f < 8.0

              # NOTE: strength_lock is an S-meter (dBFS) gate. FFT power_db is
              # uncalibrated 10*log10(|X|^2) and MUST NOT be compared to it
              # unless the caller supplied strength_offset_db. Skip that gate
              # for panoramic detections — min_snr_db is the correct filter.
              next if opts[:strength_offset_db] && sig[:power_db] && sig[:power_db] < strength_lock
              # Band-plan width gates (relative half-power BW estimator).
              next if sig[:bw_hz] && sig[:bw_hz] < min_bw_hz
              next if sig[:bw_hz] && sig[:bw_hz] > max_bw_hz

              raw_hz = sig[:hz] || sig[:freq_hz]
              # Snap to the band-plan channel raster so the same emitter seen
              # in multiple overlapping chunks / at multiple sub-peaks lands
              # on ONE canonical frequency before dedup.
              hz = ((raw_hz.to_f / step_hz).round * step_hz).to_i
              # Shape MUST match #scan_range / #init_freq freq_obj so that
              # analyze_scan / analyze_log and downstream decoders work
              # identically regardless of which scan mode produced the log.
              detected << {
                freq: PWN::SDR.hz_to_s(freq: hz),
                demodulator_mode: demodulator_mode,
                bandwidth: bandwidth,
                strength_db: sig[:power_db].to_f.round(2),
                decoder: decoder,
                squelch: squelch,
                strength_lock: strength_lock,
                audio_gain_db: audio_gain_db,
                rf_gain: rf_gain,
                intermediate_gain: intermediate_gain,
                baseband_gain: baseband_gain,
                iteration: 1,
                hz: hz,
                raw_peak_hz: raw_hz.to_i,
                bw_hz: sig[:bw_hz].to_i,
                snr_db: sig[:snr_db].to_f.round(2),
                prominence_db: sig[:prominence_db].to_f.round(2),
                noise_floor_db: sig[:noise_floor_db].to_f.round(2),
                chunk_center: PWN::SDR.hz_to_s(freq: h),
                method: :fast_spectrum_sdrangel_like
              }
            end
            h += step * dir
          end
        end

        # Cross-chunk / intra-emitter merge. A single legitimate emitter
        # occupies ~plan_bw_hz, so ANY peaks within half that width (or one
        # raster step, or half the *measured* width, whichever is largest) are
        # the same channel. Keep the highest-SNR representative.
        detected.sort_by! { |d| d[:hz] }
        merged = []
        detected.each do |d|
          prev = merged.last
          tol = fft_plan_geometry(
            plan_bw_hz: plan_bw_hz,
            step_hz: step_hz,
            res_hz: res_hz,
            measured_bw_hz: d[:bw_hz].to_i
          )[:merge_tol_hz]
          if prev && (d[:hz] - prev[:hz]).abs <= tol
            merged[-1] = d if (d[:snr_db] || -999) > (prev[:snr_db] || -999)
          else
            merged << d
          end
        end
        detected = merged

        # ---- Exact-channel refine pass ------------------------------------
        # Preliminary FFT peaks are only as precise as the bin resolution
        # (sample_rate/nfft) and the band-plan raster snap. For decoding we
        # want the true channel center, so re-walk each survivor with the
        # traditional S-meter edge_detection + find_best_peak pipeline,
        # scoped to a tight window around the FFT estimate. Opt-out via
        # refine: false for pure-panorama speed.
        refine = opts.fetch(:refine, true)
        if refine && !detected.empty?
          # Switch GQRX into the band-plan demod/passband BEFORE S-meter
          # walks — edge_detection / find_best_peak read l STRENGTH which is
          # only meaningful inside the decoder IF (FM 20 kHz for FLEX, etc.).
          begin
            cmd(
              gqrx_sock: gqrx_sock,
              cmd: "M #{mode_str} #{passband_hz}",
              resp_ok: 'RPRT 0'
            )
            cmd(
              gqrx_sock: gqrx_sock,
              cmd: "L SQL #{squelch}",
              resp_ok: 'RPRT 0'
            )
            sleep 0.15
          rescue StandardError => e
            puts "[FAST-SCAN] WARNING: could not apply band-plan IF for refine (#{e.class}: #{e.message})"
          end

          # Auto-calibrate strength_lock against the *live* S-meter noise floor
          # unless the user passed an explicit -S/--strength-lock. The default
          # -70 dBFS is meaningless across SDRs / bands (live FLEX band here
          # sits at ≈ -55…-83 dBFS); without this, edge walks either flood the
          # entire band or refuse to engage at all.
          unless user_strength_lock
            seed_hz_for_nf = detected.map { |d| d[:hz].to_i }.reject(&:zero?)
            seed_hz_for_nf = [PWN::SDR.hz_to_i(freq: ranges.first[:start_freq])] if seed_hz_for_nf.empty?
            nf_samples = []
            seed_hz_for_nf.first(5).each do |hz|
              # Probe a few offsets off-channel to estimate quiet floor.
              [-3 * plan_bw_hz, -plan_bw_hz, plan_bw_hz, 3 * plan_bw_hz].each do |off|
                ph = hz + off
                next if ph <= 0

                tune_to(gqrx_sock: gqrx_sock, hz: ph)
                3.times do
                  nf_samples << cmd(gqrx_sock: gqrx_sock, cmd: 'l STRENGTH').to_f
                  sleep 0.02
                end
              end
            end
            if nf_samples.any?
              nf_samples.sort!
              live_nf = nf_samples[nf_samples.length / 2] # median
              auto_lock = (live_nf + 8.0).round(1)
              puts "[FAST-SCAN] auto strength_lock: live S-meter nf≈#{live_nf.round(1)} dBFS → lock=#{auto_lock} dBFS (was #{strength_lock})"
              strength_lock = auto_lock
              # Keep squelch a few dB under the lock for any later decoder use.
              squelch = strength_lock - 3.0 if squelch >= strength_lock || opts[:squelch].nil?
              detected.each do |d|
                d[:strength_lock] = strength_lock
                d[:squelch] = squelch
              end
            end
          end

          # Default refine is lock-hunt (S-meter probe ±N raster steps) —
          # ~5–10× faster than local-FFT zoom and more accurate on FM where
          # panoramic centroids often land one channel off. Pass
          # refine_mode: :fft for the legacy high-res FFT zoom, or
          # refine_mode: :hybrid to run both.
          refine_mode = opts.fetch(:refine_mode, :lock)
          detected = refine_detections(
            gqrx_sock: gqrx_sock,
            detections: detected,
            precision: precision,
            step_hz: step_hz,
            strength_lock: strength_lock,
            plan_bw_hz: plan_bw_hz,
            demodulator_mode: demodulator_mode,
            bandwidth: bandwidth,
            squelch: squelch,
            refine_mode: refine_mode
          )
        elsif !refine
          puts '[FAST-SCAN] refine:false — skipping iterative edge/peak refinement'
        end

        # Final in-range gate (refine can drift a little past the requested
        # edges via local zoom). Drop anything outside the union of ranges.
        if detected.any?
          global_lo = ranges.map { |rr| PWN::SDR.hz_to_i(freq: rr[:start_freq]) }.min
          global_hi = ranges.map { |rr| PWN::SDR.hz_to_i(freq: rr[:target_freq]) }.max
          before = detected.length
          detected.select! { |d| d[:hz].to_i.between?(global_lo, global_hi) }
          puts "[FAST-SCAN] dropped #{before - detected.length} out-of-range detection(s) after refine" if detected.length != before
        end

        # Attach AI analysis only when explicitly requested. LLM calls per
        # detection dominate wall-clock on dense bands (fm_radio ~25 hits) and
        # defeat the point of panoramic/FFT scanning. Opt-in via ai_analysis:true
        # (iterative #scan_range still does AI by default for parity with its
        # slower, fewer-hit flow).
        do_ai = opts[:ai_analysis] ? true : false
        detected.each do |freq_obj|
          puts "\n**** Detected Signal ****"
          if do_ai
            begin
              ai_analysis = PWN::AI::Agent::GQRX.analyze(
                request: freq_obj.to_json,
                location: location
              )
              freq_obj[:ai_analysis] = ai_analysis unless ai_analysis.nil?
            rescue StandardError
              # AI analysis is best-effort; never let it kill the scan.
              nil
            end
          end
          puts JSON.pretty_generate(freq_obj)
          puts '-' * 86
        end

        meta = {
          sample_rate_used: sr,
          nfft: nfft,
          precision: precision,
          plan_bw_hz: plan_bw_hz,
          demodulator_mode: demodulator_mode,
          bandwidth: bandwidth,
          squelch: squelch,
          strength_lock: strength_lock,
          audio_gain_db: audio_gain_db,
          rf_gain: rf_gain,
          intermediate_gain: intermediate_gain,
          baseband_gain: baseband_gain,
          decoder: decoder,
          method: :fast_scan_range
        }
        meta[:spectrums] = all_specs if keep_spec

        # Single write through log_signals so top-level keys always match
        # the iterative #scan_range schema (plus FFT-only provenance).
        log_signals(
          signals_detected: detected,
          timestamp_start: ts_start,
          scan_log: scan_log,
          meta: meta
        )
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
              decoder: 'optional - Decoder key (e.g., :gsm / :rds) to start live decoding',
              interactive: 'optional - false → decoder.sample Hash (default true = TTY decode)',
              settle_secs: 'optional - seconds for decoder.sample (RDS default 8)',
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
              avg: 'optional - Number of FFT averages (defaults to 8)',
              capture_secs: 'optional - Duration of I/Q capture in seconds (defaults to 0.10)',
              strength_offset_db: 'optional - Add this many dB to all power levels (defaults to 0.0)'
            )

            fast_scan_resp = #{self}.fast_scan_range(
              gqrx_sock: 'required - GQRX socket object returned from #connect method',
              ranges: 'required - Array of Hash objects with :start_freq and :target_freq keys defining scan ranges',
              sample_rate: 'optional - Chunk size / visible span in Hz (defaults to 1_000_000)',
              nfft: 'optional - FFT size (defaults to 2048)',
              avg: 'optional - Number of averages (defaults to 8)',
              capture_secs: 'optional - Seconds of capture per chunk (defaults to 0.10)',
              strength_lock: 'optional - Minimum signal strength in dBFS to report (defaults to -70.0; only meaningful with strength_offset_db calibration)',
              min_snr_db: 'optional - Minimum SNR in dB above per-chunk noise floor to report (defaults to 12.0)',
              precision: 'optional - Band-plan channel raster; detections snapped to 10**(precision-1) Hz grid (defaults to 5)',
              min_bw_ratio: 'optional - Reject FFT peaks narrower than min_bw_ratio * plan bandwidth as spurs (defaults to 0.0 = off; half-power carrier BW is often << plan BW)',
              demodulator_mode: 'optional - Demodulator mode APPLIED to GQRX + attributed to detections (defaults to WFM)',
              bandwidth: 'optional - Passband bandwidth APPLIED to GQRX + attributed (defaults to "200.000")',
              squelch: 'optional - Squelch level in dBFS APPLIED to GQRX (defaults to strength_lock - 3.0)',
              audio_gain_db: 'optional - Audio gain in dB APPLIED to GQRX (defaults to 0.0)',
              rf_gain: 'optional - RF gain APPLIED to GQRX (defaults to 0.0)',
              intermediate_gain: 'optional - Intermediate gain APPLIED to GQRX (defaults to 32.0)',
              baseband_gain: 'optional - Baseband gain APPLIED to GQRX (defaults to 10.0)',
              decoder: 'optional - Decoder key (e.g. :gsm) to attribute to each detection',
              location: 'optional - Location string to include in AI analysis',
              keep_spectrum: 'optional - If true, include full spectrum data in result (can be large, defaults to false)',
              refine: 'optional - After panoramic FFT, re-walk each detection with traditional edge_detection + find_best_peak scoped around the candidate to lock the exact channel frequency (defaults to true)',
              strength_offset_db: 'optional - Add this many dB to all power levels (defaults to 0.0)',
              scan_log: 'optional - Path to save detected signals log (defaults to /tmp/pwn_sdr_gqrx_scan_<start_freq>-<target_freq>_<timestamp>.json)'
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

            #{self}.read_input_config(
              path: 'optional - GQRX conf (defaults to ~/.config/gqrx/default.conf)'
            )

            #{self}.device_input_rates(
              device: 'optional - SoapySDR device args (defaults to conf [input] device=)'
            )

            #{self}.set_input_rate(
              input_rate: 'required - Input rate Hz (rewrites conf [input] sample_rate=)',
              path: 'optional - GQRX conf path',
              clamp: 'optional - Snap to nearest device-legal rate (default true)',
              restart: 'optional - Kill+respawn gqrx so rate takes effect (default false)'
            )

            #{self}.apply_band_plan_input_rate(
              band_plan: 'required - e.g. :fm_radio / :ads_b1090 (reads FrequencyAllocation input_rate)',
              clamp: 'optional - Snap to device-legal rate (default true)',
              restart: 'optional - Bounce GQRX after write (default false)'
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
