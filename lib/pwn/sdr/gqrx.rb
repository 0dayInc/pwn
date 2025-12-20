# frozen_string_literal: true

require 'json'
require 'time'

module PWN
  module SDR
    # This plugin interacts with the remote control interface of GQRX.
    module GQRX
      # Monkey patches for frequency handling
      String.class_eval do
        def cast_to_raw_hz
          gsub('.', '').to_i
        end
      end

      Integer.class_eval do
        # Should always return format of X.XXX.XXX.XXX
        # So 002_450_000_000 becomes 2.450.000.000
        # So 2_450_000_000 becomes 2.450.000.000
        # So 960_000_000 becomes 960.000.000
        # 1000 should be 1.000
        def cast_to_pretty_hz
          str_hz = to_s
          # Nuke leading zeros
          # E.g., 002450000000 -> 2450000000
          str_hz = str_hz.sub(/^0+/, '') unless str_hz == '0'
          # Insert dots every 3 digits from the right
          str_hz.reverse.scan(/.{1,3}/).join('.').reverse
        end
      end

      # Supported Method Parameters::
      # gqrx_resp = PWN::SDR::GQRX.gqrx_cmd(
      #   gqrx_sock: 'required - GQRX socket object returned from #connect method',
      #   cmd: 'required - GQRX command to execute',
      #   resp_ok: 'optional - Expected response from GQRX to indicate success'
      # )

      private_class_method def self.gqrx_cmd(opts = {})
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
        response_str = response_str.to_i.cast_to_pretty_hz if response_str.match?(/^\d+$/) && response_str.to_i.positive?

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
      # strength_db = PWN::SDR::GQRX.measure_signal_strength(
      #   gqrx_sock: 'required - GQRX socket object returned from #connect method'
      # )
      private_class_method def self.measure_signal_strength(opts = {})
        gqrx_sock = opts[:gqrx_sock]

        strength_db = -99.9
        prev_strength_db = strength_db
        # While strength_db is rising, keep measuring
        loop do
          strength_db = gqrx_cmd(gqrx_sock: gqrx_sock, cmd: 'l STRENGTH').to_f
          break if strength_db <= prev_strength_db

          prev_strength_db = strength_db
        end

        strength_db
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # candidate_signals = PWN::SDR::GQRX.edge_detection(
      #   gqrx_sock: 'required - GQRX socket object returned from #connect method',
      #   hz: 'required - Frequency to start edge detection from',
      #   step_hz: 'required - Frequency step in Hz for edge detection',
      #   strength_lock: 'required - Strength lock in dBFS to determine signal edges'
      # )
      private_class_method def self.edge_detection(opts = {})
        gqrx_sock = opts[:gqrx_sock]
        hz = opts[:hz]
        step_hz = opts[:step_hz]
        strength_lock = opts[:strength_lock]
        left_candidate_signals = []
        right_candidate_signals = []
        candidate_signals = []

        # left_candidate_signals.clear
        original_hz = hz
        strength_db = 99.9
        puts 'Finding Beginning Edge of Signal...'
        while strength_db >= strength_lock
          gqrx_cmd(gqrx_sock: gqrx_sock, cmd: "F #{hz}")
          current_freq = 0
          while current_freq.to_s.cast_to_raw_hz != hz.to_s.cast_to_raw_hz
            current_freq = gqrx_cmd(
              gqrx_sock: gqrx_sock,
              cmd: 'f'
            )
          end
          strength_db = measure_signal_strength(gqrx_sock: gqrx_sock)
          candidate = {
            hz: hz.to_s.cast_to_raw_hz,
            freq: hz.to_i.cast_to_pretty_hz,
            strength: strength_db,
            side: :left
          }
          left_candidate_signals.push(candidate)
          hz -= step_hz
        end
        left_candidate_signals.uniq! { |s| s[:hz] }
        left_candidate_signals.sort_by! { |s| s[:hz] }

        # Now scan forwards to find the end of the signal
        # The end of the signal is where the strength drops below strength_lock
        # right_candidate_signals.clear
        hz = original_hz

        strength_db = 99.9
        puts 'Finding Ending Edge of Signal...'
        while strength_db >= strength_lock
          gqrx_cmd(gqrx_sock: gqrx_sock, cmd: "F #{hz}")
          current_freq = 0
          while current_freq.to_s.cast_to_raw_hz != hz.to_s.cast_to_raw_hz
            current_freq = gqrx_cmd(
              gqrx_sock: gqrx_sock,
              cmd: 'f'
            )
          end
          strength_db = measure_signal_strength(gqrx_sock: gqrx_sock)
          candidate = {
            hz: hz.to_s.cast_to_raw_hz,
            freq: hz.to_i.cast_to_pretty_hz,
            strength: strength_db,
            side: :right
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
      # scan_resp = PWN::SDR::GQRX.log_signals(
      #   signals_arr: 'required - Array of detected signals',
      #   timestamp_start: 'required - Scan start timestamp',
      #   scan_log: 'required - Path to save detected signals log'
      # )
      private_class_method def self.log_signals(opts = {})
        signals_arr = opts[:signals_arr]
        timestamp_start = opts[:timestamp_start]
        scan_log = opts[:scan_log]

        signals = signals_arr.sort_by { |s| s[:freq].to_s.cast_to_raw_hz }
        # Unique signals by frequency
        signals.uniq! { |s| s[:hz] }

        timestamp_end = Time.now.strftime('%Y-%m-%d %H:%M:%S%z')
        duration_secs = Time.parse(timestamp_end) - Time.parse(timestamp_start)
        # Convert duration seconds to hours minutes seconds
        hours = (duration_secs / 3600).to_i
        minutes = ((duration_secs % 3600) / 60).to_i
        seconds = (duration_secs % 60).to_i
        duration = format('%<hrs>02d:%<mins>02d:%<secs>02d', hrs: hours, mins: minutes, secs: seconds)

        scan_resp = {
          signals: signals,
          total: signals.length,
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
      # rds_resp = PWN::SDR::GQRX.decode_rds(
      #   gqrx_sock: 'required - GQRX socket object returned from #connect method'
      # )

      private_class_method def self.decode_rds(opts = {})
        gqrx_sock = opts[:gqrx_sock]

        # We toggle RDS off and on to reset the decoder
        rds_resp = gqrx_cmd(
          gqrx_sock: gqrx_sock,
          cmd: 'U RDS 0',
          resp_ok: 'RPRT 0'
        )

        rds_resp = gqrx_cmd(
          gqrx_sock: gqrx_sock,
          cmd: 'U RDS 1',
          resp_ok: 'RPRT 0'
        )

        rds_resp = {}
        attempts = 0
        max_attempts = 90
        skip_rds = "\n"
        print 'INFO: Decoding FM radio RDS data (Press ENTER to skip)...'
        max_attempts.times do
          attempts += 1
          rds_resp[:rds_pi] = gqrx_cmd(gqrx_sock: gqrx_sock, cmd: 'p RDS_PI')
          rds_resp[:rds_ps_name] = gqrx_cmd(gqrx_sock: gqrx_sock, cmd: 'p RDS_PS_NAME')
          rds_resp[:rds_radiotext] = gqrx_cmd(gqrx_sock: gqrx_sock, cmd: 'p RDS_RADIOTEXT')

          # Break if ENTER key pressed
          # This is useful if no RDS data is available
          # on the current frequency (e.g. false+)
          break if $stdin.ready? && $stdin.read_nonblock(1) == skip_rds

          break if rds_resp[:rds_pi] != '0000' && !rds_resp[:rds_ps_name].empty? && !rds_resp[:rds_radiotext].empty?

          print '.'
          sleep 0.1
        end
        puts 'complete.'
        rds_resp
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
      #   rds: 'optional - Boolean to enable/disable RDS decoding (defaults to false)',
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

        rds = opts[:rds] ||= false

        bandwidth = opts[:bandwidth] ||= 200_000
        squelch = opts[:squelch]
        decoder = opts[:decoder]
        record_dir = opts[:record_dir] ||= '/tmp'
        suppress_details = opts[:suppress_details] || false
        keep_alive = opts[:keep_alive] || false

        raise "ERROR: record_dir '#{record_dir}' does not exist. Please create it or provide a valid path." if decoder && !Dir.exist?(record_dir)

        unless keep_alive
          squelch = gqrx_cmd(gqrx_sock: gqrx_sock, cmd: 'l SQL').to_f if squelch.nil?
          change_squelch_resp = gqrx_cmd(
            gqrx_sock: gqrx_sock,
            cmd: "L SQL #{squelch}",
            resp_ok: 'RPRT 0'
          )

          mode_str = demodulator_mode.to_s.upcase
          passband_hz = bandwidth.to_s.cast_to_raw_hz
          gqrx_cmd(
            gqrx_sock: gqrx_sock,
            cmd: "M #{mode_str} #{passband_hz}",
            resp_ok: 'RPRT 0'
          )
        end

        change_freq_resp = gqrx_cmd(
          gqrx_sock: gqrx_sock,
          cmd: "F #{freq.to_s.cast_to_raw_hz}",
          resp_ok: 'RPRT 0'
        )

        current_freq = 0
        while current_freq.to_s.cast_to_raw_hz != freq.to_s.cast_to_raw_hz
          current_freq = gqrx_cmd(
            gqrx_sock: gqrx_sock,
            cmd: 'f'
          )
        end

        freq_obj = {
          bandwidth: bandwidth,
          demodulator_mode: demodulator_mode,
          rds: rds,
          freq: freq
        }

        unless suppress_details
          demod_n_passband = gqrx_cmd(
            gqrx_sock: gqrx_sock,
            cmd: 'm'
          )

          audio_gain_db = gqrx_cmd(
            gqrx_sock: gqrx_sock,
            cmd: 'l AF'
          ).to_f

          strength_db = measure_signal_strength(gqrx_sock: gqrx_sock)

          squelch = gqrx_cmd(
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

          rds_resp = nil
          rds_resp = decode_rds(gqrx_sock: gqrx_sock) if rds

          freq_obj[:audio_gain_db] = audio_gain_db
          freq_obj[:demod_mode_n_passband] = demod_n_passband
          freq_obj[:bb_gain] = bb_gain
          freq_obj[:if_gain] = if_gain
          freq_obj[:rf_gain] = rf_gain
          freq_obj[:squelch] = squelch
          freq_obj[:strength_db] = strength_db
          freq_obj[:rds] = rds_resp
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

          freq_obj[:freq] = current_freq
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
      #   rds: 'optional - Boolean to enable/disable RDS decoding (defaults to false)',
      #   bandwidth: 'optional - Bandwidth in Hz (Defaults to 200_000)',
      #   precision: 'optional - Frequency step precision (number of digits; defaults to 1)',
      #   strength_lock: 'optional - Strength lock in dBFS (defaults to -70.0)',
      #   squelch: 'optional - Squelch level in dBFS (defaults to strength_lock - 3.0)',
      #   audio_gain_db: 'optional - Audio gain in dB (defaults to 6.0)',
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
        hz_start = start_freq.to_s.cast_to_raw_hz

        target_freq = opts[:target_freq]
        hz_target = target_freq.to_s.cast_to_raw_hz

        demodulator_mode = opts[:demodulator_mode]
        rds = opts[:rds] ||= false

        bandwidth = opts[:bandwidth] ||= 200_000
        precision = opts[:precision] ||= 1
        strength_lock = opts[:strength_lock] ||= -70.0
        squelch = opts[:squelch] ||= (strength_lock - 3.0)
        scan_log = opts[:scan_log] ||= "/tmp/pwn_sdr_gqrx_scan_#{hz_start.to_i.cast_to_pretty_hz}-#{hz_target.to_i.cast_to_pretty_hz}_#{log_timestamp}.json"
        location = opts[:location] ||= 'United States'

        step_hz = 10**(precision - 1)
        step = hz_start > hz_target ? -step_hz : step_hz

        # Set squelch once for the scan
        change_squelch_resp = gqrx_cmd(
          gqrx_sock: gqrx_sock,
          cmd: "L SQL #{squelch}",
          resp_ok: 'RPRT 0'
        )

        # We always disable RDS decoding at during the scan
        # to prevent unnecessary processing overhead.
        # We return the rds boolean in the scan_resp object
        # so it will be picked up and used appropriately
        # when calling analyze_scan or analyze_log methods.
        rds_resp = gqrx_cmd(
          gqrx_sock: gqrx_sock,
          cmd: 'U RDS 0',
          resp_ok: 'RPRT 0'
        )

        # Set demodulator mode & passband once for the scan
        mode_str = demodulator_mode.to_s.upcase
        passband_hz = bandwidth.to_s.cast_to_raw_hz
        gqrx_cmd(
          gqrx_sock: gqrx_sock,
          cmd: "M #{mode_str} #{passband_hz}",
          resp_ok: 'RPRT 0'
        )

        audio_gain_db = opts[:audio_gain_db] ||= 6.0
        audio_gain_db = audio_gain_db.to_f
        audio_gain_db_resp = gqrx_cmd(
          gqrx_sock: gqrx_sock,
          cmd: "L AF #{audio_gain_db}",
          resp_ok: 'RPRT 0'
        )

        rf_gain = opts[:rf_gain] ||= 0.0
        rf_gain = rf_gain.to_f
        rf_gain_resp = gqrx_cmd(
          gqrx_sock: gqrx_sock,
          cmd: "L RF_GAIN #{rf_gain}",
          resp_ok: 'RPRT 0'
        )

        intermediate_gain = opts[:intermediate_gain] ||= 32.0
        intermediate_gain = intermediate_gain.to_f
        intermediate_resp = gqrx_cmd(
          gqrx_sock: gqrx_sock,
          cmd: "L IF_GAIN #{intermediate_gain}",
          resp_ok: 'RPRT 0'
        )

        baseband_gain = opts[:baseband_gain] ||= 10.0
        baseband_gain = baseband_gain.to_f
        baseband_resp = gqrx_cmd(
          gqrx_sock: gqrx_sock,
          cmd: "L BB_GAIN #{baseband_gain}",
          resp_ok: 'RPRT 0'
        )

        prev_freq_obj = init_freq(
          gqrx_sock: gqrx_sock,
          freq: hz_start,
          demodulator_mode: demodulator_mode,
          rds: rds,
          bandwidth: bandwidth,
          squelch: squelch,
          suppress_details: true,
          keep_alive: true
        )

        candidate_signals = []

        # Adaptive peak finder – trims weakest ends after each pass
        # Converges quickly to the true center of the bell curve
        find_best_peak = lambda do |opts = {}|
          beg_of_signal_hz = opts[:beg_of_signal_hz].to_s.cast_to_raw_hz
          end_of_signal_hz = opts[:end_of_signal_hz].to_s.cast_to_raw_hz

          samples = []
          prev_best_sample = {}
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
              strength_db = measure_signal_strength(gqrx_sock: gqrx_sock)
              samples.push({ hz: hz, strength_db: strength_db })

              # current_hz = gqrx_cmd(gqrx_sock: gqrx_sock, cmd: 'f').to_s.cast_to_raw_hz
              # puts "Sampled Frequency: #{current_hz.to_i.cast_to_pretty_hz} => Strength: #{strength_db} dBFS"
            end

            # Compute fresh averaged_samples from all cumulative samples
            averaged_samples = []
            samples.group_by { |s| s[:hz] }.each do |hz, grouped_samples|
              avg_strength = (grouped_samples.map { |s| s[:strength_db] }.sum / grouped_samples.size)
              # avg_strength = (grouped_samples.map { |s| s[:strength_db] }.sum / grouped_samples.size).round(2)
              # avg_strength = (grouped_samples.map { |s| s[:strength_db] }.sum / grouped_samples.size).round(1)
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
            if best_sample[:hz] == prev_best_sample[:hz]
              consecutive_best += 1
            else
              consecutive_best = 0
            end

            # Dup to avoid reference issues
            prev_best_sample = best_sample.dup

            puts "Pass #{pass_count}: Best #{best_sample[:hz].to_i.cast_to_pretty_hz} => #{best_sample[:strength_db]} dBFS, consecutive best count: #{consecutive_best}"

            # Break if no improvement in 3 consecutive passes or theres only one sample left
            break if consecutive_best.positive? || averaged_samples.size == 1
          end

          best_sample
        end

        # Begin scanning range
        puts "\n"
        puts '-' * 86
        puts "INFO: Scanning from #{hz_start.to_i.cast_to_pretty_hz} to #{hz_target.to_i.cast_to_pretty_hz} in steps of #{step.abs.to_i.cast_to_pretty_hz} Hz."
        puts "If scans are slow and/or you're experiencing false positives/negatives,"
        puts 'consider adjusting the following:'
        puts "1. The SDR's sample rate in GQRX"
        puts "\s\s- Click on `Configure I/O devices`."
        puts "\s\s- A lower `Input rate` value seems counter-intuitive but works well (e.g. ADALM PLUTO ~ 1000000)."
        puts '2. Adjust the :strength_lock parameter.'
        puts '3. Adjust the :precision parameter.'
        puts '4. Disable AI introspection in PWN::Env'
        puts 'Happy scanning!'
        puts '-' * 86
        puts "\n\n\n"

        signals_arr = []
        hz = hz_start
        while hz <= hz_target
          gqrx_cmd(gqrx_sock: gqrx_sock, cmd: "F #{hz}")
          current_freq = 0
          while current_freq.to_s.cast_to_raw_hz != hz.to_s.cast_to_raw_hz
            current_freq = gqrx_cmd(
              gqrx_sock: gqrx_sock,
              cmd: 'f'
            )
          end

          strength_db = measure_signal_strength(gqrx_sock: gqrx_sock)

          if strength_db >= strength_lock
            puts '-' * 86
            # Find left and right edges of the signal
            candidate_signals = edge_detection(
              gqrx_sock: gqrx_sock,
              hz: hz,
              step_hz: step_hz,
              strength_lock: strength_lock
            )
          elsif candidate_signals.length.positive?
            beg_of_signal_hz = candidate_signals.first[:hz]
            top_of_signal_hz_idx = (candidate_signals.length - 1) / 2
            top_of_signal_hz = candidate_signals[top_of_signal_hz_idx][:hz]
            end_of_signal_hz = candidate_signals.last[:hz]
            puts 'Candidate Signal(s) Detected:'
            puts JSON.pretty_generate(candidate_signals)

            prev_freq = prev_freq_obj[:freq].to_s.cast_to_raw_hz
            distance_from_prev_detected_freq_hz = (beg_of_signal_hz - prev_freq).abs
            half_bandwidth = (bandwidth / 2).to_i

            puts "Key Frequencies: Begin: #{beg_of_signal_hz.to_i.cast_to_pretty_hz} Hz | Estimated Top: #{top_of_signal_hz.to_i.cast_to_pretty_hz} Hz | End: #{end_of_signal_hz.to_i.cast_to_pretty_hz} Hz"

            puts 'Finding Best Peak...'
            best_peak = find_best_peak.call(
              beg_of_signal_hz: beg_of_signal_hz,
              end_of_signal_hz: end_of_signal_hz
            )

            if best_peak[:hz] && best_peak[:strength_db] > strength_lock
              puts "\n**** Detected Signal ****"
              best_freq = best_peak[:hz].to_i.cast_to_pretty_hz
              best_strength_db = best_peak[:strength_db]
              prev_freq_obj = init_freq(
                gqrx_sock: gqrx_sock,
                freq: best_freq,
                rds: rds,
                suppress_details: true,
                keep_alive: true
              )
              prev_freq_obj[:strength_lock] = strength_lock
              prev_freq_obj[:strength_db] = best_strength_db

              system_role_content = "Analyze signal data captured by a software-defined-radio using GQRX at the following location: #{location}. Respond with just FCC information about the transmission if available.  If the frequency is unlicensed or not found in FCC records, state that clearly.  Be clear and concise in your analysis."
              ai_analysis = PWN::AI::Introspection.reflect_on(
                request: prev_freq_obj.to_json,
                system_role_content: system_role_content,
                suppress_pii_warning: true
              )

              prev_freq_obj[:ai_analysis] = ai_analysis unless ai_analysis.nil?
              puts JSON.pretty_generate(prev_freq_obj)
              puts '-' * 86
              puts "\n\n\n"
              signals_arr.push(prev_freq_obj)
              log_signals(
                signals_arr: signals_arr,
                timestamp_start: timestamp_start,
                scan_log: scan_log
              )
              hz = end_of_signal_hz
              # gets
            end
            candidate_signals.clear
          end
          hz += step_hz
        end

        log_signals(
          signals_arr: signals_arr,
          timestamp_start: timestamp_start,
          scan_log: scan_log
        )
      rescue Interrupt
        puts "\nCTRL+C detected - goodbye."
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
          signal[:gqrx_sock] = gqrx_sock
          # This is required to keep connection alive during analysis
          signal[:keep_alive] = true
          freq_obj = init_freq(signal)
          freq_obj = signal.merge(freq_obj)
          # Redact gqrx_sock from output
          freq_obj.delete(:gqrx_sock)
          puts JSON.pretty_generate(freq_obj)
          print 'Press [ENTER] to continue...'
          gets
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

          freq_obj = #{self}.init_freq(
            gqrx_sock: 'required - GQRX socket object returned from #connect method',
            freq: 'required - Frequency to set',
            demodulator_mode: 'optional - Demodulator mode (defaults to WFM)',
            rds: 'optional - Boolean to enable/disable RDS decoding (defaults to false)',
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
            precision: 'optional - Precision (Defaults to 1)',
            strength_lock: 'optional - Strength lock (defaults to -70.0)',
            squelch: 'optional - Squelch level (defaults to strength_lock - 3.0)',
            audio_gain_db: 'optional - Audio gain in dB (defaults to 6.0)',
            rf_gain: 'optional - RF gain (defaults to 0.0)',
            intermediate_gain: 'optional - Intermediate gain (defaults to 32.0)',
            baseband_gain: 'optional - Baseband gain (defaults to 10.0)',
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
