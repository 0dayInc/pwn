# frozen_string_literal: true

require 'open3'

module PWN
  module Plugins
    # This plugin interacts with the remote control interface of GQRX.
    module GQRX
      # Supported Method Parameters::
      # gqrx_sock = PWN::Plugins::GQRX.connect(
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
      # gqrx_resp = PWN::Plugins::GQRX.gqrx_cmd(
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
        got_freq = false
        # Read all responses from gqrx_sock.write
        timeout = 0.001 if timeout.nil?

        begin
          response.push(gqrx_sock.readline.chomp) while gqrx_sock.wait_readable(timeout)
          raise IOError if response.empty?
        rescue IOError
          timeout += 0.001
          retry
        end

        got_int_value_in_resp = true if response.first.to_i.positive?
        response = response.first if response.length == 1

        raise "ERROR!!! Command: #{cmd} Expected Resp: #{resp_ok}, Got: #{response}" if resp_ok && response != resp_ok

        if got_int_value_in_resp
          fixed_len_freq = format('%0.12d', response.to_i)
          freq_segments = fixed_len_freq.scan(/.{3}/)
          first_non_zero_index = freq_segments.index { |s| s.to_i.positive? }
          freq_segments = freq_segments[first_non_zero_index..-1]
          freq_segments[0] = freq_segments.first.to_i.to_s
          response = freq_segments.join('.')
        end

        # DEBUG
        # puts response.inspect
        # puts response.length

        response
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
      # PWN::Plugins::GQRX.init_freq(
      #   gqrx_sock: 'required - GQRX socket object returned from #connect method',
      #   freq: 'required - Frequency to set',
      #   demodulator_mode: 'optional - Demodulator mode (defaults to WFM)',
      #   bandwidth: 'optional - Bandwidth (defaults to 200000)',
      #   lock_freq_duration: 'optional - Lock frequency duration (defaults to 0.5)',
      #   strength_lock: 'optional - Strength lock (defaults to -60.0)'
      # )
      public_class_method def self.init_freq(opts = {})
        gqrx_sock = opts[:gqrx_sock]
        freq = opts[:freq]
        demodulator_mode = opts[:demodulator_mode]
        bandwidth = opts[:bandwidth]
        lock_freq_duration = opts[:lock_freq_duration]
        strength_lock = opts[:strength_lock]

        demod_n_passband = gqrx_cmd(
          gqrx_sock: gqrx_sock,
          cmd: 'm'
        )

        change_freq_resp = gqrx_cmd(
          gqrx_sock: gqrx_sock,
          cmd: "F #{freq}",
          resp_ok: 'RPRT 0'
        )

        current_freq = gqrx_cmd(
          gqrx_sock: gqrx_sock,
          cmd: 'f'
        )

        audio_gain_db = gqrx_cmd(
          gqrx_sock: gqrx_sock,
          cmd: 'l AF'
        ).to_f

        current_strength = gqrx_cmd(
          gqrx_sock: gqrx_sock,
          cmd: 'l STRENGTH'
        ).to_f

        current_squelch = gqrx_cmd(
          gqrx_sock: gqrx_sock,
          cmd: 'l SQL'
        ).to_f

        rf_gain = gqrx_cmd(
          gqrx_sock: gqrx_sock,
          cmd: 'l RF_GAIN'
        ).to_f

        if_gain = gqrx_cmd(
          gqrx_sock: gqrx_sock,
          cmd: 'l IF_GAIN'
        ).to_f

        bb_gain = gqrx_cmd(
          gqrx_sock: gqrx_sock,
          cmd: 'l BB_GAIN'
        ).to_f

        init_freq_hash = {
          demod_mode_n_passband: demod_n_passband,
          frequency: current_freq,
          bandwidth: bandwidth,
          audio_gain_db: audio_gain_db,
          squelch: current_squelch,
          rf_gain: rf_gain,
          if_gain: if_gain,
          bb_gain: bb_gain,
          strength: current_strength,
          strength_lock: strength_lock,
          lock_freq_duration: lock_freq_duration
        }

        print '.'
        sleep lock_freq_duration if current_strength > strength_lock

        init_freq_hash
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::GQRX.scan_range(
      #   gqrx_sock: 'required - GQRX socket object returned from #connect method',
      #   demodulator_mode: 'required - Demodulator mode',
      #   bandwidth: 'required - Bandwidth',
      #   start_freq: 'required - Starting frequency',
      #   target_freq: 'required - Target frequency',
      #   precision: 'required - Precision',
      #   lock_freq_duration: 'optional - Lock frequency duration (defaults to 0.5)',
      #   strength_lock: 'optional - Strength lock (defaults to -60.0)'
      # )

      public_class_method def self.scan_range(opts = {})
        gqrx_sock = opts[:gqrx_sock]
        demodulator_mode = opts[:demodulator_mode]
        bandwidth = opts[:bandwidth]
        start_freq = opts[:start_freq]
        target_freq = opts[:target_freq]
        precision = opts[:precision]
        lock_freq_duration = opts[:lock_freq_duration]
        strength_lock = opts[:strength_lock]

        multiplier = 10**(precision - 1)
        prev_freq_hash = {
          demod_mode_n_passband: demodulator_mode,
          frequency: start_freq,
          bandwidth: bandwidth,
          audio_gain_db: 0.0,
          squelch: 0.0,
          rf_gain: 0.0,
          if_gain: 0.0,
          bb_gain: 0.0,
          strength: 0.0,
          strength_lock: strength_lock,
          lock_freq_duration: lock_freq_duration
        }
        if start_freq > target_freq
          start_freq.downto(target_freq) do |freq|
            next unless (freq % multiplier).zero?

            init_freq_hash = init_freq(
              gqrx_sock: gqrx_sock,
              freq: freq,
              demodulator_mode: demodulator_mode,
              bandwidth: bandwidth,
              lock_freq_duration: lock_freq_duration,
              strength_lock: strength_lock
            )

            current_strength = init_freq_hash[:strength]
            prev_strength = prev_freq_hash[:strength]
            prev_freq = prev_freq_hash[:frequency]

            approaching_detection = true if current_strength > prev_strength &&
                                            current_strength > strength_lock
            if approaching_detection && current_strength <= prev_strength
              puts "\n**** Found a signal ~ #{prev_freq} Hz ****"
              puts JSON.pretty_generate(prev_freq_hash)
              approaching_detection = false
            end

            prev_freq_hash = init_freq_hash
          end
        else
          freq = start_freq
          while freq <= target_freq
            init_freq_hash = init_freq(
              gqrx_sock: gqrx_sock,
              demodulator_mode: demodulator_mode,
              bandwidth: bandwidth,
              freq: freq,
              lock_freq_duration: lock_freq_duration,
              strength_lock: strength_lock
            )

            current_strength = init_freq_hash[:strength]
            prev_strength = prev_freq_hash[:strength]
            prev_freq = prev_freq_hash[:frequency]

            approaching_detection = true if current_strength > prev_strength &&
                                            current_strength > strength_lock
            if approaching_detection && current_strength < prev_strength
              puts "\n**** Discovered a signal ~ #{prev_freq} Hz ****"
              puts JSON.pretty_generate(prev_freq_hash)
              approaching_detection = false
            end

            prev_freq_hash = init_freq_hash

            freq += multiplier
          end
        end
      end

      # Supported Method Parameters::
      # profiles = PWN::Plugins::GQRX.list_profiles
      public_class_method def self.list_profiles
        {
          ads_b: 'ADS-B, 978mhz to 1090mhz, AM, 4.6mhz bandwidth',
          analogue_tv: 'Analogue TV, 55.25mhz to 801.25mhz, WFM, 6mhz bandwidth',
          am_radio: 'AM Radio, 540khz to 1600khz, AM, 6khz bandwidth',
          bluetooth: 'Bluetooth, 2.4ghz to 2.5ghz, AM, 1mhz bandwidth',
          cdma: 'CDMA, 824mhz to 849mhz, AM, 1.25mhz bandwidth',
          cw20: 'CW 20m, 14mhz to 14.35mhz, CW, 150hz bandwidth',
          cw40: 'CW 40m, 7mhz to 7.3mhz, CW, 150hz bandwidth',
          cw80: 'CW 80m, 3.5mhz to 3.8mhz, CW, 150hz bandwidth',
          gps: 'GPS, 1.57542ghz to 1.57545ghz, WFM, 9.6mhz bandwidth',
          gsm: 'GSM, 935mhz to 960mhz, AM, 200khz bandwidth',
          fm_radio: 'FM Radio, 88mhz to 108mhz, WFM, 200khz bandwidth',
          lora433: 'LoRa 433mhz, 433mhz, AM, 125khz bandwidth',
          lora915: 'LoRa 915mhz, 915mhz, AM, 125khz bandwidth',
          lowrfid: 'Low RFID, 125khz, AM, 200khz bandwidth',
          nfcrfid: 'NFC RFID, 13.56mhz, AM, 1mhz bandwidth',
          radio_fob: 'Radio FOB, 315mhz, AM',
          rtty20: 'RTTY 20m, 14mhz to 14.35mhz, RTTY, 170hz bandwidth',
          rtty40: 'RTTY 40m, 7mhz to 7.3mhz, RTTY, 170hz bandwidth',
          rtty80: 'RTTY 80m, 3.5mhz to 3.8mhz, RTTY, 170hz bandwidth',
          ssb10: 'SSB 10m, 28mhz to 29.7mhz, USB, 2.7khz bandwidth',
          ssb12: 'SSB 12m, 24.89mhz to 24.99mhz, USB, 2.7khz bandwidth',
          ssb15: 'SSB 15m, 21mhz to 21.45mhz, USB, 2.7khz bandwidth',
          ssb17: 'SSB 17m, 18.068mhz to 18.168mhz, USB, 2.7khz bandwidth',
          ssb20: 'SSB 20m, 14mhz to 14.35mhz, USB, 2.7khz bandwidth',
          ssb40: 'SSB 40m, 7mhz to 7.3mhz, LSB, 2.7khz bandwidth',
          ssb80: 'SSB 80m, 3.5mhz to 3.8mhz, LSB, 2.7khz bandwidth',
          ssb160: 'SSB 160m, 1.8mhz to 2mhz, LSB, 2.7khz bandwidth',
          tempest: 'Tempest, 400mhz to 430mhz, AM, 200khz bandwidth',
          wifi24: 'WiFi 2.4ghz, 2.4ghz to 2.5ghz, AM, 20mhz bandwidth',
          zigbee: 'Zigbee, 2.405ghz to 2.485ghz, AM, 2mhz bandwidth'
        }
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # opts = PWN::Plugins::GQRX.assume_profile(
      #   profile: 'required - valid GQRX profile name returned from #list_profiles method'
      # )
      public_class_method def self.assume_profile(opts = {})
        profile = opts[:profile].to_s.to_sym

        opts = {}
        case profile
        when :ads_b
          opts[:start_freq] = '978.000.000'
          opts[:target_freq] = '1.090.000.000'
          opts[:demodulator_mode] = 'AM'
          opts[:bandwidth] = '4.600.000'
        when :analogue_tv
          opts[:start_freq] = '55.250.000'
          opts[:target_freq] = '801.250.000'
          opts[:demodulator_mode] = 'WFM'
          opts[:bandwidth] = '6.000'
        when :am_radio
          opts[:start_freq] = '540.000'
          opts[:target_freq] = '1.600.000'
          opts[:demodulator_mode] = 'AM'
          opts[:bandwidth] = '6.000'
        when :bluetooth
          opts[:start_freq] = '2.400.000.000'
          opts[:target_freq] = '2.500.000.000'
          opts[:demodulator_mode] = 'AM'
          opts[:bandwidth] = '1.000.000'
        when :cdma
          opts[:start_freq] = '824.000.000'
          opts[:target_freq] = '849.000.000'
          opts[:demodulator_mode] = 'AM'
          opts[:bandwidth] = '1.250.000'
        when :cw20
          opts[:start_freq] = '14.000.000'
          opts[:target_freq] = '14.350.000'
          opts[:demodulator_mode] = 'CW'
          opts[:bandwidth] = '150'
        when :cw40
          opts[:start_freq] = '7.000.000'
          opts[:target_freq] = '7.300.000'
          opts[:demodulator_mode] = 'CW'
          opts[:bandwidth] = '150'
        when :cw80
          opts[:start_freq] = '3.500.000'
          opts[:target_freq] = '3.800.000'
          opts[:demodulator_mode] = 'CW'
          opts[:bandwidth] = '150'
        when :gps
          opts[:start_freq] = '1.575.420.000'
          opts[:target_freq] = '1.575.450.000'
          opts[:demodulator_mode] = 'WFM'
          opts[:bandwidth] = '9.600.000'
        when :gsm
          opts[:start_freq] = '935.000.000'
          opts[:target_freq] = '960.000.000'
          opts[:demodulator_mode] = 'AM'
          opts[:bandwidth] = '200.000'
        when :fm_radio
          opts[:start_freq] = '88.000.000'
          opts[:target_freq] = '108.000.000'
          opts[:demodulator_mode] = 'WFM'
          opts[:bandwidth] = '200.000'
        when :lora433
          opts[:start_freq] = '433.000.000'
          opts[:target_freq] = '433.000.000'
          opts[:demodulator_mode] = 'AM'
          opts[:bandwidth] = '125.000'
        when :lora915
          opts[:start_freq] = '915.000.000'
          opts[:target_freq] = '915.000.000'
          opts[:demodulator_mode] = 'AM'
          opts[:bandwidth] = '125.000'
        when :lowrfid
          opts[:start_freq] = '125.000'
          opts[:target_freq] = '125.000'
          opts[:demodulator_mode] = 'AM'
          opts[:bandwidth] = '200.000'
        when :nfcrfid
          opts[:start_freq] = '13.560.000'
          opts[:target_freq] = '13.560.000'
          opts[:demodulator_mode] = 'AM'
          opts[:bandwidth] = '1.000.000'
        when :radio_fob
          opts[:start_freq] = '315.000.000'
          opts[:target_freq] = '315.000.000'
          opts[:demodulator_mode] = 'AM'
        when :rtty20
          opts[:start_freq] = '14.000.000'
          opts[:target_freq] = '14.350.000'
          opts[:demodulator_mode] = 'RTTY'
          opts[:bandwidth] = '170'
        when :rtty40
          opts[:start_freq] = '7.000.000'
          opts[:target_freq] = '7.300.000'
          opts[:demodulator_mode] = 'RTTY'
          opts[:bandwidth] = '170'
        when :rtty80
          opts[:start_freq] = '3.500.000'
          opts[:target_freq] = '3.800.000'
          opts[:demodulator_mode] = 'RTTY'
          opts[:bandwidth] = '170'
        when :ssb10
          opts[:start_freq] = '28.000.000'
          opts[:target_freq] = '29.700.000'
          opts[:demodulator_mode] = 'USB'
          opts[:bandwidth] = '2.700'
        when :ssb12
          opts[:start_freq] = '24.890.000'
          opts[:target_freq] = '24.990.000'
          opts[:demodulator_mode] = 'USB'
          opts[:bandwidth] = '2.700'
        when :ssb15
          opts[:start_freq] = '21.000.000'
          opts[:target_freq] = '21.450.000'
          opts[:demodulator_mode] = 'USB'
          opts[:bandwidth] = '2.700'
        when :ssb17
          opts[:start_freq] = '18.068.000'
          opts[:target_freq] = '18.168.000'
          opts[:demodulator_mode] = 'USB'
          opts[:bandwidth] = '2.700'
        when :ssb20
          opts[:start_freq] = '14.000.000'
          opts[:target_freq] = '14.350.000'
          opts[:demodulator_mode] = 'USB'
          opts[:bandwidth] = '2.700'
        when :ssb40
          opts[:start_freq] = '7.000.000'
          opts[:target_freq] = '7.300.000'
          opts[:demodulator_mode] = 'LSB'
          opts[:bandwidth] = '2.700'
        when :ssb80
          opts[:start_freq] = '3.500.000'
          opts[:target_freq] = '3.800.000'
          opts[:demodulator_mode] = 'LSB'
          opts[:bandwidth] = '2.700'
        when :ssb160
          opts[:start_freq] = '1.800.000'
          opts[:target_freq] = '2.000.000'
          opts[:demodulator_mode] = 'LSB'
          opts[:bandwidth] = '2.700'
        when :tempest
          opts[:start_freq] = '400.000.000'
          opts[:target_freq] = '430.000.000'
          opts[:demodulator_mode] = 'AM'
          opts[:bandwidth] = '200.000'
        when :wifi24
          opts[:start_freq] = '2.400.000.000'
          opts[:target_freq] = '2.500.000.000'
          opts[:demodulator_mode] = 'AM'
          opts[:bandwidth] = '20.000.000'
        when :zigbee
          opts[:start_freq] = '2.405.000.000'
          opts[:target_freq] = '2.485.000.000'
          opts[:demodulator_mode] = 'AM'
          opts[:bandwidth] = '2.000.000'
        else
          raise "ERROR: Invalid profile: #{profile}"
        end

        opts
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::GQRX.disconnect(
      #   gqrx_sock: 'required - GQRX socket object returned from #connect method'
      # )
      public_class_method def self.disconnect(opts = {})
        gqrx_sock = opts[:gqrx_sock]

        PWN::Plugins::Sock.disconnect(sock_obj: gqrx_sock)
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
          gqrx_sock = #{self}.connect(
          target: 'optional - GQRX target IP address (defaults to 127.0.0.1)',
            port: 'optional - GQRX target port (defaults to 7356)'
          )

          #{self}.gqrx_cmd(
            gqrx_sock: 'required - GQRX socket object returned from #connect method',
            cmd: 'required - GQRX command to execute',
            resp_ok: 'optional - Expected response from GQRX to indicate success'
          )

          #{self}.init_freq(
            gqrx_sock: 'required - GQRX socket object returned from #connect method',
            freq: 'required - Frequency to set',
            demodulator_mode: 'optional - Demodulator mode (defaults to WFM)',
            bandwidth: 'optional - Bandwidth (defaults to 200000)',
            lock_freq_duration: 'optional - Lock frequency duration (defaults to 0.5)',
            strength_lock: 'optional - Strength lock (defaults to -60.0)'
          )

          #{self}.scan_range(
            gqrx_sock: 'required - GQRX socket object returned from #connect method',
            demodulator_mode: 'required - Demodulator mode',
            bandwidth: 'required - Bandwidth',
            start_freq: 'required - Starting frequency',
            target_freq: 'required - Target frequency',
            precision: 'required - Precision',
            lock_freq_duration: 'optional - Lock frequency duration (defaults to 0.5)',
            strength_lock: 'optional - Strength lock (defaults to -60.0)'
          )

          profiles = #{self}.list_profiles

          opts = #{self}.assume_profile(
            profile: 'required - valid GQRX profile name returned from #list_profiles method'
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
