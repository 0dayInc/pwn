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
        # TODO: Wifi5 / Wifi6 profiles,
        # migrate to a YAML file, and add
        # rSpec test to ensure all profiles
        # contain consistent key-value pairs
        {
          ads_b978: {
            start_freq: '978.000.000',
            target_freq: '979.000.000',
            demodulator_mode: :RAW,
            bandwidth: '1.000.000',
            precision: 5
          },
          ads_b1090: {
            start_freq: '1.090.000.000',
            target_freq: '1.091.000.000',
            demodulator_mode: :RAW,
            bandwidth: '1.000.000',
            precision: 5
          },
          analog_tv_vhf: {
            start_freq: '54.000.000',
            target_freq: '216.000.000',
            demodulator_mode: :WFM,
            bandwidth: '6.000',
            precision: 5
          },
          analog_tv_uhf: {
            start_freq: '470.000.000',
            target_freq: '890.000.000',
            demodulator_mode: :WFM,
            bandwidth: '6.000',
            precision: 5
          },
          am_radio: {
            start_freq: '540.000',
            target_freq: '1.700.000',
            demodulator_mode: :AM,
            bandwidth: '10.000',
            precision: 4
          },
          bluetooth: {
            start_freq: '2.400.000.000',
            target_freq: '2.485.000.000',
            demodulator_mode: :RAW,
            bandwidth: '1.000.000',
            precision: 5
          },
          cdma: {
            start_freq: '824.000.000',
            target_freq: '849.000.000',
            demodulator_mode: :RAW,
            bandwidth: '1.250.000',
            precision: 6
          },
          cw20: {
            start_freq: '14.000.000',
            target_freq: '14.350.000',
            demodulator_mode: :CW,
            bandwidth: '150',
            precision: 3
          },
          cw40: {
            start_freq: '7.000.000',
            target_freq: '7.300.000',
            demodulator_mode: :CW,
            bandwidth: '150',
            precision: 3
          },
          cw80: {
            start_freq: '3.500.000',
            target_freq: '3.800.000',
            demodulator_mode: :CW,
            bandwidth: '150',
            precision: 3
          },
          gps12: {
            start_freq: '1.227.600.000',
            target_freq: '1.227.700.000',
            demodulator_mode: :RAW,
            bandwidth: '2.000.000',
            precision: 6
          },
          gps15: {
            start_freq: '1.575.420.000',
            target_freq: '1.575.450.000',
            demodulator_mode: :RAW,
            bandwidth: '2.000.000',
            precision: 6
          },
          gsm: {
            start_freq: '935.000.000',
            target_freq: '960.000.000',
            demodulator_mode: :RAW,
            bandwidth: '200.000',
            precision: 4
          },
          fm_radio: {
            start_freq: '88.000.000',
            target_freq: '108.000.000',
            demodulator_mode: :WFM,
            bandwidth: '200.000',
            precision: 5
          },
          high_rfid: {
            start_freq: '13.560.000',
            target_freq: '13.570.000',
            demodulator_mode: :RAW,
            bandwidth: '2.000.000',
            precision: 3
          },
          lora433: {
            start_freq: '432.000.000',
            target_freq: '434.000.000',
            demodulator_mode: :RAW,
            bandwidth: '500.000',
            precision: 3
          },
          lora915: {
            start_freq: '914.000.000',
            target_freq: '916.000.000',
            demodulator_mode: :RAW,
            bandwidth: '500.000',
            precision: 3
          },
          low_rfid: {
            start_freq: '125.000',
            target_freq: '125.100',
            demodulator_mode: :RAW,
            bandwidth: '200.000',
            precision: 1
          },
          keyfob300: {
            start_freq: '300.000.000',
            target_freq: '300.100.000',
            demodulator_mode: :RAW,
            bandwidth: '50.000',
            precision: 4
          },
          keyfob310: {
            start_freq: '310.000.000',
            target_freq: '310.100.000',
            demodulator_mode: :RAW,
            bandwidth: '50.000',
            precision: 4
          },
          keyfob315: {
            start_freq: '315.000.000',
            target_freq: '315.100.000',
            demodulator_mode: :RAW,
            bandwidth: '50.000',
            precision: 4
          },
          keyfob390: {
            start_freq: '390.000.000',
            target_freq: '390.100.000',
            demodulator_mode: :RAW,
            bandwidth: '50.000',
            precision: 4
          },
          rtty20: {
            start_freq: '14.000.000',
            target_freq: '14.350.000',
            demodulator_mode: :RTTY,
            bandwidth: '170',
            precision: 3
          },
          rtty40: {
            start_freq: '7.000.000',
            target_freq: '7.300.000',
            demodulator_mode: :RTTY,
            bandwidth: '170',
            precision: 3
          },
          rtty80: {
            start_freq: '3.500.000',
            target_freq: '3.800.000',
            demodulator_mode: :RTTY,
            bandwidth: '170',
            precision: 3
          },
          ssb10: {
            start_freq: '28.000.000',
            target_freq: '29.700.000',
            demodulator_mode: :USB,
            bandwidth: '2.700',
            precision: 6
          },
          ssb12: {
            start_freq: '24.890.000',
            target_freq: '24.990.000',
            demodulator_mode: :USB,
            bandwidth: '2.700',
            precision: 6
          },
          ssb15: {
            start_freq: '21.000.000',
            target_freq: '21.450.000',
            demodulator_mode: :USB,
            bandwidth: '2.700',
            precision: 6
          },
          ssb17: {
            start_freq: '18.068.000',
            target_freq: '18.168.000',
            demodulator_mode: :USB,
            bandwidth: '2.700',
            precision: 6
          },
          ssb20: {
            start_freq: '14.000.000',
            target_freq: '14.350.000',
            demodulator_mode: :USB,
            bandwidth: '2.700',
            precision: 6
          },
          ssb40: {
            start_freq: '7.000.000',
            target_freq: '7.300.000',
            demodulator_mode: :LSB,
            bandwidth: '2.700',
            precision: 6
          },
          ssb80: {
            start_freq: '3.500.000',
            target_freq: '3.800.000',
            demodulator_mode: :LSB,
            bandwidth: '2.700',
            precision: 6
          },
          ssb160: {
            start_freq: '1.800.000',
            target_freq: '2.000.000',
            demodulator_mode: :LSB,
            bandwidth: '2.700',
            precision: 6
          },
          tempest: {
            start_freq: '400.000.000',
            target_freq: '430.000.000',
            demodulator_mode: :WFM,
            bandwidth: '200.000',
            precision: 4
          },
          wifi24: {
            start_freq: '2.400.000.000',
            target_freq: '2.500.000.000',
            demodulator_mode: :RAW,
            bandwidth: '20.000.000',
            precision: 7
          },
          zigbee: {
            start_freq: '2.405.000.000',
            target_freq: '2.485.000.000',
            demodulator_mode: :RAW,
            bandwidth: '2.000.000',
            precision: 7
          }
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

        profiles_available = list_profiles
        opts = {}
        case profile
        when :ads_b978
          opts = profiles_available[:ads_b978]
        when :ads_b1090
          opts = profiles_available[:ads_b1090]
        when :analog_tv_vhf
          opts = profiles_available[:analog_tv_vhf]
        when :analog_tv_uhf
          opts = profiles_available[:analog_tv_uhf]
        when :am_radio
          opts = profiles_available[:am_radio]
        when :bluetooth
          opts = profiles_available[:bluetooth]
        when :cdma
          opts = profiles_available[:cdma]
        when :cw20
          opts = profiles_available[:cw20]
        when :cw40
          opts = profiles_available[:cw40]
        when :cw80
          opts = profiles_available[:cw80]
        when :gps12
          opts = profiles_available[:gps12]
        when :gps15
          opts = profiles_available[:gps15]
        when :gsm
          opts = profiles_available[:gsm]
        when :fm_radio
          opts = profiles_available[:fm_radio]
        when :high_rfid
          opts = profiles_available[:high_rfid]
        when :lora433
          opts = profiles_available[:lora433]
        when :lora915
          opts = profiles_available[:lora915]
        when :low_rfid
          opts = profiles_available[:low_rfid]
        when :keyfob300
          opts = profiles_available[:keyfob300]
        when :keyfob310
          opts = profiles_available[:keyfob310]
        when :keyfob315
          opts = profiles_available[:keyfob315]
        when :keyfob390
          opts = profiles_available[:keyfob390]
        when :rtty20
          opts = profiles_available[:rtty20]
        when :rtty40
          opts = profiles_available[:rtty40]
        when :rtty80
          opts = profiles_available[:rtty80]
        when :ssb10
          opts = profiles_available[:ssb10]
        when :ssb12
          opts = profiles_available[:ssb12]
        when :ssb15
          opts = profiles_available[:ssb15]
        when :ssb17
          opts = profiles_available[:ssb17]
        when :ssb20
          opts = profiles_available[:ssb20]
        when :ssb40
          opts = profiles_available[:ssb40]
        when :ssb80
          opts = profiles_available[:ssb80]
        when :ssb160
          opts = profiles_available[:ssb160]
        when :tempest
          opts = profiles_available[:tempest]
        when :wifi24
          opts = profiles_available[:wifi24]
        when :zigbee
          opts = profiles_available[:zigbee]
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
