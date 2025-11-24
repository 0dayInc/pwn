# frozen_string_literal: true

require 'open3'
require 'json'
require 'fileutils'

module PWN
  module SDR
    # This plugin interacts with the remote control interface of GQRX.
    module FrequencyAllocation
      # Supported Method Parameters::
      # profiles = PWN::SDR::FrequencyAllocation.profiles
      # Supported Method Parameters::
      # profiles = PWN::SDR::FrequencyAllocation.profiles
      public_class_method def self.profiles
        # TODO: Wifi5 / Wifi6 profiles,
        # migrate to a YAML file, and add
        # rSpec test to ensure all profiles
        # contain consistent key-value pairs
        {
          ads_b978: {
            start_freq: '978.000.000',
            target_freq: '979.000.000',
            demodulator_mode: 'RAW',
            bandwidth: 100_000,
            precision: 5,
            overlap_protection: true
          },
          ads_b1090: {
            start_freq: '1.090.000.000',
            target_freq: '1.091.000.000',
            demodulator_mode: 'RAW',
            bandwidth: 100_000,
            precision: 5,
            overlap_protection: true
          },
          analog_tv_vhf: {
            start_freq: '54.000.000',
            target_freq: '216.000.000',
            demodulator_mode: 'WFM',
            bandwidth: 600_000,
            precision: 5,
            overlap_protection: true
          },
          analog_tv_uhf: {
            start_freq: '470.000.000',
            target_freq: '890.000.000',
            demodulator_mode: 'WFM',
            bandwidth: 600_000,
            precision: 5,
            overlap_protection: true
          },
          am_radio: {
            start_freq: '540.000',
            target_freq: '1.700.000',
            demodulator_mode: 'AM',
            bandwidth: 10_000,
            precision: 4,
            overlap_protection: true
          },
          bluetooth: {
            start_freq: '2.402.000.000',
            target_freq: '2.480.000.000',
            demodulator_mode: 'RAW',
            bandwidth: 100_000,
            precision: 5,
            overlap_protection: true
          },
          cdma: {
            start_freq: '824.000.000',
            target_freq: '849.000.000',
            demodulator_mode: 'RAW',
            bandwidth: 125_000,
            precision: 6,
            overlap_protection: false
          },
          cw20: {
            start_freq: '14.000.000',
            target_freq: '14.350.000',
            demodulator_mode: 'CW',
            bandwidth: 150,
            precision: 3,
            overlap_protection: true
          },
          cw40: {
            start_freq: '7.000.000',
            target_freq: '7.300.000',
            demodulator_mode: 'CW',
            bandwidth: 150,
            precision: 3,
            overlap_protection: true
          },
          cw80: {
            start_freq: '3.500.000',
            target_freq: '3.800.000',
            demodulator_mode: 'CW',
            bandwidth: 150,
            precision: 3,
            overlap_protection: true
          },
          fm_radio: {
            start_freq: '87.900.000',
            target_freq: '108.000.000',
            demodulator_mode: 'WFM',
            bandwidth: 200_000,
            precision: 6,
            overlap_protection: true
          },
          frs: {
            start_freq: '462.562.500',
            target_freq: '467.725.000',
            demodulator_mode: 'FM',
            bandwidth: 200_000,
            precision: 3,
            overlap_protection: true
          },
          gmrs: {
            start_freq: '462.550.000',
            target_freq: '467.725.000',
            demodulator_mode: 'FM',
            bandwidth: 200_000,
            precision: 3,
            overlap_protection: true
          },
          gprs: {
            start_freq: '880.000.000',
            target_freq: '915.000.000',
            demodulator_mode: 'RAW',
            bandwidth: 200_000,
            precision: 4,
            overlap_protection: false
          },
          gps_l1: {
            start_freq: '1.574.420.000',
            target_freq: '1.576.420.000',
            demodulator_mode: 'RAW',
            bandwidth: 200_000,
            precision: 6,
            overlap_protection: false
          },
          gps_l2: {
            start_freq: '1.226.600.000',
            target_freq: '1.228.600.000',
            demodulator_mode: 'RAW',
            bandwidth: 200_000,
            precision: 6,
            overlap_protection: false
          },
          gsm: {
            start_freq: '824.000.000',
            target_freq: '894.000.000',
            demodulator_mode: 'RAW',
            bandwidth: 200_000,
            precision: 4,
            overlap_protection: false
          },
          high_rfid: {
            start_freq: '13.560.000',
            target_freq: '13.570.000',
            demodulator_mode: 'RAW',
            bandwidth: 200_000,
            precision: 3,
            overlap_protection: true
          },
          lora433: {
            start_freq: '432.000.000',
            target_freq: '434.000.000',
            demodulator_mode: 'RAW',
            bandwidth: 50_000,
            precision: 3,
            overlap_protection: true
          },
          lora915: {
            start_freq: '902.000.000',
            target_freq: '928.000.000',
            demodulator_mode: 'RAW',
            bandwidth: 50_000,
            precision: 3,
            overlap_protection: true
          },
          low_rfid: {
            start_freq: '125.000',
            target_freq: '134.000',
            demodulator_mode: 'RAW',
            bandwidth: 200_000,
            precision: 1,
            overlap_protection: true
          },
          keyfob300: {
            start_freq: '300.000.000',
            target_freq: '300.100.000',
            demodulator_mode: 'RAW',
            bandwidth: 50_000,
            precision: 4,
            overlap_protection: true
          },
          keyfob310: {
            start_freq: '310.000.000',
            target_freq: '310.100.000',
            demodulator_mode: 'RAW',
            bandwidth: 50_000,
            precision: 4,
            overlap_protection: true
          },
          keyfob315: {
            start_freq: '315.000.000',
            target_freq: '315.100.000',
            demodulator_mode: 'RAW',
            bandwidth: 50_000,
            precision: 4,
            overlap_protection: true
          },
          keyfob390: {
            start_freq: '390.000.000',
            target_freq: '390.100.000',
            demodulator_mode: 'RAW',
            bandwidth: 50_000,
            precision: 4,
            overlap_protection: true
          },
          keyfob433: {
            start_freq: '433.000.000',
            target_freq: '434.000.000',
            demodulator_mode: 'RAW',
            bandwidth: 50_000,
            precision: 4,
            overlap_protection: true
          },
          keyfob868: {
            start_freq: '868.000.000',
            target_freq: '869.000.000',
            demodulator_mode: 'RAW',
            bandwidth: 50_000,
            precision: 4,
            overlap_protection: true
          },
          rtty20: {
            start_freq: '14.000.000',
            target_freq: '14.350.000',
            demodulator_mode: 'RTTY',
            bandwidth: 170,
            precision: 3,
            overlap_protection: true
          },
          rtty40: {
            start_freq: '7.000.000',
            target_freq: '7.300.000',
            demodulator_mode: 'RTTY',
            bandwidth: 170,
            precision: 3,
            overlap_protection: true
          },
          rtty80: {
            start_freq: '3.500.000',
            target_freq: '3.800.000',
            demodulator_mode: 'RTTY',
            bandwidth: 170,
            precision: 3,
            overlap_protection: true
          },
          ssb10: {
            start_freq: '28.000.000',
            target_freq: '29.700.000',
            demodulator_mode: 'USB',
            bandwidth: 2_700,
            precision: 6,
            overlap_protection: true
          },
          ssb12: {
            start_freq: '24.890.000',
            target_freq: '24.990.000',
            demodulator_mode: 'USB',
            bandwidth: 2_700,
            precision: 6,
            overlap_protection: true
          },
          ssb15: {
            start_freq: '21.000.000',
            target_freq: '21.450.000',
            demodulator_mode: 'USB',
            bandwidth: 2_700,
            precision: 6,
            overlap_protection: true
          },
          ssb17: {
            start_freq: '18.068.000',
            target_freq: '18.168.000',
            demodulator_mode: 'USB',
            bandwidth: 2_700,
            precision: 6,
            overlap_protection: true
          },
          ssb20: {
            start_freq: '14.000.000',
            target_freq: '14.350.000',
            demodulator_mode: 'USB',
            bandwidth: 2_700,
            precision: 6,
            overlap_protection: true
          },
          ssb40: {
            start_freq: '7.000.000',
            target_freq: '7.300.000',
            demodulator_mode: 'LSB',
            bandwidth: 2_700,
            precision: 6,
            overlap_protection: true
          },
          ssb80: {
            start_freq: '3.500.000',
            target_freq: '3.800.000',
            demodulator_mode: 'LSB',
            bandwidth: 2_700,
            precision: 6,
            overlap_protection: true
          },
          ssb160: {
            start_freq: '1.800.000',
            target_freq: '2.000.000',
            demodulator_mode: 'LSB',
            bandwidth: 2_700,
            precision: 6,
            overlap_protection: true
          },
          tempest: {
            start_freq: '400.000.000',
            target_freq: '430.000.000',
            demodulator_mode: 'WFM',
            bandwidth: 200_000,
            precision: 4,
            overlap_protection: false
          },
          uhf_rfid: {
            start_freq: '860.000.000',
            target_freq: '960.000.000',
            demodulator_mode: 'RAW',
            bandwidth: 100_000,
            precision: 5,
            overlap_protection: true
          },
          wifi24: {
            start_freq: '2.400.000.000',
            target_freq: '2.500.000.000',
            demodulator_mode: 'RAW',
            bandwidth: 200_000,
            precision: 7,
            overlap_protection: true
          },
          wifi5: {
            start_freq: '5.150.000.000',
            target_freq: '5.850.000.000',
            demodulator_mode: 'RAW',
            bandwidth: 200_000,
            precision: 7,
            overlap_protection: true
          },
          wifi6: {
            start_freq: '5.925.000.000',
            target_freq: '7.125.000.000',
            demodulator_mode: 'RAW',
            bandwidth: 200_000,
            precision: 7,
            overlap_protection: true
          },
          zigbee: {
            start_freq: '2.405.000.000',
            target_freq: '2.485.000.000',
            demodulator_mode: 'RAW',
            bandwidth: 200_000,
            precision: 7,
            overlap_protection: true
          }
        }
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # opts = PWN::SDR::FrequencyAllocation.load(
      #   profile: 'required - valid FrequencyAllocation profile name returned from #profiles method'
      # )
      public_class_method def self.load(opts = {})
        profile = opts[:profile]&.to_sym

        profiles_available = profiles
        raise "ERROR: Invalid profile: #{profile}" unless profiles_available.key?(profile)

        profiles_available[profile]
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
          profiles = #{self}.profiles

          opts = #{self}.load(
            profile: 'required - valid frequency allocation profile name returned from #profiles method'
          )

          #{self}.authors
        "
      end
    end
  end
end
