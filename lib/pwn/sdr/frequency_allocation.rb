# frozen_string_literal: true

module PWN
  module SDR
    # This plugin interacts with the remote control interface of GQRX.
    module FrequencyAllocation
      # Supported Method Parameters::
      # profiles = PWN::SDR::FrequencyAllocation.profiles
      public_class_method def self.profiles
        {
          ads_b978: {
            start_freq: '978.000.000',
            target_freq: '979.000.000',
            demodulator_mode: :RAW,
            bandwidth: '100.000',
            precision: 5
          },
          ads_b1090: {
            start_freq: '1.090.000.000',
            target_freq: '1.091.000.000',
            demodulator_mode: :RAW,
            bandwidth: '100.000',
            precision: 5
          },
          aeronautical_lf: {
            start_freq: '200.000',
            target_freq: '415.000',
            demodulator_mode: :AM,
            bandwidth: '10.000',
            precision: 3
          },
          aeronautical_mf: {
            start_freq: '285.000',
            target_freq: '325.000',
            demodulator_mode: :AM,
            bandwidth: '10.000',
            precision: 3
          },
          amateur_1_25m: {
            start_freq: '222.000.000',
            target_freq: '225.000.000',
            demodulator_mode: :FM,
            bandwidth: '25.000',
            precision: 4
          },
          amateur_160m: {
            start_freq: '1.800.000',
            target_freq: '2.000.000',
            demodulator_mode: :LSB,
            bandwidth: '2.700',
            precision: 6
          },
          amateur_2m: {
            start_freq: '144.000.000',
            target_freq: '148.000.000',
            demodulator_mode: :FM,
            bandwidth: '15.000',
            precision: 4
          },
          amateur_30m: {
            start_freq: '10.100.000',
            target_freq: '10.150.000',
            demodulator_mode: :CW,
            bandwidth: '150',
            precision: 3
          },
          amateur_60m: {
            start_freq: '5.351.500',
            target_freq: '5.366.500',
            demodulator_mode: :USB,
            bandwidth: '2.700',
            precision: 6
          },
          amateur_6m: {
            start_freq: '50.000.000',
            target_freq: '54.000.000',
            demodulator_mode: :USB,
            bandwidth: '2.700',
            precision: 6
          },
          amateur_70cm: {
            start_freq: '420.000.000',
            target_freq: '450.000.000',
            demodulator_mode: :FM,
            bandwidth: '25.000',
            precision: 4
          },
          analog_tv_uhf: {
            start_freq: '470.000.000',
            target_freq: '890.000.000',
            demodulator_mode: :WFM_ST,
            bandwidth: '600.000',
            precision: 5
          },
          analog_tv_vhf: {
            start_freq: '54.000.000',
            target_freq: '216.000.000',
            demodulator_mode: :WFM_ST,
            bandwidth: '600.000',
            precision: 5
          },
          am_radio: {
            start_freq: '540.000',
            target_freq: '1.700.000',
            demodulator_mode: :AM,
            bandwidth: '10.000',
            precision: 4
          },
          aviation_nav: {
            start_freq: '108.000.000',
            target_freq: '118.000.000',
            demodulator_mode: :AM,
            bandwidth: '25.000',
            precision: 4
          },
          aviation_vhf: {
            start_freq: '118.000.000',
            target_freq: '137.000.000',
            demodulator_mode: :AM,
            bandwidth: '25.000',
            precision: 4
          },
          aws: {
            start_freq: '1.710.000.000',
            target_freq: '1.755.000.000',
            demodulator_mode: :RAW,
            bandwidth: '200.000',
            precision: 6
          },
          bluetooth: {
            start_freq: '2.402.000.000',
            target_freq: '2.480.000.000',
            demodulator_mode: :RAW,
            bandwidth: '1.000.000',
            precision: 5
          },
          cb: {
            start_freq: '26.965.000',
            target_freq: '27.405.000',
            demodulator_mode: :AM,
            bandwidth: '10.000',
            precision: 3
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
          dect: {
            start_freq: '1.880.000.000',
            target_freq: '1.900.000.000',
            demodulator_mode: :RAW,
            bandwidth: '100.000',
            precision: 5
          },
          fm_radio: {
            start_freq: '87.900.000',
            target_freq: '108.000.000',
            demodulator_mode: :WFM_ST,
            bandwidth: '200.000',
            precision: 6,
            decoder: :rds
          },
          frs: {
            start_freq: '462.562.500',
            target_freq: '467.725.000',
            demodulator_mode: :FM,
            bandwidth: '200.000',
            precision: 3
          },
          gmrs: {
            start_freq: '462.550.000',
            target_freq: '467.725.000',
            demodulator_mode: :FM,
            bandwidth: '200.000',
            precision: 3
          },
          gprs: {
            start_freq: '880.000.000',
            target_freq: '915.000.000',
            demodulator_mode: :RAW,
            bandwidth: '171.200',
            precision: 4
          },
          gps_l1: {
            start_freq: '1.574.420.000',
            target_freq: '1.576.420.000',
            demodulator_mode: :RAW,
            bandwidth: '30.000.000',
            precision: 6
          },
          gps_l2: {
            start_freq: '1.226.600.000',
            target_freq: '1.228.600.000',
            demodulator_mode: :RAW,
            bandwidth: '11.000.000',
            precision: 6
          },
          gsm: {
            start_freq: '824.000.000',
            target_freq: '894.000.000',
            demodulator_mode: :RAW,
            bandwidth: '200.000',
            precision: 4
          },
          high_rfid: {
            start_freq: '13.560.000',
            target_freq: '13.570.000',
            demodulator_mode: :RAW,
            bandwidth: '400.000',
            precision: 3
          },
          iridium: {
            start_freq: '1.616.000.000',
            target_freq: '1.626.500.000',
            demodulator_mode: :RAW,
            bandwidth: '704.000',
            precision: 6
          },
          ism_5g: {
            start_freq: '5.725.000.000',
            target_freq: '5.875.000.000',
            demodulator_mode: :RAW,
            bandwidth: '150.000.000',
            precision: 7
          },
          ism_902: {
            start_freq: '902.000.000',
            target_freq: '928.000.000',
            demodulator_mode: :RAW,
            bandwidth: '26.000.000',
            precision: 3
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
          keyfob433: {
            start_freq: '433.000.000',
            target_freq: '434.000.000',
            demodulator_mode: :RAW,
            bandwidth: '50.000',
            precision: 4
          },
          keyfob868: {
            start_freq: '868.000.000',
            target_freq: '869.000.000',
            demodulator_mode: :RAW,
            bandwidth: '50.000',
            precision: 4
          },
          land_mobile_uhf: {
            start_freq: '450.000.000',
            target_freq: '470.000.000',
            demodulator_mode: :FM,
            bandwidth: '25.000',
            precision: 4
          },
          land_mobile_vhf: {
            start_freq: '150.000.000',
            target_freq: '174.000.000',
            demodulator_mode: :FM,
            bandwidth: '25.000',
            precision: 4
          },
          longwave_broadcast: {
            start_freq: '148.500',
            target_freq: '283.500',
            demodulator_mode: :AM,
            bandwidth: '10.000',
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
            start_freq: '902.000.000',
            target_freq: '928.000.000',
            demodulator_mode: :RAW,
            bandwidth: '500.000',
            precision: 3
          },
          low_rfid: {
            start_freq: '125.000',
            target_freq: '134.000',
            demodulator_mode: :RAW,
            bandwidth: '40.000',
            precision: 1
          },
          marine_vhf: {
            start_freq: '156.000.000',
            target_freq: '162.000.000',
            demodulator_mode: :FM,
            bandwidth: '25.000',
            precision: 4
          },
          maritime_mf: {
            start_freq: '415.000',
            target_freq: '535.000',
            demodulator_mode: :USB,
            bandwidth: '2.700',
            precision: 6
          },
          noaa_weather: {
            start_freq: '162.400.000',
            target_freq: '162.550.000',
            demodulator_mode: :FM,
            bandwidth: '16.000',
            precision: 4
          },
          pager: {
            start_freq: '929.000.000',
            target_freq: '932.000.000',
            demodulator_mode: :FM,
            bandwidth: '12.500',
            precision: 4
          },
          pcs: {
            start_freq: '1.850.000.000',
            target_freq: '1.990.000.000',
            demodulator_mode: :RAW,
            bandwidth: '200.000',
            precision: 6
          },
          public_safety_700: {
            start_freq: '698.000.000',
            target_freq: '806.000.000',
            demodulator_mode: :FM,
            bandwidth: '25.000',
            precision: 4
          },
          rtty20: {
            start_freq: '14.000.000',
            target_freq: '14.350.000',
            demodulator_mode: :FM,
            bandwidth: '170',
            precision: 3
          },
          rtty40: {
            start_freq: '7.000.000',
            target_freq: '7.300.000',
            demodulator_mode: :FM,
            bandwidth: '170',
            precision: 3
          },
          rtty80: {
            start_freq: '3.500.000',
            target_freq: '3.800.000',
            demodulator_mode: :FM,
            bandwidth: '170',
            precision: 3
          },
          shortwave1: {
            start_freq: '5.900.000',
            target_freq: '6.200.000',
            demodulator_mode: :AM_SYNC,
            bandwidth: '10.000',
            precision: 4
          },
          shortwave2: {
            start_freq: '7.200.000',
            target_freq: '7.450.000',
            demodulator_mode: :AM_SYNC,
            bandwidth: '10.000',
            precision: 4
          },
          shortwave3: {
            start_freq: '9.400.000',
            target_freq: '9.900.000',
            demodulator_mode: :AM_SYNC,
            bandwidth: '10.000',
            precision: 4
          },
          shortwave4: {
            start_freq: '11.600.000',
            target_freq: '12.100.000',
            demodulator_mode: :AM_SYNC,
            bandwidth: '10.000',
            precision: 4
          },
          shortwave5: {
            start_freq: '13.570.000',
            target_freq: '13.870.000',
            demodulator_mode: :AM_SYNC,
            bandwidth: '10.000',
            precision: 4
          },
          shortwave6: {
            start_freq: '15.100.000',
            target_freq: '15.800.000',
            demodulator_mode: :AM_SYNC,
            bandwidth: '10.000',
            precision: 4
          },
          ssb10: {
            start_freq: '28.000.000',
            target_freq: '29.700.000',
            demodulator_mode: :USB,
            bandwidth: '3.000',
            precision: 6
          },
          ssb12: {
            start_freq: '24.890.000',
            target_freq: '24.990.000',
            demodulator_mode: :USB,
            bandwidth: '3.000',
            precision: 6
          },
          ssb15: {
            start_freq: '21.000.000',
            target_freq: '21.450.000',
            demodulator_mode: :USB,
            bandwidth: '3.000',
            precision: 6
          },
          ssb17: {
            start_freq: '18.068.000',
            target_freq: '18.168.000',
            demodulator_mode: :USB,
            bandwidth: '3.000',
            precision: 6
          },
          ssb20: {
            start_freq: '14.000.000',
            target_freq: '14.350.000',
            demodulator_mode: :USB,
            bandwidth: '3.000',
            precision: 6
          },
          ssb40: {
            start_freq: '7.000.000',
            target_freq: '7.300.000',
            demodulator_mode: :LSB,
            bandwidth: '3.000',
            precision: 6
          },
          ssb80: {
            start_freq: '3.500.000',
            target_freq: '3.800.000',
            demodulator_mode: :LSB,
            bandwidth: '3.000',
            precision: 6
          },
          ssb160: {
            start_freq: '1.800.000',
            target_freq: '2.000.000',
            demodulator_mode: :LSB,
            bandwidth: '3.000',
            precision: 6
          },
          tempest: {
            start_freq: '400.000.000',
            target_freq: '430.000.000',
            demodulator_mode: :WFM,
            bandwidth: '6.000.000',
            precision: 4
          },
          tv_high_vhf: {
            start_freq: '174.000.000',
            target_freq: '216.000.000',
            demodulator_mode: :WFM_ST,
            bandwidth: '6.000.000',
            precision: 5
          },
          tv_low_vhf: {
            start_freq: '54.000.000',
            target_freq: '88.000.000',
            demodulator_mode: :WFM_ST,
            bandwidth: '6.000.000',
            precision: 5
          },
          tv_uhf: {
            start_freq: '470.000.000',
            target_freq: '698.000.000',
            demodulator_mode: :WFM_ST,
            bandwidth: '6.000.000',
            precision: 5
          },
          uhf_rfid: {
            start_freq: '860.000.000',
            target_freq: '960.000.000',
            demodulator_mode: :RAW,
            bandwidth: '400.000',
            precision: 5
          },
          umts: {
            start_freq: '1.920.000.000',
            target_freq: '2.170.000.000',
            demodulator_mode: :RAW,
            bandwidth: '5.000.000',
            precision: 6
          },
          weather_sat: {
            start_freq: '137.000.000',
            target_freq: '138.000.000',
            demodulator_mode: :FM,
            bandwidth: '15.000',
            precision: 5
          },
          wifi24: {
            start_freq: '2.400.000.000',
            target_freq: '2.500.000.000',
            demodulator_mode: :RAW,
            bandwidth: '20.000.000',
            precision: 7
          },
          wifi5: {
            start_freq: '5.150.000.000',
            target_freq: '5.850.000.000',
            demodulator_mode: :RAW,
            bandwidth: '20.000.000',
            precision: 7
          },
          wifi6: {
            start_freq: '5.925.000.000',
            target_freq: '7.125.000.000',
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

          #{self}.authors
        "
      end
    end
  end
end
