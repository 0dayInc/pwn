# frozen_string_literal: true

module PWN
  module SDR
    # This moule contains methods for managing frequency allocation band plans
    module FrequencyAllocation
      # Supported Method Parameters::
      # band_plans = PWN::SDR::FrequencyAllocation.band_plans
      public_class_method def self.band_plans
        {
          ads_b978: {
            ranges: [
              { start_freq: '978.000.000', target_freq: '979.000.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '100.000',
            precision: 5,
            input_rate: 2_000_000
          },
          ads_b1090: {
            ranges: [
              { start_freq: '1.090.000.000', target_freq: '1.091.000.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '100.000',
            precision: 5,
            input_rate: 2_000_000
          },
          aeronautical_lf: {
            ranges: [
              { start_freq: '200.000', target_freq: '415.000' }
            ],
            demodulator_mode: :AM,
            bandwidth: '10.000',
            precision: 3,
            input_rate: 1_000_000
          },
          aeronautical_mf: {
            ranges: [
              { start_freq: '285.000', target_freq: '325.000' }
            ],
            demodulator_mode: :AM,
            bandwidth: '10.000',
            precision: 3,
            input_rate: 1_000_000
          },
          amateur_1_25m: {
            ranges: [
              { start_freq: '222.000.000', target_freq: '225.000.000' }
            ],
            demodulator_mode: :FM,
            bandwidth: '25.000',
            precision: 4,
            input_rate: 1_000_000
          },
          amateur_160m: {
            ranges: [
              { start_freq: '1.800.000', target_freq: '2.000.000' }
            ],
            demodulator_mode: :LSB,
            bandwidth: '2.700',
            precision: 6,
            input_rate: 1_000_000
          },
          amateur_2m: {
            ranges: [
              { start_freq: '144.000.000', target_freq: '148.000.000' }
            ],
            demodulator_mode: :FM,
            bandwidth: '15.000',
            precision: 4,
            input_rate: 1_000_000
          },
          amateur_30m: {
            ranges: [
              { start_freq: '10.100.000', target_freq: '10.150.000' }
            ],
            demodulator_mode: :CW,
            bandwidth: '150',
            precision: 3,
            input_rate: 1_000_000
          },
          amateur_60m: {
            ranges: [
              { start_freq: '5.351.500', target_freq: '5.366.500' }
            ],
            demodulator_mode: :USB,
            bandwidth: '2.700',
            precision: 6,
            input_rate: 1_000_000
          },
          amateur_6m: {
            ranges: [
              { start_freq: '50.000.000', target_freq: '54.000.000' }
            ],
            demodulator_mode: :USB,
            bandwidth: '2.700',
            precision: 6,
            input_rate: 1_000_000
          },
          amateur_70cm: {
            ranges: [
              { start_freq: '420.000.000', target_freq: '450.000.000' }
            ],
            demodulator_mode: :FM,
            bandwidth: '25.000',
            precision: 4,
            input_rate: 1_000_000
          },
          analog_tv_uhf: {
            ranges: [
              { start_freq: '470.000.000', target_freq: '890.000.000' }
            ],
            demodulator_mode: :WFM_ST,
            bandwidth: '600.000',
            precision: 5,
            input_rate: 10_000_000
          },
          analog_tv_vhf: {
            ranges: [
              { start_freq: '54.000.000', target_freq: '216.000.000' }
            ],
            demodulator_mode: :WFM_ST,
            bandwidth: '600.000',
            precision: 5,
            input_rate: 10_000_000
          },
          am_radio: {
            ranges: [
              { start_freq: '540.000', target_freq: '1.700.000' }
            ],
            demodulator_mode: :AM,
            bandwidth: '10.000',
            precision: 4,
            input_rate: 1_000_000
          },
          aviation_nav: {
            ranges: [
              { start_freq: '108.000.000', target_freq: '118.000.000' }
            ],
            demodulator_mode: :AM,
            bandwidth: '25.000',
            precision: 4,
            input_rate: 1_000_000
          },
          aviation_vhf: {
            ranges: [
              { start_freq: '118.000.000', target_freq: '137.000.000' }
            ],
            demodulator_mode: :AM,
            bandwidth: '25.000',
            precision: 4,
            input_rate: 1_000_000
          },
          aws: {
            ranges: [
              { start_freq: '1.710.000.000', target_freq: '1.755.000.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '200.000',
            precision: 6,
            input_rate: 2_000_000
          },
          bluetooth: {
            ranges: [
              { start_freq: '2.402.000.000', target_freq: '2.480.000.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '1.000.000',
            precision: 5,
            input_rate: 2_000_000
          },
          cb: {
            ranges: [
              { start_freq: '26.965.000', target_freq: '27.405.000' }
            ],
            demodulator_mode: :AM,
            bandwidth: '10.000',
            precision: 3,
            input_rate: 1_000_000
          },
          cdma: {
            ranges: [
              { start_freq: '824.000.000', target_freq: '849.000.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '1.250.000',
            precision: 6,
            input_rate: 2_000_000
          },
          cw20: {
            ranges: [
              { start_freq: '14.000.000', target_freq: '14.350.000' }
            ],
            demodulator_mode: :CW,
            bandwidth: '150',
            precision: 3,
            input_rate: 1_000_000
          },
          cw40: {
            ranges: [
              { start_freq: '7.000.000', target_freq: '7.300.000' }
            ],
            demodulator_mode: :CW,
            bandwidth: '150',
            precision: 3,
            input_rate: 1_000_000
          },
          cw80: {
            ranges: [
              { start_freq: '3.500.000', target_freq: '3.800.000' }
            ],
            demodulator_mode: :CW,
            bandwidth: '150',
            precision: 3,
            input_rate: 1_000_000
          },
          dect: {
            ranges: [
              { start_freq: '1.880.000.000', target_freq: '1.900.000.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '100.000',
            precision: 5,
            input_rate: 2_000_000
          },
          fm_radio: {
            ranges: [
              { start_freq: '87.900.000', target_freq: '108.000.000' }
            ],
            demodulator_mode: :WFM_ST,
            bandwidth: '200.000',
            precision: 6,
            input_rate: 1_000_000,
            decoder: :rds
          },
          frs: {
            ranges: [
              { start_freq: '462.562.500', target_freq: '467.725.000' }
            ],
            demodulator_mode: :FM,
            bandwidth: '200.000',
            precision: 3,
            input_rate: 1_000_000
          },
          gmrs: {
            ranges: [
              { start_freq: '462.550.000', target_freq: '467.725.000' }
            ],
            demodulator_mode: :FM,
            bandwidth: '200.000',
            precision: 3,
            input_rate: 1_000_000
          },
          gprs: {
            ranges: [
              { start_freq: '880.000.000', target_freq: '915.000.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '171.200',
            precision: 4,
            input_rate: 2_000_000
          },
          gps_l1: {
            ranges: [
              { start_freq: '1.574.420.000', target_freq: '1.576.420.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '30.000.000',
            precision: 6,
            input_rate: 20_000_000
          },
          gps_l2: {
            ranges: [
              { start_freq: '1.226.600.000', target_freq: '1.228.600.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '11.000.000',
            precision: 6,
            input_rate: 20_000_000
          },
          gsm: {
            ranges: [
              { start_freq: '824.000.000', target_freq: '894.000.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '200.000',
            precision: 4,
            input_rate: 2_000_000
          },
          high_rfid: {
            ranges: [
              { start_freq: '13.560.000', target_freq: '13.570.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '400.000',
            precision: 3,
            input_rate: 1_000_000
          },
          iridium: {
            ranges: [
              { start_freq: '1.616.000.000', target_freq: '1.626.500.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '704.000',
            precision: 6,
            input_rate: 2_000_000
          },
          ism_5g: {
            ranges: [
              { start_freq: '5.725.000.000', target_freq: '5.875.000.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '150.000.000',
            precision: 7,
            input_rate: 20_000_000
          },
          ism_902: {
            ranges: [
              { start_freq: '902.000.000', target_freq: '928.000.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '26.000.000',
            precision: 3,
            input_rate: 20_000_000
          },
          keyfob300: {
            ranges: [
              { start_freq: '300.000.000', target_freq: '300.100.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '50.000',
            precision: 4,
            input_rate: 1_000_000
          },
          keyfob310: {
            ranges: [
              { start_freq: '310.000.000', target_freq: '310.100.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '50.000',
            precision: 4,
            input_rate: 1_000_000
          },
          keyfob315: {
            ranges: [
              { start_freq: '315.000.000', target_freq: '315.100.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '50.000',
            precision: 4,
            input_rate: 1_000_000
          },
          keyfob390: {
            ranges: [
              { start_freq: '390.000.000', target_freq: '390.100.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '50.000',
            precision: 4,
            input_rate: 1_000_000
          },
          keyfob433: {
            ranges: [
              { start_freq: '433.000.000', target_freq: '434.000.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '50.000',
            precision: 4,
            input_rate: 1_000_000
          },
          keyfob868: {
            ranges: [
              { start_freq: '868.000.000', target_freq: '869.000.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '50.000',
            precision: 4,
            input_rate: 1_000_000
          },
          land_mobile_uhf: {
            ranges: [
              { start_freq: '450.000.000', target_freq: '470.000.000' }
            ],
            demodulator_mode: :FM,
            bandwidth: '25.000',
            precision: 4,
            input_rate: 1_000_000
          },
          land_mobile_vhf: {
            ranges: [
              { start_freq: '150.000.000', target_freq: '174.000.000' }
            ],
            demodulator_mode: :FM,
            bandwidth: '25.000',
            precision: 4,
            input_rate: 1_000_000
          },
          longwave_broadcast: {
            ranges: [
              { start_freq: '148.500', target_freq: '283.500' }
            ],
            demodulator_mode: :AM,
            bandwidth: '10.000',
            precision: 3,
            input_rate: 1_000_000
          },
          lora4x: {
            ranges: [
              { start_freq: '433.000.000', target_freq: '434.000.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '500.000',
            precision: 3,
            input_rate: 2_000_000
          },
          lora8x: {
            ranges: [
              { start_freq: '869.400.000', target_freq: '869.650.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '500.000',
            precision: 3,
            input_rate: 2_000_000
          },
          lora9x: {
            ranges: [
              { start_freq: '902.000.000', target_freq: '928.000.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '500.000',
            precision: 3,
            input_rate: 2_000_000
          },
          low_rfid: {
            ranges: [
              { start_freq: '125.000', target_freq: '134.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '40.000',
            precision: 1,
            input_rate: 1_000_000
          },
          marine_vhf: {
            ranges: [
              { start_freq: '156.000.000', target_freq: '162.000.000' }
            ],
            demodulator_mode: :FM,
            bandwidth: '25.000',
            precision: 4,
            input_rate: 1_000_000
          },
          maritime_mf: {
            ranges: [
              { start_freq: '415.000', target_freq: '535.000' }
            ],
            demodulator_mode: :USB,
            bandwidth: '2.700',
            precision: 6,
            input_rate: 1_000_000
          },
          noaa_weather: {
            ranges: [
              { start_freq: '162.400.000', target_freq: '162.550.000' }
            ],
            demodulator_mode: :FM,
            bandwidth: '16.000',
            precision: 4,
            input_rate: 1_000_000
          },
          pager_all: {
            ranges: [
              # Low-power / unlicensed / CB-related (very limited POCSAG usage)
              # RCRS channels (shared data/telemetry, occasional POCSAG)
              { start_freq: '26.995.000', target_freq: '27.195.000' },
              # Single channel — CB ch. 23, unlicensed paging/telemetry allowed (Part 95)
              { start_freq: '27.255.000', target_freq: '27.255.000' },

              # Low-band VHF paging (limited, many reallocated)
              # Exclusive paging allocation (35–36 MHz)
              { start_freq: '35.000.000', target_freq: '36.000.000' },
              # Exclusive paging allocation (43–44 MHz)
              { start_freq: '43.000.000', target_freq: '44.000.000' },

              # High-band VHF paging — most common for public-safety POCSAG today
              # Classic VHF paging band (152/157/158 MHz very common)
              { start_freq: '152.000.000', target_freq: '159.000.000' },

              # UHF paging bands (hospital, on-site, restaurant/coaster pagers, some public safety)
              # UHF low — occasional private systems
              { start_freq: '400.000.000',  target_freq: '430.000.000' },
              # UHF high — very common for local POCSAG (incl. 450–470 & 467.xxx for on-site)
              { start_freq: '440.000.000',  target_freq: '470.000.000' },
              # Classic UHF paging allocation (454/459 MHz pairs — many reallocated)
              { start_freq: '454.000.000',  target_freq: '460.000.000' },

              # 900 MHz exclusive paging band (mostly FLEX, but some legacy POCSAG remains)
              # Primary nationwide commercial paging band
              { start_freq: '929.000.000', target_freq: '932.000.000' }
            ],
            demodulator_mode: :FM,
            bandwidth: '25.000',
            precision: 4,
            input_rate: 1_000_000
          },
          pager_flex: {
            ranges: [
              # 900 MHz exclusive paging band (mostly FLEX, but some legacy POCSAG remains)
              # Primary nationwide commercial paging band
              { start_freq: '929.000.000', target_freq: '932.000.000' }
            ],
            demodulator_mode: :FM,
            bandwidth: '20.000',
            precision: 4,
            input_rate: 1_000_000,
            decoder: :flex
          },
          pager_pocsag: {
            ranges: [
              # High-band VHF paging — most common for public-safety POCSAG today
              # Classic VHF paging band (152/157/158 MHz very common)
              { start_freq: '152.000.000', target_freq: '159.000.000' },

              # UHF paging bands (hospital, on-site, restaurant/coaster pagers, some public safety)
              # UHF low — occasional private systems
              { start_freq: '400.000.000',  target_freq: '430.000.000' },
              # UHF high — very common for local POCSAG (incl. 450–470 & 467.xxx for on-site)
              { start_freq: '440.000.000',  target_freq: '470.000.000' },
              # Classic UHF paging allocation (454/459 MHz pairs — many reallocated)
              { start_freq: '454.000.000',  target_freq: '460.000.000' }
            ],
            demodulator_mode: :FM,
            bandwidth: '12.500',
            precision: 4,
            input_rate: 1_000_000,
            decoder: :pocsag
          },
          pcs: {
            ranges: [
              { start_freq: '1.850.000.000', target_freq: '1.990.000.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '200.000',
            precision: 6,
            input_rate: 2_000_000
          },
          public_safety_700: {
            ranges: [
              { start_freq: '698.000.000', target_freq: '806.000.000' }
            ],
            demodulator_mode: :FM,
            bandwidth: '25.000',
            precision: 4,
            input_rate: 1_000_000
          },
          rtty20: {
            ranges: [
              { start_freq: '14.000.000', target_freq: '14.350.000' }
            ],
            demodulator_mode: :FM,
            bandwidth: '170',
            precision: 3,
            input_rate: 1_000_000
          },
          rtty40: {
            ranges: [
              { start_freq: '7.000.000', target_freq: '7.300.000' }
            ],
            demodulator_mode: :FM,
            bandwidth: '170',
            precision: 3,
            input_rate: 1_000_000
          },
          rtty80: {
            ranges: [
              { start_freq: '3.500.000', target_freq: '3.800.000' }
            ],
            demodulator_mode: :FM,
            bandwidth: '170',
            precision: 3,
            input_rate: 1_000_000
          },
          shortwave1: {
            ranges: [
              { start_freq: '5.900.000', target_freq: '6.200.000' }
            ],
            demodulator_mode: :AM_SYNC,
            bandwidth: '10.000',
            precision: 4,
            input_rate: 1_000_000
          },
          shortwave2: {
            ranges: [
              { start_freq: '7.200.000', target_freq: '7.450.000' }
            ],
            demodulator_mode: :AM_SYNC,
            bandwidth: '10.000',
            precision: 4,
            input_rate: 1_000_000
          },
          shortwave3: {
            ranges: [
              { start_freq: '9.400.000', target_freq: '9.900.000' }
            ],
            demodulator_mode: :AM_SYNC,
            bandwidth: '10.000',
            precision: 4,
            input_rate: 1_000_000
          },
          shortwave4: {
            ranges: [
              { start_freq: '11.600.000', target_freq: '12.100.000' }
            ],
            demodulator_mode: :AM_SYNC,
            bandwidth: '10.000',
            precision: 4,
            input_rate: 1_000_000
          },
          shortwave5: {
            ranges: [
              { start_freq: '13.570.000', target_freq: '13.870.000' }
            ],
            demodulator_mode: :AM_SYNC,
            bandwidth: '10.000',
            precision: 4,
            input_rate: 1_000_000
          },
          shortwave6: {
            ranges: [
              { start_freq: '15.100.000', target_freq: '15.800.000' }
            ],
            demodulator_mode: :AM_SYNC,
            bandwidth: '10.000',
            precision: 4,
            input_rate: 1_000_000
          },
          ssb10: {
            ranges: [
              { start_freq: '28.000.000', target_freq: '29.700.000' }
            ],
            demodulator_mode: :USB,
            bandwidth: '3.000',
            precision: 6,
            input_rate: 1_000_000
          },
          ssb12: {
            ranges: [
              { start_freq: '24.890.000', target_freq: '24.990.000' }
            ],
            demodulator_mode: :USB,
            bandwidth: '3.000',
            precision: 6,
            input_rate: 1_000_000
          },
          ssb15: {
            ranges: [
              { start_freq: '21.000.000', target_freq: '21.450.000' }
            ],
            demodulator_mode: :USB,
            bandwidth: '3.000',
            precision: 6,
            input_rate: 1_000_000
          },
          ssb17: {
            ranges: [
              { start_freq: '18.068.000', target_freq: '18.168.000' }
            ],
            demodulator_mode: :USB,
            bandwidth: '3.000',
            precision: 6,
            input_rate: 1_000_000
          },
          ssb20: {
            ranges: [
              { start_freq: '14.000.000', target_freq: '14.350.000' }
            ],
            demodulator_mode: :USB,
            bandwidth: '3.000',
            precision: 6,
            input_rate: 1_000_000
          },
          ssb40: {
            ranges: [
              { start_freq: '7.000.000', target_freq: '7.300.000' }
            ],
            demodulator_mode: :LSB,
            bandwidth: '3.000',
            precision: 6,
            input_rate: 1_000_000
          },
          ssb80: {
            ranges: [
              { start_freq: '3.500.000', target_freq: '3.800.000' }
            ],
            demodulator_mode: :LSB,
            bandwidth: '3.000',
            precision: 6,
            input_rate: 1_000_000
          },
          ssb160: {
            ranges: [
              { start_freq: '1.800.000', target_freq: '2.000.000' }
            ],
            demodulator_mode: :LSB,
            bandwidth: '3.000',
            precision: 6,
            input_rate: 1_000_000
          },
          tempest: {
            ranges: [
              { start_freq: '400.000.000', target_freq: '430.000.000' }
            ],
            demodulator_mode: :WFM,
            bandwidth: '6.000.000',
            precision: 4,
            input_rate: 10_000_000
          },
          tv_high_vhf: {
            ranges: [
              { start_freq: '174.000.000', target_freq: '216.000.000' }
            ],
            demodulator_mode: :WFM_ST,
            bandwidth: '6.000.000',
            precision: 5,
            input_rate: 10_000_000
          },
          tv_low_vhf: {
            ranges: [
              { start_freq: '54.000.000', target_freq: '88.000.000' }
            ],
            demodulator_mode: :WFM_ST,
            bandwidth: '6.000.000',
            precision: 5,
            input_rate: 10_000_000
          },
          tv_uhf: {
            ranges: [
              { start_freq: '470.000.000', target_freq: '698.000.000' }
            ],
            demodulator_mode: :WFM_ST,
            bandwidth: '6.000.000',
            precision: 5,
            input_rate: 10_000_000
          },
          uhf_rfid: {
            ranges: [
              { start_freq: '860.000.000', target_freq: '960.000.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '400.000',
            precision: 5,
            input_rate: 1_000_000
          },
          umts: {
            ranges: [
              { start_freq: '1.920.000.000', target_freq: '2.170.000.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '5.000.000',
            precision: 6,
            input_rate: 10_000_000
          },
          weather_sat: {
            ranges: [
              { start_freq: '137.000.000', target_freq: '138.000.000' }
            ],
            demodulator_mode: :FM,
            bandwidth: '15.000',
            precision: 5,
            input_rate: 1_000_000
          },
          wifi24: {
            ranges: [
              { start_freq: '2.400.000.000', target_freq: '2.500.000.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '20.000.000',
            precision: 7,
            input_rate: 20_000_000
          },
          wifi5: {
            ranges: [
              { start_freq: '5.150.000.000', target_freq: '5.850.000.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '20.000.000',
            precision: 7,
            input_rate: 20_000_000
          },
          wifi6: {
            ranges: [
              { start_freq: '5.925.000.000', target_freq: '7.125.000.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '20.000.000',
            precision: 7,
            input_rate: 20_000_000
          },
          zigbee: {
            ranges: [
              { start_freq: '2.405.000.000', target_freq: '2.485.000.000' }
            ],
            demodulator_mode: :RAW,
            bandwidth: '2.000.000',
            precision: 7,
            input_rate: 2_000_000
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
          band_plans = #{self}.band_plans

          #{self}.authors
        "
      end
    end
  end
end
