# frozen_string_literal: true

require 'cgi'
require 'json'

module PWN
  module Plugins
    # This plugin provides useful VIN generation and decoding capabilities using the NHTSA vPIC API
    module VIN
      # Constants for VIN generation
      WEIGHTS = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2].freeze
      LETTER_VALUES = {
        'A' => 1, 'B' => 2, 'C' => 3, 'D' => 4, 'E' => 5, 'F' => 6, 'G' => 7, 'H' => 8,
        'J' => 1, 'K' => 2, 'L' => 3, 'M' => 4, 'N' => 5, 'P' => 7, 'R' => 9,
        'S' => 2, 'T' => 3, 'U' => 4, 'V' => 5, 'W' => 6, 'X' => 7, 'Y' => 8, 'Z' => 9
      }.freeze
      YEAR_CODES = %w[A B C D E F G H J K L M N P R S T V W X Y 1 2 3 4 5 6 7 8 9].freeze

      # Supported Method Parameters:
      # vin_rest_call(
      #   http_method: 'optional - e.g. :get, :post (defaults to :get)',
      #   rest_call: 'required - rest call to make per the schema',
      #   params: 'optional - params passed in the URI or HTTP Headers',
      #   http_headers: 'optional - HTTP Headers to pass in the request'
      # )
      private_class_method def self.vin_rest_call(opts = {})
        http_method = opts[:http_method] || :get
        rest_call = opts[:rest_call]
        params = opts[:params] ||= {}
        headers = opts[:http_headers] ||= {
          content_type: 'application/json; charset=utf-8'
        }

        base_url = 'https://vpic.nhtsa.dot.gov/api/'
        browser_obj = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)
        rest_client = browser_obj[:browser]::Request

        case http_method
        when :get
          headers[:params] = params
          response = rest_client.execute(
            method: http_method,
            url: "#{base_url}#{rest_call}",
            headers: headers,
            verify_ssl: false,
            timeout: 5400
          )
        else
          raise ArgumentError, "Unsupported HTTP method: #{http_method}"
        end

        response
      rescue RestClient::ExceptionWithResponse => e
        if e.response
          puts "HTTP BASE URL: #{base_url}"
          puts "HTTP PATH: #{rest_call}"
          puts "HTTP RESPONSE CODE: #{e.response.code}"
          puts "HTTP RESPONSE HEADERS:\n#{e.response.headers}"
          puts "HTTP RESPONSE BODY:\n#{e.response.body.inspect}\n\n\n"
        end
      rescue StandardError => e
        puts e.backtrace.join("\n")
        raise e
      end

      # Supported Method Parameters:
      # manufacturers = PWN::Plugins::VIN.get_all_manufacturers
      public_class_method def self.get_all_manufacturers
        rest_call = 'vehicles/getallmanufacturers'
        page = 1

        all_manufacturers = []
        loop do
          params = {
            format: 'json',
            page: page
          }
          response = vin_rest_call(
            rest_call: rest_call,
            params: params
          )
          json_resp = JSON.parse(response, symbolize_names: true)
          print '.'
          break if json_resp[:Results].empty?

          page += 1
          all_manufacturers.concat(json_resp[:Results])
        end

        all_manufacturers
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters:
      # makes = PWN::Plugins::VIN.get_all_makes
      public_class_method def self.get_all_makes
        rest_call = 'vehicles/getallmakes'
        params = { format: 'json' }
        response = vin_rest_call(
          rest_call: rest_call,
          params: params
        )
        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters:
      # wmis = PWN::Plugins::VIN.get_wmis_for_manufacturer(
      #   mfr: 'required - Mfr_CommonName returned from #get_all_manufacturers method'
      # )
      public_class_method def self.get_wmis_for_manufacturer(opts = {})
        mfr = opts[:mfr]
        raise "Invalid manufacturer: #{mfr}" unless mfr.is_a?(String)

        uri_encoded_mfr = CGI.escape_uri_component(mfr)
        rest_call = "vehicles/GetWMIsForManufacturer/#{uri_encoded_mfr}"
        params = { format: 'json' }
        response = vin_rest_call(
          rest_call: rest_call,
          params: params
        )
        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters:
      # models = PWN::Plugins::VIN.decode_wmi(
      #   wmi: 'required - WMI to decode (e.g. "1FD")'
      # )
      public_class_method def self.decode_wmi(opts = {})
        wmi = opts[:wmi]
        raise "Invalid WMI: #{wmi}" unless wmi.is_a?(String) && wmi.length == 3

        rest_call = "vehicles/decodewmi/#{wmi}"
        params = { format: 'json' }
        response = vin_rest_call(
          rest_call: rest_call,
          params: params
        )
        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters:
      # models = PWN::Plugins::VIN.decode_vin(
      #   vin: 'required - 17 character VIN to decode'
      # )
      public_class_method def self.decode_vin(opts = {})
        vin = opts[:vin]
        raise "Invalid VIN: #{vin}" unless vin.is_a?(String) && vin.length == 17

        rest_call = "vehicles/decodevin/#{vin}"
        params = { format: 'json' }
        response = vin_rest_call(
          rest_call: rest_call,
          params: params
        )
        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters:
      # models = PWN::Plugins::VIN.get_models_for_make(
      #   make: 'required - Make_Name returned from get_all_makes'
      # )
      public_class_method def self.get_models_for_make(opts = {})
        make = opts[:make]
        valid_makes = get_all_makes[:Results].map { |m| m[:Make_Name] }
        raise "Invalid make: #{make}" unless valid_makes.include?(make.to_s.upcase)

        uri_encoded_make = CGI.escape_uri_component(make)
        rest_call = "vehicles/getmodelsformake/#{uri_encoded_make}"
        params = { format: 'json' }
        response = vin_rest_call(
          rest_call: rest_call,
          params: params
        )
        json_resp = JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters:
      # models = PWN::Plugins::VIN.get_models_for_make_year(
      #   make: 'required - Make_Name returned from get_all_makes',
      #   year: 'optional - e.g. 2023 (defaults to current year)'
      # )
      public_class_method def self.get_models_for_make_year(opts = {})
        make = opts[:make]
        valid_makes = get_all_makes[:Results].map { |m| m[:Make_Name] }
        raise "Invalid make: #{make}" unless valid_makes.include?(make.to_s.upcase)

        year = opts[:year] || Time.now.year

        uri_encoded_make = CGI.escape_uri_component(make)
        rest_call = "vehicles/getmodelsformakeyear/make/#{uri_encoded_make}/modelyear/#{year}"
        params = { format: 'json' }
        response = vin_rest_call(
          rest_call: rest_call,
          params: params
        )
        json_resp = JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters:
      # models = PWN::Plugins::VIN.get_vehicle_types_for_make(
      #   make: 'required - Make_Name returned from get_all_makes'
      # )
      public_class_method def self.get_vehicle_types_for_make(opts = {})
        make = opts[:make]
        valid_makes = get_all_makes[:Results].map { |m| m[:Make_Name] }
        raise "Invalid make: #{make}" unless valid_makes.include?(make.to_s.upcase)

        uri_encoded_make = CGI.escape_uri_component(make)
        rest_call = "vehicles/GetVehicleTypesForMake/#{uri_encoded_make}"
        params = { format: 'json' }
        response = vin_rest_call(
          rest_call: rest_call,
          params: params
        )
        json_resp = JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters:
      # models = PWN::Plugins::VIN.get_manufacturer_details(
      #   mfr: 'required - Mfr_Name returned from get_all_manufacturers'
      # )
      public_class_method def self.get_manufacturer_details(opts = {})
        mfr = opts[:mfr]

        uri_encoded_mfr = CGI.escape_uri_component(mfr)
        rest_call = "vehicles/getmanufacturerdetails/#{uri_encoded_mfr}"
        params = { format: 'json' }
        response = vin_rest_call(
          rest_call: rest_call,
          params: params
        )
        json_resp = JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters:
      # vin = PWN::Plugins::VIN.generate_vin(
      #   mfr: 'required - manufacturer name (i.e. Mfr_CommonName from #get_all_manufacturers)',
      #   year: 'optional - year of the vehicle (defaults to current year)'
      # )
      public_class_method def self.generate_vin(opts = {})
        mfr = opts[:mfr]
        year = opts[:year] || Time.now.year

        raise ArgumentError, 'Manufacturer is required' unless mfr

        wmis = get_wmis_for_manufacturer(mfr: mfr)
        raise "No WMIs found for manufacturer: #{mfr}" if wmis[:Results].empty?

        wmi = wmis[:Results].first[:WMI]
        raise "Invalid WMI: #{wmi}" unless wmi.is_a?(String) && wmi.length == 3

        # Fixed VDS for simplicity
        vds = '12345'
        year_code = get_year_code(year)
        plant_code = 'A'
        serial = format('%06d', rand(1_000_000))

        vin = "#{wmi}#{vds}0#{year_code}#{plant_code}#{serial}"
        check_digit = calculate_check_digit(vin)
        vin[8] = check_digit
        vin
      end

      # Helper method to get the year code for a given year
      private_class_method def self.get_year_code(year)
        index = (year - 1980) % 30
        YEAR_CODES[index]
      end

      # Helper method to calculate the check digit for a VIN
      private_class_method def self.calculate_check_digit(vin)
        raise "Invalid VIN length: #{vin.length}" unless vin.length == 17

        total = 0
        vin.each_char.with_index do |char, i|
          # Skip check digit position
          next if i == 8

          value = if char =~ /\d/
                    char.to_i
                  else
                    LETTER_VALUES[char.upcase] || raise("Invalid character in VIN: #{char}")
                  end
          total += value * WEIGHTS[i]
        end
        check_digit = total % 11
        check_digit = 'X' if check_digit == 10
        check_digit.to_s
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
          manufacturers = #{self}.get_all_manufacturers

          makes = #{self}.get_all_makes

          wmis = #{self}.get_wmis_for_manufacturer(
            mfr: 'required - Mfr_CommonName returned from #get_all_manufacturers method'
          )

          models = #{self}.decode_wmi(
            wmi: 'required - WMI to decode (e.g. \"1FD\")'
          )

          models = #{self}.decode_vin(
            vin: 'required - 17 character VIN to decode'
          )

          models = #{self}.get_models_for_make(
            make: 'required - Make_Name returned from get_all_makes'
          )

          models = #{self}.get_models_for_make_year(
            make: 'required - Make_Name returned from get_all_makes',
            year: 'optional - e.g. 2023 (defaults to current year)'
          )

          models = #{self}.get_vehicle_types_for_make(
            make: 'required - Make_Name returned from get_all_makes'
          )

          details = #{self}.get_manufacturer_details(
            mfr: 'required - Mfr_Name returned from get_all_manufacturers'
          )

          vin = #{self}.generate_vin(
            mfr: 'required - manufacturer name (e.g., Mfr_CommonName from get_all_manufacturers)',
            year: 'optional - year of the vehicle (defaults to current year)'
          )

          #{self}.authors
        "
      end
    end
  end
end
