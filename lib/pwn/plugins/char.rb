# frozen_string_literal: true

require 'cgi'
require 'htmlentities'

module PWN
  module Plugins
    # This plugin was created to generate various characters for fuzzing
    module Char
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # PWN::Plugins::Char.generate_by_range(
      #   from: 'required - integer to start from',
      #   to: 'required - integer to end UTF-8 generation'
      # )

      public_class_method def self.generate_by_range(opts = {})
        from = opts[:from].to_i
        to = opts[:to].to_i

        char_arr = []

        encoder_arr = list_encoders
        encoder_arr.delete('UTF-8')

        (from..to).each do |this_int|
          char_hash = {}

          this_bin = format('%08d', this_int.to_s(2))
          this_dec = this_int
          this_hex = format('%02x', this_int)
          # this_long_int = [this_int].pack('L>').unpack1('H*').scan(/../).map { |h| '\x' + h }.join
          this_long_int = [this_int].pack('L>').unpack1('H*').scan(/../).map { |h| "\\x#{h}" }.join
          this_oct = format('\%03d', this_int.to_s(8))
          # this_short_int = [this_int].pack('S>').unpack1('H*').scan(/../).map { |h| '\x' + h }.join
          this_short_int = [this_int].pack('S>').unpack1('H*').scan(/../).map { |h| "\\x#{h}" }.join
          this_utf8 = [this_int].pack('U*')

          begin
            # Begins breaking once this_int reaches 55296
            this_html_entity = HTMLEntities.new.encode(this_utf8)
            this_html_entity_dec = HTMLEntities.new.encode(this_utf8, :decimal)
            this_html_entity_hex = HTMLEntities.new.encode(this_utf8, :hexadecimal)
          rescue ArgumentError
            this_html_entity = "***max_int<#{this_int}"
            this_html_entity_dec = "***max_int<#{this_int}"
            thishtml_entity_hex = "***max_int<#{this_int}"
            next
          end

          this_url = CGI.escape(this_utf8)

          # To date Base 2 - Base 36 is supported:
          # (0..999).each {|base| begin; puts "#{base} => #{this_dec.to_s(base)}"; rescue; next; end }
          char_hash[:bin] = { char: this_bin, encoder: nil }
          char_hash[:dec] = { char: this_dec, encoder: nil }
          char_hash[:hex] = { char: this_hex, encoder: nil }
          char_hash[:html_entity] = { char: this_html_entity, encoder: nil }
          char_hash[:html_entity_dec] = { char: this_html_entity_dec, encoder: nil }
          char_hash[:html_entity_hex] = { char: this_html_entity_hex, encoder: nil }
          char_hash[:long_int] = { char: this_long_int, encoder: nil }
          char_hash[:oct] = { char: this_oct, encoder: nil }
          char_hash[:short_int] = { char: this_short_int, encoder: nil }
          char_hash[:url] = { char: this_url, encoder: nil }
          char_hash[:utf8] = { char: this_utf8, encoder: 'UTF-8' }

          encoder_arr.each do |encoder|
            this_encoder_key = encoder.downcase.tr('-', '_').to_sym
            begin
              char_hash[this_encoder_key] = {
                char: this_utf8.encode(encoder, 'UTF-8'),
                encoder: encoder
              }
            rescue Encoding::InvalidByteSequenceError
              char_hash[this_encoder_key] = {
                char: "***invalid_byte_seq@#{this_int}",
                encoder: encoder
              }
              next
            rescue Encoding::UndefinedConversionError
              char_hash[this_encoder_key] = {
                char: "***max_int<#{this_int}",
                encoder: encoder
              }
              next
            rescue Encoding::ConverterNotFoundError
              char_hash[this_encoder_key] = {
                char: '***convertor_not_found',
                encoder: encoder
              }
              next
            end
          end

          sorted_char_hash = char_hash.sort.to_h
          char_arr.push(sorted_char_hash)
        end

        char_arr
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Char.c0_controls_latin_basic

      public_class_method def self.c0_controls_latin_basic
        generate_by_range(from: 0, to: 127)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Char.c1_controls_latin_supplement

      public_class_method def self.c1_controls_latin_supplement
        generate_by_range(from: 128, to: 255)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Char.latin_extended_a

      public_class_method def self.latin_extended_a
        generate_by_range(from: 256, to: 383)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Char.latin_extended_b

      public_class_method def self.latin_extended_b
        generate_by_range(from: 384, to: 591)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Char.spacing_modifiers

      public_class_method def self.spacing_modifiers
        generate_by_range(from: 688, to: 767)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Char.diacritical_marks

      public_class_method def self.diacritical_marks
        generate_by_range(from: 768, to: 879)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Char.greek_coptic

      public_class_method def self.greek_coptic
        generate_by_range(from: 880, to: 1023)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Char.cyrillic_basic

      public_class_method def self.cyrillic_basic
        generate_by_range(from: 1024, to: 1279)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Char.cyrillic_supplement

      public_class_method def self.cyrillic_supplement
        generate_by_range(from: 1280, to: 1327)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Char.punctuation

      public_class_method def self.punctuation
        generate_by_range(from: 8192, to: 8303)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Char.currency_symbols

      public_class_method def self.currency_symbols
        generate_by_range(from: 8352, to: 8399)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Char.letterlike_symbols

      public_class_method def self.letterlike_symbols
        generate_by_range(from: 8448, to: 8527)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Char.arrows

      public_class_method def self.arrows
        generate_by_range(from: 8592, to: 8703)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Char.math_operators

      public_class_method def self.math_operators
        generate_by_range(from: 8704, to: 8959)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Char.box_drawings

      public_class_method def self.box_drawings
        generate_by_range(from: 9312, to: 9599)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Char.block_elements

      public_class_method def self.block_elements
        generate_by_range(from: 9600, to: 9631)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Char.geometric_shapes

      public_class_method def self.geometric_shapes
        generate_by_range(from: 9632, to: 9727)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Char.misc_symbols

      public_class_method def self.misc_symbols
        generate_by_range(from: 9728, to: 9983)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Char.dingbats

      public_class_method def self.dingbats
        generate_by_range(from: 9984, to: 10_175)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Char.bubble_ip(
      #   ip: 'required - ip address to transform'
      # )

      public_class_method def self.bubble_ip(opts = {})
        ip = opts[:ip].to_s

        bubble_ip = ''
        ip_arr = ip.split('.')
        dot = "\u3002"
        ip_arr.each.with_index do |octet_str, this_index|
          octet_str.each_char do |digit_str|
            case digit_str.to_i
            when 0
              bubble_ip = "#{bubble_ip}\u24ea"
            when 1
              bubble_ip = "#{bubble_ip}\u2460"
            when 2
              bubble_ip = "#{bubble_ip}\u2461"
            when 3
              bubble_ip = "#{bubble_ip}\u2462"
            when 4
              bubble_ip = "#{bubble_ip}\u2463"
            when 5
              bubble_ip = "#{bubble_ip}\u2464"
            when 6
              bubble_ip = "#{bubble_ip}\u2465"
            when 7
              bubble_ip = "#{bubble_ip}\u2466"
            when 8
              bubble_ip = "#{bubble_ip}\u2467"
            when 9
              bubble_ip = "#{bubble_ip}\u2468"
            end
          end
          bubble_ip = "#{bubble_ip}#{dot}" if (this_index + 1) < ip_arr.length
        end

        bubble_ip
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # encoder_arr = PWN::Plugins::Char.list_encoders

      public_class_method def self.list_encoders
        encoder_arr = []

        Encoding.list.each do |encoder|
          encoder_arr.push(encoder.name)
        end

        encoder_arr.sort
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Char.generate_encoded_files(
      #   from: 'required - integer to start from',
      #   to: 'required - integer to end UTF-8 generation',
      #   output_dir: 'required - folder to create files'
      # )

      public_class_method def self.generate_encoded_files(opts = {})
        from = opts[:from].to_i
        to = opts[:to].to_i
        output_dir = opts[:output_dir] if Dir.exist?(opts[:output_dir])

        char_arr = generate_by_range(from: 0, to: 0).first
        char_keys = char_arr.keys
        char_keys.each do |char_key|
          encoder = char_arr[char_key][:encoder]
          this_file = "#{output_dir}/#{from}_#{to}_#{encoder}.txt"

          case char_key
          when :bin, :dec, :hex, :html_entity, :html_entity_dec, :html_entity_hex, :long_int, :oct, :short_int, :url
            file_instr = 'wb'
          else
            file_instr = "wb:#{encoder}"
          end

          File.open(this_file, file_instr) do |f|
            generate_by_range(from: from, to: to).each do |char_hash|
              case char_key
              when :bin, :dec, :hex, :html_entity, :html_entity_dec, :html_entity_hex, :long_int, :oct, :short_int, :url
                f.puts char_hash[char_key][:char]
              else
                f.puts char_hash[char_key][:char] unless char_hash[char_key][:char].nil? || char_hash[char_key][:char].encode('utf-8').include?('***')
              end
            end
          end

          if File.read(this_file).length.zero?
            File.unlink(this_file)
          else
            print '.'
          end
        rescue StandardError => e
          puts "FILE GENERATION ATTEMPT OF: #{this_file} RESULTED THE FOLLOWING ERROR:"
          puts "#{e.class}: #{e.message}\n#{e.backtrace}\n\n\n"
          File.unlink(this_file) if File.read(this_file).length.zero?
          next
        end
        print "\n"
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
          char_arr = #{self}.generate_by_range(
            from: 'required - integer to start from',
            to: 'required - integer to end char generation'
          )

          #{self}.c0_controls_latin_basic

          #{self}.c1_controls_latin_supplement

          #{self}.latin_extended_a

          #{self}.latin_extended_b

          #{self}.spacing_modifiers

          #{self}.diacritical_marks

          #{self}.greek_coptic

          #{self}.cyrillic_basic

          #{self}.cyrillic_supplement

          #{self}.punctuation

          #{self}.currency_symbols

          #{self}.letterlike_symbols

          #{self}.arrows

          #{self}.math_operators

          #{self}.box_drawings

          #{self}.block_elements

          #{self}.geometric_shapes

          #{self}.misc_symbols

          #{self}.dingbats

          #{self}.bubble_ip(
            ip: 'required - ip address to transform'
          )

          encoder_arr = #{self}.list_encoders

          #{self}.generate_encoded_files(
            from: 'required - integer to start from',
            to: 'required - integer to end UTF-8 generation',
            output_dir: 'required - folder to create files'
          )

          #{self}.authors
        "
      end
    end
  end
end
