# frozen_string_literal: true

module PWN
  # This file, using the autoload directive loads SP reports
  # into memory only when they're needed. For more information, see:
  # http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html
  module Banner
    autoload :Bubble, 'pwn/banner/bubble'
    autoload :Matrix, 'pwn/banner/matrix'
    autoload :Ninja, 'pwn/banner/ninja'
    autoload :OffTheAir, 'pwn/banner/off_the_air'
    autoload :Pirate, 'pwn/banner/pirate'
    autoload :WhiteRabbit, 'pwn/banner/white_rabbit'

    # Supported Method Parameters::
    # PWN::Banner.get(
    #   index: 'optional - defaults to random banner index'
    # )

    public_class_method def self.get(opts = {})
      index = opts[:index].to_i
      index = Random.rand(1..6) unless index.positive?

      banner = ''
      case index
      when 1
        banner = PWN::Banner::Bubble.get
      when 2
        banner = PWN::Banner::Matrix.get
      when 3
        banner = PWN::Banner::Ninja.get
      when 4
        banner = PWN::Banner::OffTheAir.get
      when 5
        banner = PWN::Banner::Pirate.get
      when 6
        banner = PWN::Banner::WhiteBanner.get
      else
        raise 'Invalid Index.'
      end

      banner
    end

    # Supported Method Parameters::
    # PWN::Banner.get(
    #   index: 'optional - defaults to random banner index'
    # )

    public_class_method def self.welcome
      banner = PWN::Banner.get
      banner = "#{banner}\nUse the #help command & methods for more options.\n"
      banner = "#{banner}e.g help\n"
      banner = "#{banner}e.g PWN.help\n"
      banner = "#{banner}e.g PWN::Plugins.help\n"
      banner = "#{banner}e.g PWN::Plugins::TransparentBrowser.help\n"
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
        banner = #{self}.get(
          index: 'optional - defaults to random banner index'
        )

        banner = #{self}.welcome

        #{self}.authors
      "
    end
  end
end
