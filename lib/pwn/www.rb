# frozen_string_literal: true

module PWN
  # This file, using the autoload directive loads SP plugins
  # into memory only when they're needed. For more information, see:
  # http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html
  module WWW
    autoload :AppCobaltIO, 'pwn/www/app_cobalt_io'
    autoload :Bing, 'pwn/www/bing'
    autoload :BugCrowd, 'pwn/www/bug_crowd'
    autoload :Checkip, 'pwn/www/checkip.rb'
    autoload :CoinbasePro, 'pwn/www/coinbase_pro.rb'
    autoload :Duckduckgo, 'pwn/www/duckduckgo'
    autoload :Facebook, 'pwn/www/facebook'
    autoload :Google, 'pwn/www/google'
    autoload :HackerOne, 'pwn/www/hacker_one'
    autoload :Linkedin, 'pwn/www/linkedin'
    autoload :Pastebin, 'pwn/www/pastebin'
    autoload :Pandora, 'pwn/www/pandora'
    autoload :Paypal, 'pwn/www/paypal'
    autoload :Synack, 'pwn/www/synack'
    autoload :Torch, 'pwn/www/torch'
    autoload :TradingView, 'pwn/www/trading_view'
    autoload :Twitter, 'pwn/www/twitter'
    autoload :Uber, 'pwn/www/uber'
    autoload :Upwork, 'pwn/www/upwork'
    autoload :WaybackMachine, 'pwn/www/wayback_machine'
    autoload :Youtube, 'pwn/www/youtube'

    # Display a List of Every PWN::WWW Module

    public_class_method def self.help
      constants.sort
    end
  end
end
