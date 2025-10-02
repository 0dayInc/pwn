# frozen_string_literal: true

module PWN
  # This file, using the autoload directive loads SP plugins
  # into memory only when they're needed. For more information, see:
  # http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html
  module Blockchain
    autoload :BTC, 'pwn/blockchain/btc'
    autoload :ETH, 'pwn/blockchain/eth'

    # Display a List of Every PWN::Blockchain Module

    public_class_method def self.help
      constants.sort
    end
  end
end
