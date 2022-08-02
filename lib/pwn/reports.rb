# frozen_string_literal: true

module PWN
  # This file, using the autoload directive loads SP reports
  # into memory only when they're needed. For more information, see:
  # http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html
  module Reports
    # autoload :HTML, 'pwn/reports/html'
    # autoload :JSON, 'pwn/reports/json'
    # autoload :PDF, 'pwn/reports/pdf'
    autoload :Fuzz, 'pwn/reports/fuzz'
    autoload :Phone, 'pwn/reports/phone'
    autoload :SAST, 'pwn/reports/sast'
    # autoload :XML, 'pwn/reports/xml'

    # Display a List of Every PWN Report

    public_class_method def self.help
      constants.sort
    end
  end
end
