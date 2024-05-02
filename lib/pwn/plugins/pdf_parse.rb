# frozen_string_literal: true

require 'pdf-reader'

module PWN
  module Plugins
    # This plugin is used for parsing and interacting with PDF files
    module PDFParse
      # Supported Method Parameters::
      # PWN::Plugins::PDFParse.read_text(
      #   pdf_path: 'optional path to dir defaults to .'
      # )

      public_class_method def self.read_text(opts = {})
        pdf_path = opts[:pdf_path].to_s.scrub if File.exist?(opts[:pdf_path].to_s.scrub)
        raise "PWN Error: Invalid Directory #{pdf_path}" if pdf_path.nil?

        pdf_pages_hash = {}
        page_no = 1
        reader = PDF::Reader.new(pdf_path)
        reader.pages.each do |page|
          print '.'
          pdf_pages_hash[page_no] = page.text
          page_no += 1
        end
        print "\n"
        pdf_pages_hash
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
          pdf_pages_hash = #{self}.read_text(
            pdf_path: 'required path to pdf file'
          )

          #{self}.authors
        "
      end
    end
  end
end
