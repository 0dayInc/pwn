#!/usr/bin/env ruby
# frozen_string_literal: true

require 'rest-client'
require 'nokogiri'

printf 'Installing phantomjs ******************************************************************'
phantomjs_tar_bz2 = ''
phantomjs_tar_extraction_path = '/opt/phantomjs-releases'
phantomjs_linux_download = ''
url = 'http://phantomjs.org/download.html'
# Look for specific links w/ pattern matching 64 bit linux tar.gz
phantomjs_resp = RestClient.get(url)
links = Nokogiri::HTML(phantomjs_resp).xpath('//a/@href')
links.each do |link|
  if link.value.match?(/linux-x86_64\.tar\.bz2/)
    phantomjs_tar_bz2 = "/opt/#{File.basename(link.value)}"
    phantomjs_linux_download = link.value
  end
end

puts `sudo wget -O #{phantomjs_tar_bz2} #{phantomjs_linux_download}` unless File.exist?(phantomjs_tar_bz2)

puts `sudo mkdir -p #{phantomjs_tar_extraction_path}` unless Dir.exist?(phantomjs_tar_extraction_path)
puts `sudo tar -xjvf #{phantomjs_tar_bz2} -C #{phantomjs_tar_extraction_path}`
phantomjs_tar_extracted_root = "#{phantomjs_tar_extraction_path}/#{File.basename(phantomjs_tar_bz2, '.tar.bz2')}"
puts `sudo cp "#{phantomjs_tar_extracted_root}/bin/phantomjs" "/usr/local/bin/phantomjs"`
puts `sudo rm #{phantomjs_tar_bz2}`
