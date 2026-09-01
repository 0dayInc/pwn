# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::Plugins::TransparentBrowser do
  it 'should display information for authors' do
    authors_response = PWN::Plugins::TransparentBrowser
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Plugins::TransparentBrowser
    expect(help_response).to respond_to :help
  end

  it 'caps Watir element waits and Selenium page_load / script timeouts' do
    src = File.read(described_class.method(:open).source_location.first)
    expect(src).to match(/Watir\.default_timeout\s*=\s*15/)
    expect(src).not_to match(/Watir\.default_timeout\s*=\s*900/)
    expect(src).to match(/page_load\s*=\s*45/)
    expect(src).to match(/script\s*=\s*30/)
  end

  it 'evidence! writes screenshot, dom, and har files' do
    Dir.mktmpdir do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      browser = Object.new
      def browser.html
        '<html/>'
      end
      out = described_class.evidence!(browser_obj: { browser: browser }, label: 't', session_id: 's')
      expect(File.file?(out[:screenshot])).to be true
      expect(File.file?(out[:dom])).to be true
      expect(File.file?(out[:har])).to be true
    end
  end
end
