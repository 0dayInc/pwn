# frozen_string_literal: true

require 'spec_helper'

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
end
