# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::TransparentBrowser, 'constructor navigation bound' do
  it '[PBR-11] stops startup navigation after two failures and closes the partial browser' do
    driver = double('driver', window_handles: ['fixture'], close: nil, quit: nil)
    allow(driver).to receive(:switch_to).and_return(double('switcher', window: nil))
    browser = double('browser', driver: driver, close: nil)
    allow(Selenium::WebDriver).to receive(:for).and_return(driver)
    allow(Watir::Browser).to receive(:new).with(driver).and_return(browser)
    attempts = 0
    allow(browser).to receive(:goto) do
      attempts += 1
      raise Selenium::WebDriver::Error::WebDriverError, 'fixture navigation failed'
    end
    expect { described_class.open(browser_type: :chrome, devtools: true) }.to raise_error(Selenium::WebDriver::Error::WebDriverError, /fixture navigation failed/)
    expect(browser).to have_received(:close)
    expect(attempts).to eq(2)
  end
end
