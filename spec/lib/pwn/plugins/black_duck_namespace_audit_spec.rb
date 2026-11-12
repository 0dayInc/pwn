# frozen_string_literal: true

require 'spec_helper'
require 'rest-client'

RSpec.describe PWN::Plugins::BlackDuckBinaryAnalysis, 'upload flags regression' do
  before do
    allow(PWN::Plugins::TransparentBrowser).to receive(:open).and_return(browser: RestClient)
    allow(PWN::Plugins::TTYSpinner).to receive_messages(start: nil, stop: nil)
  end

  [{}, { scan_infoleak: true, code_analysis: false, scan_code_familiarity: true }].each do |flags|
    it "forwards the documented scan flags for #{flags.inspect}" do
      Tempfile.create('bdba-audit') do |file|
        file.write('offline fixture')
        file.flush
        expect(RestClient::Request).to receive(:execute) do |request|
          expect(request[:headers]).to include({ scan_infoleak: true, code_analysis: true, scan_code_familiarity: false }.merge(flags))
          '{}'
        end
        described_class.upload_file(file: file.path, token: 'fixture-token', **flags)
      end
    end
  end
end
