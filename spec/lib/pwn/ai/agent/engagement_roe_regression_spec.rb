# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::Engagement, 'RoE parse failures' do
  include_context 'pwn tmp sandbox'

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
    FileUtils.mkdir_p(File.join(@tmp, '.pwn'))
  end

  it 'keeps an absent RoE policy optional' do
    expect(described_class.load_roe).to include(present: false)
  end

  ['targets_allow: [unfinished', '- not a policy mapping', 'false'].each do |document|
    it "does not silently disable enforcement for #{document.inspect}" do
      File.write(File.join(@tmp, '.pwn', 'roe.yaml'), document)
      expect { described_class.load_roe }.to raise_error(ArgumentError, /Invalid RoE policy/)
      expect { described_class.in_scope?(host: 'outside.example') }.to raise_error(ArgumentError, /Invalid RoE policy/)
      expect { described_class.deny_if_out_of_scope(command: 'scan outside.example') }.to raise_error(ArgumentError, /Invalid RoE policy/)
    end
  end
end
